#!/usr/bin/env bun
/**
 * scripts/demo.mjs — leasebroker red-to-green demo
 *
 * Demonstrates two red→green scenarios:
 *
 *   DEMO 1 — Filesystem path-scope
 *     RED:   unbrokered agent reads both ./fixtures/data/ AND ./fixtures/private/
 *     GREEN: brokered agent (lease: fs.read data/**) — private dir read is DENIED
 *
 *   DEMO 2 — Spend cap + endpoint scope
 *     RED:   unbrokered agent calls any endpoint, charges any amount
 *     GREEN: brokered agent (lease: spend cap=100 USD, http.call api.example.com/**)
 *            → over-cap charge DENIED, off-list endpoint DENIED
 *
 * Run:  bun run demo
 *       npm  run demo
 *
 * Requirements:
 *   - Runs entirely offline (no real API keys or network needed)
 *   - No subprocess spawning — all servers run in-process via InMemoryTransport
 *   - Uses @modelcontextprotocol/server-filesystem lib to power the fs demo server
 */

// ---------------------------------------------------------------------------
// Node / Bun built-ins
// ---------------------------------------------------------------------------
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

// ---------------------------------------------------------------------------
// MCP SDK
// ---------------------------------------------------------------------------
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// ---------------------------------------------------------------------------
// Official @modelcontextprotocol/server-filesystem library functions
// ---------------------------------------------------------------------------
// We import directly from the official package's lib.js to build an in-process
// FS server powered by the same validation logic the real binary uses.
// (The package is a devDependency declared in package.json.)
import {
  setAllowedDirectories,
  validatePath,
  readFileContent,
} from '@modelcontextprotocol/server-filesystem/dist/lib.js';

// ---------------------------------------------------------------------------
// Leasebroker internals (TypeScript source resolved by Bun)
// ---------------------------------------------------------------------------
import { generateKeyPair } from '../src/signing/keygen.js';
import { PasetoV4PublicSigner } from '../src/signing/signer.js';
import { InMemoryAuditSink } from '../src/audit/audit-sink.js';
import { InMemoryRevocationList } from '../src/audit/revocation-list.js';
import { InMemorySpendLedger } from '../src/audit/spend-ledger.js';
import { DeclarativePolicyEngine, loadRules } from '../src/policy/index.js';
import { Broker } from '../src/broker/broker.js';
import { LeaseEnforcer } from '../src/enforce/enforcer.js';
import { LeasebrokerProxy } from '../src/enforce/proxy.js';
import { createMockApiServer } from '../fixtures/mock-api-server.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');
const fixturesDir = join(projectRoot, 'fixtures');
const dataDir = join(fixturesDir, 'data');
// 'private' avoids the gitignore pattern 'secrets/' — same concept, just renamed.
const secretsDir = join(fixturesDir, 'private');
const dataFile = join(dataDir, 'hello.txt');
const secretsFile = join(secretsDir, 'password.txt');

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

function print(s = '') { process.stdout.write(s + '\n'); }
function label(tag, text) {
  const col = tag === 'RED' ? red : green;
  print(`  ${col(bold(`[${tag}]`))} ${text}`);
}

// ---------------------------------------------------------------------------
// Low-level MCP helpers for scenarios that need to inject a lease token
// into the MCP initialize handshake (_meta['x-lease-token']).
//
// The standard MCP Client API does not expose _meta injection, so we use
// the raw transport send/receive pattern (same technique as enforce.test.ts).
// ---------------------------------------------------------------------------

let _msgId = 1;
function nextId() { return _msgId++; }

/**
 * Send a JSON-RPC request on `transport` and wait for the matching response.
 */
async function sendAndWait(transport, method, params) {
  const id = nextId();
  return new Promise((resolve, reject) => {
    const prev = transport.onmessage;
    transport.onmessage = (msg) => {
      if (msg.id === id) {
        transport.onmessage = prev;
        resolve(msg);
      } else {
        prev?.(msg);
      }
    };
    transport.send({ jsonrpc: '2.0', id, method, params }).catch(reject);
    setTimeout(() => {
      transport.onmessage = prev;
      reject(new Error(`Timeout waiting for JSON-RPC id=${id} (${method})`));
    }, 8000);
  });
}

/**
 * Perform the MCP initialize handshake on `clientTransport`, injecting the
 * lease token into `_meta['x-lease-token']` so the proxy can bind it.
 */
async function initProxySession(clientTransport, token) {
  await sendAndWait(clientTransport, 'initialize', {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'demo-agent', version: '1.0.0' },
    _meta: { 'x-lease-token': token },
  });
  // Send initialized notification (no response expected).
  await clientTransport.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
}

/**
 * Call a tool via raw transport (works for both direct and proxied sessions).
 * Returns { isError, text } where text is the first content item's text.
 */
async function callTool(transport, toolName, args) {
  const resp = await sendAndWait(transport, 'tools/call', {
    name: toolName,
    arguments: args,
  });
  const result = resp.result ?? {};
  const content = result.content ?? [];
  const text = content[0]?.text ?? '';
  return { isError: Boolean(result.isError), text };
}

// ---------------------------------------------------------------------------
// Shared leasebroker setup (key pair, signer, policy engine, broker)
// ---------------------------------------------------------------------------

function createBroker() {
  const kp = generateKeyPair('demo-k1');
  const signer = new PasetoV4PublicSigner(kp);
  const audit = new InMemoryAuditSink();
  const pending = new InMemoryAuditSink(); // unused for grant-only demo
  const policy = new DeclarativePolicyEngine(
    loadRules([
      // Allow any fs.read (policy engine just needs to GRANT; scope enforced by proxy)
      { ruleId: 'allow-fs-read', effect: 'allow', capabilityKind: 'fs.read' },
      // Allow any http.call
      { ruleId: 'allow-http-call', effect: 'allow', capabilityKind: 'http.call' },
      // Allow any spend
      { ruleId: 'allow-spend', effect: 'allow', capabilityKind: 'spend' },
    ]),
  );
  const pendingStore = {
    put() {}, get() { return undefined; }, list() { return []; }, resolve() {},
  };
  const broker = new Broker(policy, signer, audit, pendingStore, kp.kid);
  return { kp, signer, broker, audit };
}

/**
 * Issue a lease via the broker and return the PASETO token.
 */
function issueToken(broker, capabilities) {
  const result = broker.request({
    agentId: 'demo-agent',
    taskId: 'demo-task-' + randomUUID().slice(0, 8),
    capabilities,
    requestedDurationMs: 60_000, // 1 minute
  });
  if (result.type !== 'granted') {
    throw new Error(`Lease not granted: ${JSON.stringify(result)}`);
  }
  return result.token;
}

/**
 * Create an Enforcer wired to a fresh RevocationList + SpendLedger.
 */
function createEnforcer(signer) {
  const revList = new InMemoryRevocationList();
  const spendLedger = new InMemorySpendLedger();
  return new LeaseEnforcer(signer, revList, spendLedger);
}

// ---------------------------------------------------------------------------
// In-process FS server (powered by official @modelcontextprotocol/server-filesystem lib)
// ---------------------------------------------------------------------------

/**
 * Build an in-process MCP server that reads files using the official
 * @modelcontextprotocol/server-filesystem validation logic.
 *
 * `allowedDirs` — absolute paths; mirrors the CLI args of the official server.
 *
 * Without the leasebroker proxy, this server grants read access to ALL files
 * in `allowedDirs`.  The proxy layer adds the capability-scoped restriction.
 */
function createFsServer(allowedDirs) {
  // Configure the official lib with the allowed directories.
  setAllowedDirectories(allowedDirs);

  const server = new Server(
    { name: 'leasebroker-demo-fs', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      {
        name: 'read_file',
        description: 'Read the contents of a file.',
        inputSchema: {
          type: 'object',
          properties: { path: { type: 'string', description: 'Absolute path to the file.' } },
          required: ['path'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const filePath = String(req.params.arguments?.['path'] ?? '');
    try {
      // Use the official lib's validatePath — enforces allowedDirs at the server level.
      const resolved = await validatePath(filePath);
      const content = await readFileContent(resolved, 'utf-8');
      return { content: [{ type: 'text', text: content }] };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Demo helper: connect two in-process servers via a linked transport pair
// and return a raw client transport ready for direct tool calls.
// ---------------------------------------------------------------------------

async function connectDirect(server) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await clientTransport.start();

  // Perform a minimal MCP handshake (no token needed for direct connection).
  await sendAndWait(clientTransport, 'initialize', {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'demo-agent', version: '1.0.0' },
  });
  await clientTransport.send({ jsonrpc: '2.0', method: 'notifications/initialized' });

  return clientTransport;
}

// ---------------------------------------------------------------------------
// Demo helper: connect a proxied client to a downstream server.
// Returns the raw client transport (lease token must be injected by caller).
// ---------------------------------------------------------------------------

async function connectViaProxy(downstreamServer, enforcer, audit, toolActionResolver) {
  // Transport pair: downstream server ↔ proxy client side
  const [proxyClientTransport, downstreamServerTransport] = InMemoryTransport.createLinkedPair();
  // Transport pair: demo client ↔ proxy server side
  const [demoClientTransport, proxyServerTransport] = InMemoryTransport.createLinkedPair();
  // Assign a stable session ID so the proxy can bind the token.
  proxyServerTransport.sessionId = 'demo-session-' + randomUUID().slice(0, 8);

  await downstreamServer.connect(downstreamServerTransport);

  const proxy = new LeasebrokerProxy({ enforcer, audit, toolActionResolver });
  await proxy.connect(proxyServerTransport, proxyClientTransport);

  return { demoClientTransport, proxy };
}

// ---------------------------------------------------------------------------
// ══════════════════════════════════════════════════════════════════════════
// DEMO 1: Filesystem path-scope red → green
// ══════════════════════════════════════════════════════════════════════════
// ---------------------------------------------------------------------------

async function runFsDemo() {
  print();
  print(bold('══════════════════════════════════════════════'));
  print(bold('  DEMO 1 — Filesystem Path-Scope'));
  print(bold('══════════════════════════════════════════════'));
  print(dim('  Fronts @modelcontextprotocol/server-filesystem via LeasebrokerProxy.'));
  print(dim('  Lease: fs.read  ./fixtures/data/**  (NOT ./fixtures/private/**)'));
  print();

  // Ensure fixture files exist.
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(secretsDir, { recursive: true });
  if (!existsSync(dataFile)) {
    writeFileSync(dataFile, 'Hello from leasebroker fixtures!\nThis is public data.\n');
  }
  if (!existsSync(secretsFile)) {
    writeFileSync(secretsFile, 'SECRET_KEY=sk-not-real\nDB_PASSWORD=hunter2\n');
  }

  // ── RED ─────────────────────────────────────────────────────────────────
  print(bold('  ── RED: unbrokered agent (direct access) ──'));
  print(dim('     No lease, no proxy — server grants ANY file in its allowed dirs.'));

  // The official FS server is started with BOTH dataDir and secretsDir allowed.
  const redServer = createFsServer([dataDir, secretsDir]);
  const redClient = await connectDirect(redServer);

  const redData = await callTool(redClient, 'read_file', { path: dataFile });
  label('RED', `read_file(data/hello.txt)       → ${redData.isError ? red('ERROR: ' + redData.text) : green('OK')} — "${redData.text.trim().slice(0, 60)}"`);

  const redSecrets = await callTool(redClient, 'read_file', { path: secretsFile });
  label('RED', `read_file(private/password.txt) → ${redSecrets.isError ? red('ERROR') : red('OK ← PROBLEM: private dir accessible!')} — "${redSecrets.text.trim().slice(0, 50)}"`);

  print();
  if (!redData.isError && !redSecrets.isError) {
    print(red('  ⚠  Without the broker: agent reads BOTH data AND secrets. No restrictions.'));
  }
  await redServer.close();

  // ── GREEN ────────────────────────────────────────────────────────────────
  print();
  print(bold('  ── GREEN: brokered agent (proxy enforces lease scope) ──'));
  print(dim('     Lease: fs.read  ' + dataDir + '/**'));
  print(dim('     The FS server still allows both dirs — broker adds the scope restriction.'));

  const { broker: greenBroker, signer: greenSigner, audit: greenAudit } = createBroker();
  const greenToken = issueToken(greenBroker, [
    { kind: 'fs.read', paths: [dataDir + '/**'] },
  ]);
  const greenEnforcer = createEnforcer(greenSigner);

  const greenServer = createFsServer([dataDir, secretsDir]); // server allows both
  const { demoClientTransport: greenClient, proxy: greenProxy } = await connectViaProxy(
    greenServer,
    greenEnforcer,
    greenAudit,
    (name, args) => {
      if (name === 'read_file') return { kind: 'fs.read', path: String(args['path'] ?? '') };
      return undefined;
    },
  );

  await initProxySession(greenClient, greenToken);

  const greenData = await callTool(greenClient, 'read_file', { path: dataFile });
  label('GREEN', `read_file(data/hello.txt)       → ${greenData.isError ? red('DENIED') : green('ALLOWED')} ✓`);

  const greenSecrets = await callTool(greenClient, 'read_file', { path: secretsFile });
  label(
    'GREEN',
    `read_file(private/password.txt) → ${greenSecrets.isError ? green('DENIED ✓') : red('ALLOWED ← BROKER FAILED!')}  "${greenSecrets.text.trim().slice(0, 60)}"`,
  );

  print();
  if (!greenData.isError && greenSecrets.isError) {
    print(green('  ✓  Broker enforced: data accessible, private directory DENIED.'));
  } else {
    print(red('  ✗  Demo FAILED — expected data=OK, private=DENIED'));
    process.exitCode = 1;
  }

  await greenProxy.close();
  await greenServer.close();
}

// ---------------------------------------------------------------------------
// ══════════════════════════════════════════════════════════════════════════
// DEMO 2: Spend cap + endpoint scope red → green
// ══════════════════════════════════════════════════════════════════════════
// ---------------------------------------------------------------------------

async function runSpendDemo() {
  print();
  print(bold('══════════════════════════════════════════════'));
  print(bold('  DEMO 2 — Spend Cap + Endpoint Scope'));
  print(bold('══════════════════════════════════════════════'));
  print(dim('  Mock API MCP server — no real network or API keys needed.'));
  print(dim('  Lease: spend cap=100 USD, http.call api.example.com/**'));
  print();

  // ── RED ─────────────────────────────────────────────────────────────────
  print(bold('  ── RED: unbrokered agent (direct access) ──'));
  print(dim('     No lease, no proxy — server executes ALL calls without restriction.'));

  const redApiServer = createMockApiServer();
  const redApiClient = await connectDirect(redApiServer);

  const redCharge500 = await callTool(redApiClient, 'charge_api', {
    endpoint: 'api.example.com/v1/models',
    currency: 'USD',
    amount: 500, // 5× over cap — no enforcement
  });
  label('RED', `charge_api(USD 500) unbrokered   → ${redCharge500.isError ? red('ERROR') : red('OK ← over cap, but no enforcement!')}`);

  const redCharge10k = await callTool(redApiClient, 'charge_api', {
    endpoint: 'api.example.com/v1/embed',
    currency: 'USD',
    amount: 10000, // 100× over cap
  });
  label('RED', `charge_api(USD 10000) unbrokered → ${redCharge10k.isError ? red('ERROR') : red('OK ← massively over cap!')}`);

  const redEvil = await callTool(redApiClient, 'call_api', {
    endpoint: 'evil.example.com/exfiltrate',
  });
  label('RED', `call_api(evil.example.com) unbrokered → ${redEvil.isError ? red('ERROR') : red('OK ← off-list endpoint, no enforcement!')}`);

  print();
  if (!redCharge500.isError && !redCharge10k.isError && !redEvil.isError) {
    print(red('  ⚠  Without the broker: unlimited spend, any endpoint. No restrictions.'));
  }
  await redApiServer.close();

  // ── GREEN ────────────────────────────────────────────────────────────────
  print();
  print(bold('  ── GREEN: brokered agent (proxy enforces spend cap + endpoints) ──'));
  print(dim('     Lease: spend cap=100 USD,  http.call api.example.com/**'));

  const { broker: spendBroker, signer: spendSigner, audit: spendAudit } = createBroker();
  const spendToken = issueToken(spendBroker, [
    { kind: 'spend', currency: 'USD', capMinor: 100 },   // cap = $1.00
    { kind: 'http.call', endpoints: ['api.example.com/**'] },
  ]);
  const spendEnforcer = createEnforcer(spendSigner);

  const greenApiServer = createMockApiServer();
  const { demoClientTransport: greenApiClient, proxy: greenApiProxy } = await connectViaProxy(
    greenApiServer,
    spendEnforcer,
    spendAudit,
    (name, args) => {
      if (name === 'call_api') {
        return { kind: 'http.call', endpoint: String(args['endpoint'] ?? '') };
      }
      if (name === 'charge_api') {
        return {
          kind: 'spend',
          currency: String(args['currency'] ?? 'USD'),
          amountMinor: Number(args['amount'] ?? 0),
        };
      }
      return undefined;
    },
  );

  await initProxySession(greenApiClient, spendToken);

  // First charge: 80 USD — within cap (100 USD).
  const g1 = await callTool(greenApiClient, 'charge_api', {
    endpoint: 'api.example.com/v1/models',
    currency: 'USD',
    amount: 80,
  });
  label('GREEN', `charge_api(USD  80) [spent=80/100]  → ${g1.isError ? red('DENIED') : green('ALLOWED')} ✓`);

  // Second charge: 50 USD — 80 + 50 = 130 > 100 cap → DENIED.
  const g2 = await callTool(greenApiClient, 'charge_api', {
    endpoint: 'api.example.com/v1/embed',
    currency: 'USD',
    amount: 50,
  });
  label(
    'GREEN',
    `charge_api(USD  50) [would=130>100] → ${g2.isError ? green('DENIED ✓ (over cap)') : red('ALLOWED ← BROKER FAILED!')}  "${g2.text.slice(0, 50)}"`,
  );

  // Off-list endpoint: evil.example.com → DENIED.
  const g3 = await callTool(greenApiClient, 'call_api', {
    endpoint: 'evil.example.com/exfiltrate',
  });
  label(
    'GREEN',
    `call_api(evil.example.com)          → ${g3.isError ? green('DENIED ✓ (off-list)') : red('ALLOWED ← BROKER FAILED!')}  "${g3.text.slice(0, 50)}"`,
  );

  // Allowed endpoint: api.example.com → allowed (endpoint in list, no spend).
  const g4 = await callTool(greenApiClient, 'call_api', {
    endpoint: 'api.example.com/v1/health',
  });
  label('GREEN', `call_api(api.example.com/health)    → ${g4.isError ? red('DENIED ← unexpected') : green('ALLOWED')} ✓ (in scope)`);

  print();
  const spendDemoOk = !g1.isError && g2.isError && g3.isError && !g4.isError;
  if (spendDemoOk) {
    print(green('  ✓  Broker enforced: within-cap allowed, over-cap DENIED, off-list DENIED.'));
  } else {
    print(red('  ✗  Demo FAILED — unexpected results above'));
    process.exitCode = 1;
  }

  await greenApiProxy.close();
  await greenApiServer.close();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
  print();
  print(bold('╔══════════════════════════════════════════════╗'));
  print(bold('║   leasebroker — red-to-green demo            ║'));
  print(bold('╚══════════════════════════════════════════════╝'));

  await runFsDemo();
  await runSpendDemo();

  print();
  if (process.exitCode) {
    print(red(bold('DEMO FAILED — see ✗ above')));
  } else {
    print(green(bold('ALL DEMOS PASSED ✓')));
  }
  print();
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});

/**
 * Tests for the enforce lane: LeaseEnforcer (unit) + LeasebrokerProxy (integration).
 *
 * Required coverage:
 *   - LeaseEnforcer: valid token + in-scope → ok
 *   - LeaseEnforcer: valid token + out-of-scope → denied
 *   - LeaseEnforcer: expired token → denied
 *   - LeaseEnforcer: revoked token → denied
 *   - LeaseEnforcer: spend at-cap → ok; over-cap → denied
 *   - ProxyServer: in-scope forward (tool call forwarded to downstream)
 *   - ProxyServer: out-of-scope deny (tool call denied)
 *   - ProxyServer: expired deny
 *   - ProxyServer: revoked deny
 *   - ProxyServer: over-cap deny + at-cap allowed
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type JSONRPCMessage,
  type JSONRPCRequest,
} from '@modelcontextprotocol/sdk/types.js';
import type { Lease } from '../contract/index.js';
import { InMemoryAuditSink } from '../audit/audit-sink.js';
import { InMemoryRevocationList } from '../audit/revocation-list.js';
import { InMemorySpendLedger } from '../audit/spend-ledger.js';
import { generateKeyPair } from '../signing/keygen.js';
import { PasetoV4PublicSigner } from '../signing/signer.js';
import { LeaseEnforcer } from './enforcer.js';
import { LeasebrokerProxy } from './proxy.js';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeLease(overrides?: Partial<Lease>): Lease {
  return {
    id: 'lease-test-1',
    agentId: 'agent-test',
    taskId: 'task-test',
    capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(), // 1 minute from now
    kid: 'k1',
    ...overrides,
  };
}

/** Build a PASETO token for the given lease using the provided signer. */
function sign(signer: PasetoV4PublicSigner, lease: Lease): string {
  return signer.issue(lease);
}

// ---------------------------------------------------------------------------
// LeaseEnforcer (unit tests)
// ---------------------------------------------------------------------------

describe('LeaseEnforcer', () => {
  let signer: PasetoV4PublicSigner;
  let revocationList: InMemoryRevocationList;
  let spendLedger: InMemorySpendLedger;
  let enforcer: LeaseEnforcer;

  beforeEach(() => {
    const kp = generateKeyPair('k1');
    signer = new PasetoV4PublicSigner(kp);
    revocationList = new InMemoryRevocationList();
    spendLedger = new InMemorySpendLedger();
    enforcer = new LeaseEnforcer(signer, revocationList, spendLedger);
  });

  // ── Signature / decode ─────────────────────────────────────────────────

  it('allows a valid in-scope fs.read action', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'fs.read', path: '/data/file.txt' });
    expect(result.ok).toBe(true);
  });

  it('allows fs.read with a glob that matches a nested path', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'fs.read', path: '/data/sub/dir/file.json' });
    expect(result.ok).toBe(true);
  });

  it('denies a bad token (garbled data)', () => {
    const result = enforcer.check('v4.public.notvalid', {
      kind: 'fs.read',
      path: '/data/file.txt',
    });
    expect(result.ok).toBe(false);
  });

  // ── Expiry ─────────────────────────────────────────────────────────────

  it('denies an expired token', () => {
    const lease = makeLease({
      expiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second in the past
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'fs.read', path: '/data/file.txt' });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  // ── Revocation ─────────────────────────────────────────────────────────

  it('denies a revoked token', () => {
    const lease = makeLease();
    const token = sign(signer, lease);

    revocationList.revoke(lease.id);

    const result = enforcer.check(token, { kind: 'fs.read', path: '/data/file.txt' });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/revoked/i);
  });

  // ── Scope ──────────────────────────────────────────────────────────────

  it('denies an fs.read action outside the allowed path glob', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'fs.read', path: '/secrets/key.pem' });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/scope/i);
  });

  it('denies an action kind not in the lease capabilities', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'fs.write', path: '/data/file.txt' });
    expect(result.ok).toBe(false);
  });

  it('allows http.call to a matching endpoint', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'http.call', endpoints: ['api.example.com/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'http.call', endpoint: 'api.example.com/v1/data' });
    expect(result.ok).toBe(true);
  });

  it('denies http.call to a non-matching endpoint', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'http.call', endpoints: ['api.example.com/**'] }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, {
      kind: 'http.call',
      endpoint: 'evil.example.com/v1/data',
    });
    expect(result.ok).toBe(false);
  });

  // ── Spend ──────────────────────────────────────────────────────────────

  it('allows a spend action exactly at the cap (at-cap)', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 100 }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'spend', currency: 'USD', amountMinor: 100 });
    expect(result.ok).toBe(true);
    expect(spendLedger.spent(lease.id)).toBe(100);
  });

  it('denies a spend action that would exceed the cap (over-cap)', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 100 }],
    });
    const token = sign(signer, lease);

    // Accrue 60 first (within cap)
    const first = enforcer.check(token, { kind: 'spend', currency: 'USD', amountMinor: 60 });
    expect(first.ok).toBe(true);

    // Try to accrue 60 more (60 + 60 = 120 > 100 cap)
    const second = enforcer.check(token, { kind: 'spend', currency: 'USD', amountMinor: 60 });
    expect(second.ok).toBe(false);
    expect(second.reason).toMatch(/cap/i);

    // Spent should remain at 60 (denied amount not accrued)
    expect(spendLedger.spent(lease.id)).toBe(60);
  });

  it('denies spend when currency does not match', () => {
    const lease = makeLease({
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 1000 }],
    });
    const token = sign(signer, lease);

    const result = enforcer.check(token, { kind: 'spend', currency: 'EUR', amountMinor: 10 });
    expect(result.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ProxyServer integration tests
// ---------------------------------------------------------------------------

/**
 * Sends a JSON-RPC request over clientTransport and waits for the response
 * with the matching `id`.  Concurrent requests must use distinct IDs.
 */
async function sendAndWait(
  clientTransport: InMemoryTransport,
  req: { id: number; method: string; params: unknown },
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const prev = clientTransport.onmessage;
    clientTransport.onmessage = (msg: JSONRPCMessage) => {
      const m = msg as Record<string, unknown>;
      if (m['id'] === req.id) {
        // Restore previous handler before resolving.
        clientTransport.onmessage = prev;
        resolve(m);
      } else {
        // Not ours — pass to prior handler if any.
        prev?.(msg);
      }
    };
    void clientTransport.send({
      jsonrpc: '2.0',
      id: req.id,
      method: req.method,
      params: req.params,
    } as JSONRPCRequest);
    // Safety timeout
    setTimeout(() => {
      clientTransport.onmessage = prev;
      reject(new Error(`Timeout waiting for response to id=${req.id}`));
    }, 5000);
  });
}

/**
 * Initialise a proxy session by sending the MCP initialize request with the
 * lease token in `_meta['x-lease-token']`, then sending notifications/initialized.
 */
async function initSession(
  clientTransport: InMemoryTransport,
  token: string,
  id = 1,
): Promise<void> {
  await sendAndWait(clientTransport, {
    id,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test-client', version: '1.0.0' },
      _meta: { 'x-lease-token': token },
    },
  });
  // Send the initialized notification (no response expected).
  await clientTransport.send({
    jsonrpc: '2.0',
    method: 'notifications/initialized',
  } as JSONRPCMessage);
}

describe('LeasebrokerProxy', () => {
  let signer: PasetoV4PublicSigner;
  let revocationList: InMemoryRevocationList;
  let spendLedger: InMemorySpendLedger;
  let audit: InMemoryAuditSink;
  let enforcer: LeaseEnforcer;

  let mockDownstream: Server;
  let proxyInstance: LeasebrokerProxy;

  // Transport pairs:
  //   [clientTransport, proxyServerTransport]  — client ↔ proxy server side
  //   [proxyClientTransport, downstreamServerTransport] — proxy client ↔ downstream
  let clientTransport: InMemoryTransport;
  let proxyServerTransport: InMemoryTransport;
  let proxyClientTransport: InMemoryTransport;
  let downstreamServerTransport: InMemoryTransport;

  /** Downstream responses by tool name — set per test. */
  const downstreamResponses = new Map<
    string,
    { content: Array<{ type: 'text'; text: string }> }
  >();

  beforeEach(async () => {
    // Build fresh instances for isolation.
    const kp = generateKeyPair('k1');
    signer = new PasetoV4PublicSigner(kp);
    revocationList = new InMemoryRevocationList();
    spendLedger = new InMemorySpendLedger();
    audit = new InMemoryAuditSink();
    enforcer = new LeaseEnforcer(signer, revocationList, spendLedger);

    // Transport pairs.
    [clientTransport, proxyServerTransport] = InMemoryTransport.createLinkedPair();
    [proxyClientTransport, downstreamServerTransport] = InMemoryTransport.createLinkedPair();

    // Set a deterministic sessionId so the proxy can bind tokens.
    proxyServerTransport.sessionId = 'test-session';

    // Mock downstream server.
    downstreamResponses.clear();
    mockDownstream = new Server(
      { name: 'mock-downstream', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    mockDownstream.setRequestHandler(ListToolsRequestSchema, () => ({
      tools: [
        {
          name: 'read_file',
          inputSchema: {
            type: 'object' as const,
            properties: { path: { type: 'string' } },
            required: ['path'],
          },
        },
        {
          name: 'charge_api',
          inputSchema: {
            type: 'object' as const,
            properties: {
              currency: { type: 'string' },
              amount: { type: 'number' },
            },
          },
        },
      ],
    }));

    mockDownstream.setRequestHandler(CallToolRequestSchema, (req) => {
      const toolName = req.params.name;
      const canned = downstreamResponses.get(toolName) ?? {
        content: [{ type: 'text' as const, text: `${toolName}: ok` }],
      };
      return canned;
    });

    await mockDownstream.connect(downstreamServerTransport);

    // Build and connect proxy.
    proxyInstance = new LeasebrokerProxy({
      enforcer,
      audit,
      toolActionResolver: (toolName, args) => {
        if (toolName === 'read_file') {
          const path = typeof args['path'] === 'string' ? args['path'] : '';
          return { kind: 'fs.read', path };
        }
        if (toolName === 'charge_api') {
          const currency = typeof args['currency'] === 'string' ? args['currency'] : 'USD';
          const amount = typeof args['amount'] === 'number' ? args['amount'] : 0;
          return { kind: 'spend', currency, amountMinor: amount };
        }
        // Unknown tools → pass through
        return undefined;
      },
    });

    await proxyInstance.connect(proxyServerTransport, proxyClientTransport);
  });

  afterEach(async () => {
    await proxyInstance.close().catch(() => {});
    await mockDownstream.close().catch(() => {});
  });

  // ── In-scope forward ───────────────────────────────────────────────────

  it('forwards an in-scope fs.read tool call to the downstream', async () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);
    downstreamResponses.set('read_file', {
      content: [{ type: 'text', text: 'file contents' }],
    });

    await initSession(clientTransport, token);

    const response = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/data/readme.txt' } },
    });

    const result = response['result'] as Record<string, unknown> | undefined;
    expect(result?.['isError']).toBeFalsy();
    const content = result?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toBe('file contents');

    // Audit: use event emitted, attributed to the lease and its workflow
    // (the trust-per-workflow report joins on these fields).
    const events = audit.read();
    const useEvent = events.find((e) => e.type === 'use');
    expect(useEvent).toBeDefined();
    expect(useEvent?.leaseId).toBe('lease-test-1');
    expect(useEvent?.detail['taskId']).toBe('task-test');
  });

  // ── Out-of-scope deny ──────────────────────────────────────────────────

  it('denies an out-of-scope fs.read tool call', async () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);

    await initSession(clientTransport, token);

    const response = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/secrets/key.pem' } },
    });

    const result = response['result'] as Record<string, unknown> | undefined;
    expect(result?.['isError']).toBe(true);
    const content = result?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toMatch(/denied/i);

    // Audit: denial event emitted, attributed to the lease and its workflow.
    const events = audit.read();
    const denialEvent = events.find((e) => e.type === 'denial');
    expect(denialEvent).toBeDefined();
    expect(denialEvent?.leaseId).toBe('lease-test-1');
    expect(denialEvent?.detail['taskId']).toBe('task-test');
  });

  // ── Expired deny ───────────────────────────────────────────────────────

  it('denies a call when the lease token has expired', async () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
      expiresAt: new Date(Date.now() - 1000).toISOString(), // already expired
    });
    const token = sign(signer, lease);

    await initSession(clientTransport, token);

    const response = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/data/file.txt' } },
    });

    const result = response['result'] as Record<string, unknown> | undefined;
    expect(result?.['isError']).toBe(true);
    const content = result?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toMatch(/expired/i);
  });

  // ── Revoked deny ───────────────────────────────────────────────────────

  it('denies a call when the lease has been revoked', async () => {
    const lease = makeLease({
      capabilities: [{ kind: 'fs.read', paths: ['/data/**'] }],
    });
    const token = sign(signer, lease);
    revocationList.revoke(lease.id); // revoke before call

    await initSession(clientTransport, token);

    const response = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/data/file.txt' } },
    });

    const result = response['result'] as Record<string, unknown> | undefined;
    expect(result?.['isError']).toBe(true);
    const content = result?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toMatch(/revoked/i);
  });

  // ── Spend: at-cap allowed + over-cap denied ────────────────────────────

  it('allows a spend call at the exact cap and denies the next call that would exceed it', async () => {
    const capMinor = 100;
    const lease = makeLease({
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor }],
    });
    const token = sign(signer, lease);

    await initSession(clientTransport, token);

    // First call: spend exactly to the cap (at-cap → allowed)
    const atCapResponse = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: {
        name: 'charge_api',
        arguments: { currency: 'USD', amount: 100 },
      },
    });
    const atCapResult = atCapResponse['result'] as Record<string, unknown> | undefined;
    expect(atCapResult?.['isError']).toBeFalsy();

    // Second call: any positive amount is now over-cap
    const overCapResponse = await sendAndWait(clientTransport, {
      id: 3,
      method: 'tools/call',
      params: {
        name: 'charge_api',
        arguments: { currency: 'USD', amount: 1 },
      },
    });
    const overCapResult = overCapResponse['result'] as Record<string, unknown> | undefined;
    expect(overCapResult?.['isError']).toBe(true);
    const content = overCapResult?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toMatch(/cap/i);
  });

  // ── Unknown tool: pass through ─────────────────────────────────────────

  it('passes through a call for an unknown tool without enforcement', async () => {
    const lease = makeLease({
      // No capabilities needed — resolver returns undefined for 'unknown_tool'
      capabilities: [],
    });
    const token = sign(signer, lease);
    downstreamResponses.set('unknown_tool', {
      content: [{ type: 'text', text: 'downstream says hello' }],
    });

    await initSession(clientTransport, token);

    const response = await sendAndWait(clientTransport, {
      id: 2,
      method: 'tools/call',
      params: { name: 'unknown_tool', arguments: {} },
    });

    const result = response['result'] as Record<string, unknown> | undefined;
    // Should not be an enforcement denial
    expect(result?.['isError']).toBeFalsy();
    const content = result?.['content'] as Array<{ text: string }> | undefined;
    expect(content?.[0]?.text).toBe('downstream says hello');
  });
});

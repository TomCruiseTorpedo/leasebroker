/**
 * CLI state management — file-backed persistence for leasebroker stores.
 *
 * Persists the in-memory stores to a state directory so that CLI commands
 * share state across invocations. Each store is serialised to a separate
 * JSON file; the audit log uses JSONL (one event per line).
 *
 * Default state directory: `.leasebroker/` relative to cwd.
 * Override with --state-dir or LEASEBROKER_STATE_DIR env var.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditEvent, LeaseRequest, PolicyRule } from '../contract/index.js';
import { InMemoryAuditSink } from '../audit/index.js';
import { InMemoryPendingStore } from '../audit/index.js';
import { InMemoryRevocationList } from '../audit/index.js';
import { InMemorySpendLedger } from '../audit/index.js';
import { generateKeyPair, keyPairFromSeed } from '../signing/index.js';
import type { KeyPair } from '../signing/index.js';

// ---------------------------------------------------------------------------
// State directory resolution
// ---------------------------------------------------------------------------

export function resolveStateDir(override?: string): string {
  return override ?? process.env['LEASEBROKER_STATE_DIR'] ?? join(process.cwd(), '.leasebroker');
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Key persistence
// ---------------------------------------------------------------------------

interface StoredKeys {
  kid: string;
  secretKeyHex: string;
  publicKeyHex: string;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function loadOrCreateKeyPair(stateDir: string): KeyPair {
  ensureDir(stateDir);
  const keysPath = join(stateDir, 'keys.json');
  if (existsSync(keysPath)) {
    const stored = JSON.parse(readFileSync(keysPath, 'utf8')) as StoredKeys;
    const secretKey = hexToBytes(stored.secretKeyHex);
    return keyPairFromSeed(secretKey, stored.kid);
  }
  // Generate a fresh key pair and persist it.
  const kp = generateKeyPair('k1');
  const stored: StoredKeys = {
    kid: kp.kid,
    secretKeyHex: bytesToHex(kp.secretKey),
    publicKeyHex: bytesToHex(kp.publicKey),
  };
  writeFileSync(keysPath, JSON.stringify(stored, null, 2));
  return kp;
}

// ---------------------------------------------------------------------------
// Policy rules persistence
// ---------------------------------------------------------------------------

export function loadPolicyRules(stateDir: string, rulesFilePath?: string): PolicyRule[] {
  const path = rulesFilePath ?? join(stateDir, 'policy.json');
  if (!existsSync(path)) return [];
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PolicyRule[];
  } catch {
    return [];
  }
}

export function savePolicyRules(stateDir: string, rules: PolicyRule[]): void {
  ensureDir(stateDir);
  writeFileSync(join(stateDir, 'policy.json'), JSON.stringify(rules, null, 2));
}

// ---------------------------------------------------------------------------
// Pending store persistence
// ---------------------------------------------------------------------------

interface StoredPending {
  [reqId: string]: LeaseRequest;
}

export function loadPendingStore(stateDir: string): InMemoryPendingStore {
  const store = new InMemoryPendingStore();
  const path = join(stateDir, 'pending.json');
  if (!existsSync(path)) return store;
  try {
    const data = JSON.parse(readFileSync(path, 'utf8')) as StoredPending;
    for (const [reqId, request] of Object.entries(data)) {
      store.put(reqId, request);
    }
  } catch {
    // Corrupted state — start fresh
  }
  return store;
}

export function savePendingStore(stateDir: string, store: InMemoryPendingStore): void {
  ensureDir(stateDir);
  const data: StoredPending = {};
  for (const { reqId, request } of store.list()) {
    data[reqId] = request;
  }
  writeFileSync(join(stateDir, 'pending.json'), JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Audit sink persistence (JSONL)
// ---------------------------------------------------------------------------

export function loadAuditSink(stateDir: string): InMemoryAuditSink {
  const sink = new InMemoryAuditSink();
  const path = join(stateDir, 'audit.jsonl');
  if (!existsSync(path)) return sink;
  try {
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim() !== '');
    for (const line of lines) {
      const event = JSON.parse(line) as AuditEvent;
      sink.append(event);
    }
  } catch {
    // Corrupted log — start fresh
  }
  return sink;
}

export function saveAuditSink(stateDir: string, sink: InMemoryAuditSink): void {
  ensureDir(stateDir);
  const events = sink.read();
  const jsonl = events.map((e) => JSON.stringify(e)).join('\n');
  writeFileSync(join(stateDir, 'audit.jsonl'), jsonl ? jsonl + '\n' : '');
}

// ---------------------------------------------------------------------------
// Revocation list persistence
// ---------------------------------------------------------------------------

export function loadRevocationList(stateDir: string): InMemoryRevocationList {
  const list = new InMemoryRevocationList();
  const path = join(stateDir, 'revoked.json');
  if (!existsSync(path)) return list;
  try {
    const ids = JSON.parse(readFileSync(path, 'utf8')) as string[];
    for (const id of ids) {
      list.revoke(id);
    }
  } catch {
    // Corrupted — start fresh
  }
  return list;
}

export function saveRevocationList(stateDir: string, list: InMemoryRevocationList): void {
  ensureDir(stateDir);
  // Collect revoked IDs by probing — we know InMemoryRevocationList stores them in a Set.
  // We use a private accessor via a cast to get all IDs without changing the interface.
  // Since we own the implementation, we add a small helper method.
  const ids = getRevocationIds(list);
  writeFileSync(join(stateDir, 'revoked.json'), JSON.stringify(ids, null, 2));
}

/**
 * Extract all revoked IDs from the list.
 * Uses a test helper that's attached at load time.
 */
function getRevocationIds(list: InMemoryRevocationList): string[] {
  // InMemoryRevocationList doesn't expose a list() method on its interface,
  // but we can use the fact that we own the implementation.
  // Cast to access the internal Set for serialisation.
  const internal = list as unknown as { revoked: Set<string> };
  return Array.from(internal.revoked);
}

// ---------------------------------------------------------------------------
// Spend ledger persistence
// ---------------------------------------------------------------------------

interface StoredSpend {
  [leaseId: string]: { spent: number; cap: number };
}

export function loadSpendLedger(stateDir: string): InMemorySpendLedger {
  const ledger = new InMemorySpendLedger();
  const path = join(stateDir, 'spend.json');
  if (!existsSync(path)) return ledger;
  try {
    const data = JSON.parse(readFileSync(path, 'utf8')) as StoredSpend;
    for (const [leaseId, entry] of Object.entries(data)) {
      ledger.setCap(leaseId, entry.cap);
      // Restore spent amount by accruing it (accrue won't fail since cap >= spent).
      if (entry.spent > 0) {
        // Set cap large enough to restore, then restore.
        const tempLedger = ledger as unknown as { ledger: Map<string, { spent: number; cap: number }> };
        const stored = tempLedger.ledger.get(leaseId);
        if (stored !== undefined) {
          stored.spent = entry.spent;
        }
      }
    }
  } catch {
    // Corrupted — start fresh
  }
  return ledger;
}

export function saveSpendLedger(stateDir: string, ledger: InMemorySpendLedger): void {
  ensureDir(stateDir);
  const internal = ledger as unknown as { ledger: Map<string, { spent: number; cap: number }> };
  const data: StoredSpend = {};
  for (const [leaseId, entry] of internal.ledger.entries()) {
    data[leaseId] = { spent: entry.spent, cap: entry.cap };
  }
  writeFileSync(join(stateDir, 'spend.json'), JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Combined state bundle
// ---------------------------------------------------------------------------

export interface CliState {
  stateDir: string;
  keyPair: KeyPair;
  auditSink: InMemoryAuditSink;
  pendingStore: InMemoryPendingStore;
  revocationList: InMemoryRevocationList;
  spendLedger: InMemorySpendLedger;
}

export function loadState(stateDir: string): CliState {
  ensureDir(stateDir);
  return {
    stateDir,
    keyPair: loadOrCreateKeyPair(stateDir),
    auditSink: loadAuditSink(stateDir),
    pendingStore: loadPendingStore(stateDir),
    revocationList: loadRevocationList(stateDir),
    spendLedger: loadSpendLedger(stateDir),
  };
}

export function saveState(state: CliState): void {
  saveAuditSink(state.stateDir, state.auditSink);
  savePendingStore(state.stateDir, state.pendingStore);
  saveRevocationList(state.stateDir, state.revocationList);
  saveSpendLedger(state.stateDir, state.spendLedger);
}

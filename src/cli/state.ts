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

import { existsSync, linkSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditEvent, LeaseRequest, PolicyRule } from '../contract/index.js';
import { InMemoryAuditSink, parseStoredAuditJsonl } from '../audit/index.js';
import type { AuditIntegrity } from '../audit/index.js';
import { InMemoryPendingStore } from '../audit/index.js';
import { InMemoryRevocationList } from '../audit/index.js';
import { InMemorySpendLedger, InMemoryDurationLedger } from '../audit/index.js';
import { generateKeyPair, keyPairFromSeed } from '../signing/index.js';
import type { KeyPair } from '../signing/index.js';
import { acquireFileLock, FileLockTimeout } from './file-lock.js';
import type { FileLockHandle, FileLockOptions } from './file-lock.js';

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
  const readKeys = (): KeyPair => {
    const stored = JSON.parse(readFileSync(keysPath, 'utf8')) as StoredKeys;
    return keyPairFromSeed(hexToBytes(stored.secretKeyHex), stored.kid);
  };
  if (existsSync(keysPath)) return readKeys();

  // Generate a fresh key pair and persist it.
  const kp = generateKeyPair('k1');
  const stored: StoredKeys = {
    kid: kp.kid,
    secretKeyHex: bytesToHex(kp.secretKey),
    publicKeyHex: bytesToHex(kp.publicKey),
  };
  // Two first runs can both see no key. Install it exclusively so exactly one key is ever
  // published and the loser adopts it: a lease signed with a key that lost the race would
  // never verify.
  if (!publishExclusively(keysPath, JSON.stringify(stored, null, 2), 0o600)) return readKeys();
  return kp;
}

// ---------------------------------------------------------------------------
// Policy rules persistence
// ---------------------------------------------------------------------------

/**
 * Thrown when a policy file exists but cannot be read or parsed.
 *
 * Distinct from "no policy file", which is a legitimate configuration meaning
 * zero rules. Both end in deny-by-default, so both are SAFE — but they call
 * for opposite responses from the operator, and the previous `catch { return
 * [] }` made them indistinguishable. A corrupt policy.json presented as an
 * absent one leaves someone staring at a deny-all system with a policy file
 * sitting right there, apparently being ignored for no reason.
 */
export class PolicyFileError extends Error {
  readonly path: string;

  constructor(path: string, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(`policy file at ${path} could not be read: ${detail}`);
    this.name = 'PolicyFileError';
    this.path = path;
  }
}

/**
 * Load policy rules from `rulesFilePath`, or `policy.json` in the state dir.
 *
 * Returns `[]` only when the file genuinely does not exist. An existing file
 * that cannot be read or parsed throws {@link PolicyFileError} — it is a
 * misconfiguration to be fixed, not an empty ruleset to be silently adopted.
 */
export function loadPolicyRules(stateDir: string, rulesFilePath?: string): PolicyRule[] {
  const path = rulesFilePath ?? join(stateDir, 'policy.json');
  if (!existsSync(path)) return [];
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PolicyRule[];
  } catch (err) {
    throw new PolicyFileError(path, err);
  }
}

export function savePolicyRules(stateDir: string, rules: PolicyRule[]): void {
  assertStillHeld('save the policy', stateDir);
  ensureDir(stateDir);
  writeFileAtomic(join(stateDir, 'policy.json'), JSON.stringify(rules, null, 2));
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
  writeFileAtomic(join(stateDir, 'pending.json'), JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Audit sink persistence (JSONL)
// ---------------------------------------------------------------------------

/** Thrown when persisting state would overwrite tamper evidence in audit.jsonl. */
export class AuditTamperError extends Error {}

export interface AuditSinkLoadResult {
  sink: InMemoryAuditSink;
  /** Verdict against the STORED hash chain, judged at load time. */
  integrity: AuditIntegrity;
}

/**
 * Load audit.jsonl verbatim and verify the STORED hash chain.
 *
 * Events are loaded exactly as persisted (`loadVerbatim`), never re-appended
 * through `append()` — appending recomputes `prevHash`/`hash`, which would
 * re-chain a tampered file into a "valid" log and launder the evidence.
 * A tampered log is still loaded (the operator must be able to inspect it);
 * the verdict gates `saveState()` instead.
 */
export function loadAuditSink(stateDir: string): AuditSinkLoadResult {
  const sink = new InMemoryAuditSink();
  const path = join(stateDir, 'audit.jsonl');
  if (!existsSync(path)) return { sink, integrity: 'intact' };
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    // Unreadable evidence is indistinguishable from tampering — fail closed.
    return { sink, integrity: 'tampered' };
  }
  const { events, integrity } = parseStoredAuditJsonl(raw);
  sink.loadVerbatim(events);
  return { sink, integrity };
}

/**
 * Persist the sink to audit.jsonl. Production callers must go through
 * `saveState()`, which refuses to overwrite a tampered log.
 */
export function saveAuditSink(stateDir: string, sink: InMemoryAuditSink): void {
  ensureDir(stateDir);
  const events = sink.read();
  const jsonl = events.map((e) => JSON.stringify(e)).join('\n');
  writeFileAtomic(join(stateDir, 'audit.jsonl'), jsonl ? jsonl + '\n' : '');
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
  writeFileAtomic(join(stateDir, 'revoked.json'), JSON.stringify(ids, null, 2));
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

// ---------------------------------------------------------------------------
// Duration ledger persistence
// ---------------------------------------------------------------------------

/**
 * Load the duration ledger from `duration.json`.
 *
 * Sits beside `spend.json` but is deliberately NOT modelled on it: the spend
 * loader reaches through a cast into the ledger's private Map, which this one
 * avoids by going through the ledger's own serialise/hydrate.
 *
 * A corrupt file starts fresh rather than throwing — unlike `policy.json`,
 * where corruption is a misconfiguration that must be surfaced, this is an
 * accounting record and losing it forgives spend rather than granting
 * authority nobody wrote down.
 */
export function loadDurationLedger(stateDir: string): InMemoryDurationLedger {
  const path = join(stateDir, 'duration.json');
  if (!existsSync(path)) return new InMemoryDurationLedger();
  try {
    return InMemoryDurationLedger.fromJSON(JSON.parse(readFileSync(path, 'utf8')));
  } catch {
    return new InMemoryDurationLedger();
  }
}

export function saveDurationLedger(stateDir: string, ledger: InMemoryDurationLedger): void {
  ensureDir(stateDir);
  writeFileAtomic(join(stateDir, 'duration.json'), JSON.stringify(ledger.toJSON(), null, 2));
}

export function saveSpendLedger(stateDir: string, ledger: InMemorySpendLedger): void {
  ensureDir(stateDir);
  const internal = ledger as unknown as { ledger: Map<string, { spent: number; cap: number }> };
  const data: StoredSpend = {};
  for (const [leaseId, entry] of internal.ledger.entries()) {
    data[leaseId] = { spent: entry.spent, cap: entry.cap };
  }
  writeFileAtomic(join(stateDir, 'spend.json'), JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Combined state bundle
// ---------------------------------------------------------------------------

export interface CliState {
  stateDir: string;
  keyPair: KeyPair;
  auditSink: InMemoryAuditSink;
  /** Stored-chain verdict for audit.jsonl at load time; 'tampered' blocks saveState(). */
  auditIntegrity: AuditIntegrity;
  pendingStore: InMemoryPendingStore;
  revocationList: InMemoryRevocationList;
  spendLedger: InMemorySpendLedger;
  /** Bounds total granted lease time per policy rule (renewal accretion). */
  durationLedger: InMemoryDurationLedger;
}

export function loadState(stateDir: string): CliState {
  ensureDir(stateDir);
  const { sink, integrity } = loadAuditSink(stateDir);
  if (integrity === 'tampered') {
    console.error(
      `WARNING: audit log at ${join(stateDir, 'audit.jsonl')} fails stored hash-chain verification — possible tampering. ` +
        'Commands that persist state will refuse to run so the evidence is preserved. ' +
        'Inspect it with `leasebroker audit`, then archive the file manually before resuming.',
    );
  }
  return {
    stateDir,
    keyPair: loadOrCreateKeyPair(stateDir),
    auditSink: sink,
    auditIntegrity: integrity,
    pendingStore: loadPendingStore(stateDir),
    revocationList: loadRevocationList(stateDir),
    spendLedger: loadSpendLedger(stateDir),
    durationLedger: loadDurationLedger(stateDir),
  };
}

export function saveState(state: CliState): void {
  if (state.auditIntegrity === 'tampered') {
    throw new AuditTamperError(
      `refusing to save state: audit log at ${join(state.stateDir, 'audit.jsonl')} fails stored hash-chain verification. ` +
        'Overwriting it would destroy the tamper evidence. No state files were written. ' +
        'Archive the audit log manually (e.g. move it aside) to resume with a fresh chain.',
    );
  }
  // Commit point: if this transaction no longer holds the lock, another command may have changed the
  // state since this one loaded it. Writing now would erase that change, so write nothing.
  assertStillHeld('save state', state.stateDir);
  // Order matters because a crash can land between files. Enforcement state goes first and the
  // audit log last: "revoked in force, not yet in the log" fails safe, while "revoked in the log,
  // still valid" is false assurance.
  saveRevocationList(state.stateDir, state.revocationList);
  savePendingStore(state.stateDir, state.pendingStore);
  saveSpendLedger(state.stateDir, state.spendLedger);
  saveDurationLedger(state.stateDir, state.durationLedger);
  saveAuditSink(state.stateDir, state.auditSink);
}

// ---------------------------------------------------------------------------
// Serve session
// ---------------------------------------------------------------------------

/**
 * A revocation list that reads `revoked.json` through on every check.
 *
 * `serve` is long-lived and `revoke` is a separate process, so a list loaded
 * once at startup cannot see a lease revoked while the proxy is up: the
 * revocation would not take effect until a restart. This one folds the file in
 * before each answer.
 *
 * Ids are only ever added. Revocation is monotone, so a file that goes missing,
 * is truncated, or fails to parse mid-session leaves what was already learned
 * in force instead of quietly un-revoking it.
 */
export class DiskBackedRevocationList extends InMemoryRevocationList {
  constructor(private readonly path: string) {
    super();
    this.refresh();
  }

  override isRevoked(leaseId: string): boolean {
    this.refresh();
    return super.isRevoked(leaseId);
  }

  private refresh(): void {
    let ids: unknown;
    try {
      ids = JSON.parse(readFileSync(this.path, 'utf8'));
    } catch {
      return; // absent or unreadable: keep what is already known
    }
    if (!Array.isArray(ids)) return;
    for (const id of ids) {
      if (typeof id === 'string') super.revoke(id);
    }
  }
}

/**
 * Keep events a session could not merge into the log, in a file beside it.
 *
 * A session that cannot save (the state lock is held, or the log on disk fails verification) must
 * not simply lose its events. They are NOT merged into audit.jsonl: it cannot be locked, or cannot
 * be trusted, right now. Each spill is its own exclusively created file and is reported on stderr.
 */
function spillUnsavedEvents(stateDir: string, events: AuditEvent[]): void {
  const path = join(stateDir, `audit.unsaved.${process.pid}.${Date.now()}.jsonl`);
  try {
    publishExclusively(path, events.map((e) => JSON.stringify(e)).join('\n') + '\n', 0o600);
    process.stderr.write(`leasebroker: ${events.length} audit event(s) could not be saved to the log and were kept in ${path}\n`);
  } catch (err) {
    process.stderr.write(`leasebroker: ${events.length} audit event(s) could not be saved and could not be kept: ${(err as Error).message}\n`);
  }
}

export interface ServeSession {
  /** State to wire the proxy from. Its revocation list reads through to disk. */
  state: CliState;
  /**
   * Persist what this session changed: its audit events, merged onto whatever
   * the log holds now. Idempotent. Throws {@link AuditTamperError}, writing
   * nothing, if the log on disk fails stored-chain verification.
   */
  save(): void;
}

/**
 * Open the state directory for a long-running `serve` process.
 *
 * `loadState` + `saveState` is right for a command that runs and exits. It is
 * wrong for `serve`: the process holds its load-time snapshot for hours while
 * `request` and `revoke` change the directory under it, and `saveState` at
 * shutdown rewrites every file from that stale snapshot. A lease revoked
 * mid-session came back to life, and the audit events other processes wrote
 * (including the revocation record) were dropped.
 *
 * So a session owns only what it changes. Today that is its audit events: it
 * never mutates revocations, pending requests or the duration ledger, and its
 * tool resolver maps no `spend` action, so the spend ledger is untouched too.
 * If `serve` ever starts changing any of those, persist it here with merge
 * semantics, not by rewriting the file from a snapshot.
 */
export function openServeSession(
  stateDir: string,
  opts: { lockTimeoutMs?: number } = {},
): ServeSession {
  const state = loadState(stateDir);
  state.revocationList = new DiskBackedRevocationList(join(stateDir, 'revoked.json'));

  // Events present at load are already on disk. Everything after is this session's.
  let persisted = state.auditSink.readVerbatim().length;

  return {
    state,
    save(): void {
      const mine = state.auditSink.readVerbatim().slice(persisted);
      if (mine.length === 0) return;

      try {
        // The read-merge-write below must not interleave with a command that is
        // mid-transaction, or one of the two would overwrite the other's events.
        const lock = acquireFileLock(stateLockPath(stateDir), {
          timeoutMs: opts.lockTimeoutMs ?? STATE_LOCK_TIMEOUT_MS,
        });
        try {
          // Re-read the log as it is NOW, verified, and append onto its tail. The
          // chain is recomputed only for the session's own new events, after the
          // stored chain has been checked; a tampered log is never re-chained.
          const { sink, integrity } = loadAuditSink(stateDir);
          if (integrity === 'tampered') {
            throw new AuditTamperError(
              `refusing to save session: audit log at ${join(stateDir, 'audit.jsonl')} fails stored hash-chain verification. ` +
                'Overwriting it would destroy the tamper evidence. Nothing was written.',
            );
          }
          for (const event of mine) sink.append({ ...event, prevHash: '', hash: '' });
          assertStillHeld('save the session', stateDir, lock);

          const events = sink.read();
          writeFileAtomic(join(stateDir, 'audit.jsonl'), events.map((e) => JSON.stringify(e)).join('\n') + '\n');
          persisted = state.auditSink.readVerbatim().length;
        } finally {
          lock.release();
        }
      } catch (err) {
        // Do not lose the evidence: keep what could not be merged next to the log.
        spillUnsavedEvents(stateDir, mine);
        throw err;
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Atomic and exclusive writes
// ---------------------------------------------------------------------------

/** Replace `target` atomically, so a reader never sees an empty or half-written file. */
function writeFileAtomic(target: string, data: string): void {
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, data);
  renameSync(tmp, target);
}

/**
 * Create `target` with `data` only if it does not exist yet; never replace one.
 * The data is written to a temp file first (so nobody reads a half-written file)
 * and installed with a hard link, which fails if the target exists.
 *
 * @returns `true` if this call installed the file, `false` if one was already there.
 */
export function publishExclusively(target: string, data: string, mode: number): boolean {
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, data, { mode });
  try {
    linkSync(tmp, target);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  } finally {
    unlinkSync(tmp);
  }
}

// ---------------------------------------------------------------------------
// State transaction lock
// ---------------------------------------------------------------------------

/** How long a command waits for another to finish with the state directory. */
const STATE_LOCK_TIMEOUT_MS = 10_000;

/** Thrown by `saveState` when the transaction it belongs to no longer holds the state lock. */
export class LockLostError extends Error {}

/**
 * The state-lock handle of the transaction running in this process, if any. `saveState` is the
 * commit point of every command, so it checks this before writing: a transaction that has lost
 * its lock may be holding a snapshot another command has since changed, and committing it would
 * erase that change.
 */
let currentTransaction: FileLockHandle | undefined;

/**
 * Fence a commit: refuse to write unless the lock this work runs under is still ours. Every path that
 * commits under the state lock must call this immediately before its first write: `saveState`,
 * `savePolicyRules` (`policy load` writes directly, not through `saveState`) and the serve session's
 * audit merge. A path that skips it silently loses the protection the others have.
 *
 * @param lock the lock to check; defaults to the transaction running in this process, if any.
 */
function assertStillHeld(what: string, stateDir: string, lock: FileLockHandle | undefined = currentTransaction): void {
  if (lock !== undefined && !lock.isHeld()) {
    throw new LockLostError(
      `refusing to ${what}: the lock on ${stateDir} was lost while this was running, ` +
        'so another command may have changed it. Nothing was written; retry.',
    );
  }
}

function stateLockPath(stateDir: string): string {
  return join(stateDir, 'state.lock');
}

/** Turn a lock timeout into something an operator can act on. */
function explainLockTimeout(err: unknown, stateDir: string, waitedMs: number): unknown {
  if (err instanceof FileLockTimeout) {
    return new Error(
      `another command is using the state directory ${stateDir}: waited ${waitedMs}ms for ${stateLockPath(stateDir)}. ` +
        'Retry; if no leasebroker process is running, the lock is left over and can be removed.',
    );
  }
  return err;
}

/**
 * Run `fn` as one transaction on the state directory.
 *
 * `saveState` rewrites every state file from the snapshot its command loaded. Two
 * short commands running at once therefore each saved a stale snapshot over the
 * other's change: with 12 `revoke` and 12 `request` launched together, about half
 * the revocations and about 37 of 84 audit events were lost, and the audit chain
 * still verified because each surviving file was internally consistent. So a
 * command that changes state must load, change and save INSIDE this lock, and the
 * commands queue instead of overwriting each other.
 *
 * It is a lock around the whole command, not around `saveState`: a lock only at
 * save time would still let both commands load the same snapshot.
 *
 * Read-only commands do not need it (writes replace files atomically, so a reader
 * sees a whole old file or a whole new one). A long-running `serve` never holds
 * it: it takes it only for the brief merge in `ServeSession.save`.
 */
export async function withStateLock<T>(
  stateDir: string,
  fn: () => T | Promise<T>,
  opts: FileLockOptions = {},
): Promise<T> {
  ensureDir(stateDir);
  const timeoutMs = opts.timeoutMs ?? STATE_LOCK_TIMEOUT_MS;
  let lock: FileLockHandle;
  try {
    lock = acquireFileLock(stateLockPath(stateDir), { ...opts, timeoutMs });
  } catch (err) {
    throw explainLockTimeout(err, stateDir, timeoutMs);
  }
  // process.exit() inside fn skips the finally below; 'exit' handlers still run, and releasing is synchronous.
  process.once('exit', lock.release);
  const outer = currentTransaction;
  currentTransaction = lock;
  try {
    return await fn();
  } finally {
    currentTransaction = outer;
    process.removeListener('exit', lock.release);
    lock.release();
  }
}

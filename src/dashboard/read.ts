/**
 * Dashboard read-layer — a read-only projection over the leasebroker state dir.
 *
 * The core never materializes a lease table: it issues PASETO tokens and appends
 * `issuance` audit events. A governance dashboard needs the *current* lease table,
 * so we fold the append-only audit log (`issuance` − revoked − expired) back into
 * a typed `LeaseView[]`. This is the one piece of glue the core doesn't hand you.
 *
 * Read-only by design: it never generates keys or writes state. It parses
 * `audit.jsonl` directly and verifies the STORED hash chain (linkage + content
 * hash per event) plus direct JSON reads of `revoked.json` / `spend.json`.
 *
 * Why not `loadAuditSink().read()`: the sink's `append()` deliberately
 * recomputes `prevHash`/`hash` on every event, so re-loading a file through it
 * RE-CHAINS the log — a tampered file verifies clean against its own fresh
 * chain. Integrity here must be judged against the hashes on disk, which are
 * the actual tamper evidence.
 *
 * Intended consumer: a TanStack Start dashboard whose server functions import
 * these typed helpers directly for end-to-end type safety.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditEvent, Capability, Lease, LeaseRequest } from '../contract/index.js';
import { computeEventHash } from '../audit/hash.js';
import { resolveStateDir } from '../cli/state.js';

export type LeaseStatus = 'active' | 'expired' | 'revoked';

/** A reconstructed lease plus its derived status and (optional) spend. */
export interface LeaseView extends Lease {
  status: LeaseStatus;
  /** Accrued spend in minor units, if a spend ledger entry exists for this lease. */
  spentMinor?: number;
  /** Spend cap in minor units, if known. */
  capMinor?: number;
}

export interface DeriveOptions {
  /** Returns true if a lease id has been revoked. */
  isRevoked: (leaseId: string) => boolean;
  /** Returns the spend ledger entry for a lease id, if any. */
  spend?: (leaseId: string) => { spent: number; cap: number } | undefined;
  /** "Now" for active/expired classification (defaults to current time). */
  now?: Date;
}

/** Narrowed shape of an `issuance` event's detail (built by the Broker). */
interface IssuanceDetail {
  agentId?: string;
  taskId?: string;
  expiresAt?: string;
  capabilities?: Capability[];
  kid?: string;
}

/**
 * Reconstruct the current lease table by folding `issuance` events from the
 * audit log. Non-issuance events are ignored; status is derived from the
 * revocation set and `expiresAt` vs `now`.
 */
export function deriveLeases(events: AuditEvent[], opts: DeriveOptions): LeaseView[] {
  const now = (opts.now ?? new Date()).getTime();
  const out: LeaseView[] = [];
  for (const ev of events) {
    if (ev.type !== 'issuance' || !ev.leaseId) continue;
    const d = ev.detail as IssuanceDetail;
    const expiresAt = typeof d.expiresAt === 'string' ? d.expiresAt : ev.at;
    const status: LeaseStatus = opts.isRevoked(ev.leaseId)
      ? 'revoked'
      : new Date(expiresAt).getTime() <= now
        ? 'expired'
        : 'active';
    const sp = opts.spend?.(ev.leaseId);
    out.push({
      id: ev.leaseId,
      agentId: typeof d.agentId === 'string' ? d.agentId : '',
      taskId: typeof d.taskId === 'string' ? d.taskId : '',
      capabilities: Array.isArray(d.capabilities) ? d.capabilities : [],
      issuedAt: ev.at,
      expiresAt,
      kid: typeof d.kid === 'string' ? d.kid : '',
      status,
      ...(sp ? { spentMinor: sp.spent, capMinor: sp.cap } : {}),
    });
  }
  return out;
}

/** A veto-required request awaiting operator approve/deny. */
export interface PendingView {
  reqId: string;
  agentId: string;
  taskId: string;
  capabilities: Capability[];
  requestedDurationMs: number;
}

export interface DashboardSnapshot {
  leases: LeaseView[];
  audit: AuditEvent[];
  pending: PendingView[];
  counts: { active: number; expired: number; revoked: number; denials: number };
  /** Hash-chain verification result for the audit log, judged against the STORED hashes. */
  integrity: 'intact' | 'tampered';
  /** The resolved state directory this snapshot was read from. */
  stateDir: string;
}

/**
 * Parse `audit.jsonl` and verify the stored hash chain.
 *
 * Verification is against the hashes AS WRITTEN: each event's `prevHash` must
 * equal the previous event's stored `hash`, and its stored `hash` must equal
 * the recomputed content hash. A failure marks the log tampered but parsing
 * continues — the operator should see the log AND the tamper flag, not a
 * blank console. A missing file is an empty, intact log.
 */
function readAuditVerified(stateDir: string): {
  audit: AuditEvent[];
  integrity: 'intact' | 'tampered';
} {
  const path = join(stateDir, 'audit.jsonl');
  if (!existsSync(path)) return { audit: [], integrity: 'intact' };

  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return { audit: [], integrity: 'tampered' };
  }

  const audit: AuditEvent[] = [];
  let integrity: 'intact' | 'tampered' = 'intact';
  for (const line of raw.split('\n')) {
    if (line.trim() === '') continue;
    let ev: AuditEvent;
    try {
      ev = JSON.parse(line) as AuditEvent;
    } catch {
      // Unparseable line — evidence is damaged; keep what parsed so far.
      integrity = 'tampered';
      break;
    }
    const expectedPrev = audit.length === 0 ? '' : (audit[audit.length - 1]?.hash ?? '');
    if (ev.prevHash !== expectedPrev || computeEventHash(ev) !== ev.hash) {
      integrity = 'tampered';
    }
    audit.push(ev);
  }
  return { audit, integrity };
}

function readJsonFile<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T;
  } catch {
    return fallback;
  }
}

/**
 * Read a complete, read-only dashboard snapshot from a leasebroker state dir.
 * Performs no key generation and no writes.
 */
export function readDashboard(stateDirOverride?: string, now?: Date): DashboardSnapshot {
  const stateDir = resolveStateDir(stateDirOverride);
  const { audit, integrity } = readAuditVerified(stateDir);

  const revokedIds = new Set(readJsonFile<string[]>(join(stateDir, 'revoked.json'), []));
  const spendMap = readJsonFile<Record<string, { spent: number; cap: number }>>(
    join(stateDir, 'spend.json'),
    {},
  );
  const pendingRaw = readJsonFile<Record<string, LeaseRequest>>(
    join(stateDir, 'pending.json'),
    {},
  );
  const pending: PendingView[] = Object.entries(pendingRaw).map(([reqId, r]) => ({
    reqId,
    agentId: r.agentId,
    taskId: r.taskId,
    capabilities: r.capabilities,
    requestedDurationMs: r.requestedDurationMs,
  }));

  const leases = deriveLeases(audit, {
    isRevoked: (id) => revokedIds.has(id),
    spend: (id) => spendMap[id],
    now,
  });

  return {
    leases,
    audit,
    pending,
    counts: {
      active: leases.filter((l) => l.status === 'active').length,
      expired: leases.filter((l) => l.status === 'expired').length,
      revoked: leases.filter((l) => l.status === 'revoked').length,
      denials: audit.filter((e) => e.type === 'denial').length,
    },
    integrity,
    stateDir,
  };
}

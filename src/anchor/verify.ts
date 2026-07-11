/**
 * Anchor verification — judge stored proofs against the stored audit chain.
 *
 * Entirely local: no network. Each proof is checked for (1) the anchored
 * chain prefix still being present and un-rewritten — the event at
 * `eventCount - 1` must carry the recorded tip hash, (2) the proof file
 * parsing as a well-formed detached timestamp whose digest IS that tip hash,
 * and (3) what the proof's attestations actually attest: a Bitcoin
 * block-header attestation is a confirmed external witness; a pending
 * (calendar) attestation is a submitted-but-not-yet-confirmed one.
 * Completing pending proofs is `anchor --upgrade`'s job (the network step);
 * verification never needs to leave the machine.
 */

import type { AuditEvent } from '../contract/index.js';
import type { AuditIntegrity } from '../audit/index.js';
import { allAttestations, bytesEqual, hexToBytes, parseDetached } from './ots.js';
import type { AnchorRecord, AnchorRecordsLoad } from './store.js';

export type AnchorCheckStatus = 'confirmed' | 'pending' | 'invalid';

export interface AnchorCheckResult {
  record: AnchorRecord;
  status: AnchorCheckStatus;
  /** Lowest Bitcoin block height among confirming attestations. */
  bitcoinHeight?: number;
  detail: string;
}

/**
 * Overall anchor state for a log:
 * - `anchored`          — at least one Bitcoin-confirmed anchor, none invalid
 * - `anchored-pending`  — anchors submitted, none confirmed yet, none invalid
 * - `unanchored`        — no anchors recorded (feature unused; not a failure)
 * - `broken`            — chain tampered, a proof invalid, or records damaged
 */
export type AnchorState = 'anchored' | 'anchored-pending' | 'unanchored' | 'broken';

export interface AnchorVerification {
  ok: boolean;
  state: AnchorState;
  results: AnchorCheckResult[];
  /** Events covered by the newest non-invalid anchor (0 if none). */
  coveredEvents: number;
}

/** Verify one anchor record + proof against the stored audit events. */
export function verifyAnchorRecord(
  record: AnchorRecord,
  proofBytes: Uint8Array | null,
  events: AuditEvent[],
): AnchorCheckResult {
  if (proofBytes === null) {
    return { record, status: 'invalid', detail: `proof file missing: ${record.proofFile}` };
  }

  if (record.eventCount < 1 || record.eventCount > events.length) {
    return {
      record,
      status: 'invalid',
      detail:
        `anchored prefix of ${record.eventCount} event(s) not present in log ` +
        `(log has ${events.length}) — history may have been truncated or replaced`,
    };
  }

  const tipEvent = events[record.eventCount - 1];
  if (tipEvent === undefined || tipEvent.hash !== record.tipHash) {
    return {
      record,
      status: 'invalid',
      detail: `stored hash at event[${record.eventCount - 1}] does not match anchored tip ${record.tipHash}`,
    };
  }

  let digest: Uint8Array;
  let leaves;
  try {
    const detached = parseDetached(proofBytes);
    if (detached.fileHashOp !== 'sha256') {
      return { record, status: 'invalid', detail: `unexpected file hash op: ${detached.fileHashOp}` };
    }
    digest = detached.digest;
    leaves = allAttestations(detached.root);
  } catch (err) {
    return { record, status: 'invalid', detail: `proof unparseable: ${(err as Error).message}` };
  }

  if (!bytesEqual(digest, hexToBytes(record.tipHash))) {
    return { record, status: 'invalid', detail: 'proof digest does not match the anchored tip hash' };
  }

  const heights = leaves
    .filter((l) => l.attestation.kind === 'bitcoin')
    .map((l) => (l.attestation as { height: number }).height);
  if (heights.length > 0) {
    const bitcoinHeight = Math.min(...heights);
    return {
      record,
      status: 'confirmed',
      bitcoinHeight,
      detail: `Bitcoin block ${bitcoinHeight} attests to ${record.eventCount} event(s)`,
    };
  }

  if (leaves.some((l) => l.attestation.kind === 'pending')) {
    return {
      record,
      status: 'pending',
      detail: `submitted to ${record.calendars.length} calendar(s), awaiting Bitcoin attestation — run \`leasebroker anchor --upgrade\``,
    };
  }

  return { record, status: 'invalid', detail: 'proof carries no recognizable attestations' };
}

/**
 * Fold per-anchor results into one verdict.
 *
 * Policy (fail-closed, matching saveState's stance on tamper evidence):
 * a tampered chain or ANY invalid proof breaks the whole verdict — a proof
 * that stopped matching the log is exactly the signal this feature exists to
 * raise. Pending-only anchors are healthy (Bitcoin latency is normal), and a
 * log with no anchors at all is unanchored-but-ok so `--verify-anchor`
 * stays adoptable before the first cron run fires.
 */
export function summarizeAnchors(
  results: AnchorCheckResult[],
  integrity: AuditIntegrity,
  recordsMalformed: boolean,
): AnchorVerification {
  const nonInvalid = results.filter((r) => r.status !== 'invalid');
  const coveredEvents = nonInvalid.reduce((max, r) => Math.max(max, r.record.eventCount), 0);

  if (integrity === 'tampered' || recordsMalformed || results.some((r) => r.status === 'invalid')) {
    return { ok: false, state: 'broken', results, coveredEvents };
  }
  if (results.some((r) => r.status === 'confirmed')) {
    return { ok: true, state: 'anchored', results, coveredEvents };
  }
  if (results.some((r) => r.status === 'pending')) {
    return { ok: true, state: 'anchored-pending', results, coveredEvents };
  }
  return { ok: true, state: 'unanchored', results, coveredEvents };
}

/** Convenience: verify a full records load against the stored events. */
export function verifyAnchors(
  load: AnchorRecordsLoad,
  events: AuditEvent[],
  integrity: AuditIntegrity,
  readProof: (filename: string) => Uint8Array | null,
): AnchorVerification {
  const results = load.records.map((record) =>
    verifyAnchorRecord(record, readProof(record.proofFile), events),
  );
  return summarizeAnchors(results, integrity, load.malformed);
}

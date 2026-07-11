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
 *
 * Failures split into two categories with opposite security meanings:
 * - `contradicted` — the stored chain DISAGREES with what was anchored
 *   (prefix gone, or a different hash at the anchored index). This is the
 *   history-rewrite signal this feature exists to raise. Breaks the verdict.
 * - `damaged` — the proof cannot testify (missing, unparseable, or not the
 *   proof the record points at). Evidence degradation, not contradiction:
 *   coverage shrinks and the operator should re-anchor, but nothing here
 *   says the chain was rewritten. Surfaced as a degraded verdict (CLI exit
 *   2), never silently dropped — and never conflated with an attack.
 */

import type { AuditEvent } from '../contract/index.js';
import type { AuditIntegrity } from '../audit/index.js';
import { allAttestations, bytesEqual, hexToBytes, parseDetached } from './ots.js';
import type { AnchorRecord, AnchorRecordsLoad } from './store.js';

export type AnchorCheckStatus = 'confirmed' | 'pending' | 'contradicted' | 'damaged';

export interface AnchorCheckResult {
  record: AnchorRecord;
  status: AnchorCheckStatus;
  /** Lowest Bitcoin block height among confirming attestations. */
  bitcoinHeight?: number;
  detail: string;
}

/**
 * Overall anchor state for a log:
 * - `anchored`          — at least one Bitcoin-confirmed anchor
 * - `anchored-pending`  — anchors submitted, none confirmed yet
 * - `unanchored`        — no usable anchors (feature unused; not a failure)
 * - `broken`            — chain tampered or an anchor contradicts the chain
 *
 * Damaged proofs never move the state on their own — they are reported via
 * `damaged` and the exit code, and excluded from coverage.
 */
export type AnchorState = 'anchored' | 'anchored-pending' | 'unanchored' | 'broken';

export interface AnchorVerification {
  /** False only for `broken` — tamper or contradiction, never mere damage. */
  ok: boolean;
  state: AnchorState;
  results: AnchorCheckResult[];
  /** Events covered by the newest usable (confirmed/pending) anchor. */
  coveredEvents: number;
  /** Count of damaged (unusable, non-contradicting) proofs. */
  damaged: number;
  /** True if anchors.jsonl itself had unreadable lines. */
  recordsMalformed: boolean;
}

/** Verify one anchor record + proof against the stored audit events. */
export function verifyAnchorRecord(
  record: AnchorRecord,
  proofBytes: Uint8Array | null,
  events: AuditEvent[],
): AnchorCheckResult {
  // Contradiction checks first: they are about the CHAIN, and must be judged
  // even when the proof file itself is gone or rotten.
  if (record.eventCount < 1 || record.eventCount > events.length) {
    return {
      record,
      status: 'contradicted',
      detail:
        `anchored prefix of ${record.eventCount} event(s) not present in log ` +
        `(log has ${events.length}) — history may have been truncated or replaced`,
    };
  }

  const tipEvent = events[record.eventCount - 1];
  if (tipEvent === undefined || tipEvent.hash !== record.tipHash) {
    return {
      record,
      status: 'contradicted',
      detail: `stored hash at event[${record.eventCount - 1}] does not match anchored tip ${record.tipHash}`,
    };
  }

  if (proofBytes === null) {
    return {
      record,
      status: 'damaged',
      detail: `proof file missing: ${record.proofFile} — re-anchor and investigate`,
    };
  }

  let digest: Uint8Array;
  let leaves;
  try {
    const detached = parseDetached(proofBytes);
    if (detached.fileHashOp !== 'sha256') {
      return { record, status: 'damaged', detail: `unexpected file hash op: ${detached.fileHashOp}` };
    }
    digest = detached.digest;
    leaves = allAttestations(detached.root);
  } catch (err) {
    return { record, status: 'damaged', detail: `proof unparseable: ${(err as Error).message}` };
  }

  if (!bytesEqual(digest, hexToBytes(record.tipHash))) {
    return {
      record,
      status: 'damaged',
      detail: 'proof digest does not match the anchored tip hash — not the proof this record points at',
    };
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

  return { record, status: 'damaged', detail: 'proof carries no recognizable attestations' };
}

/**
 * Fold per-anchor results into one verdict.
 *
 * Policy: fail closed on CONTRADICTION only. A tampered chain or a proof the
 * chain disagrees with breaks the verdict (`broken`, ok=false, CLI exit 1) —
 * that is the history-rewrite alarm and it must never be dampened. Damaged
 * proofs and malformed record lines degrade instead: they are counted,
 * excluded from coverage, and surfaced (CLI exit 2), but they do not break —
 * bit rot is not an attack, and a policy whose only clearing action is
 * deleting the bookkeeping would push operators to destroy evidence.
 * Note the local anchors dir is unauthenticated either way: deletion
 * resistance comes from off-box copies of the (tiny) proof files, not from
 * this verdict. Pending-only anchors are healthy (Bitcoin latency is
 * normal), and a log with no anchors at all is unanchored-but-ok so
 * `--verify-anchor` stays adoptable before the first cron run fires.
 */
export function summarizeAnchors(
  results: AnchorCheckResult[],
  integrity: AuditIntegrity,
  recordsMalformed: boolean,
): AnchorVerification {
  const usable = results.filter((r) => r.status === 'confirmed' || r.status === 'pending');
  const coveredEvents = usable.reduce((max, r) => Math.max(max, r.record.eventCount), 0);
  const damaged = results.filter((r) => r.status === 'damaged').length;

  if (integrity === 'tampered' || results.some((r) => r.status === 'contradicted')) {
    return { ok: false, state: 'broken', results, coveredEvents, damaged, recordsMalformed };
  }
  const state: AnchorState = results.some((r) => r.status === 'confirmed')
    ? 'anchored'
    : results.some((r) => r.status === 'pending')
      ? 'anchored-pending'
      : 'unanchored';
  return { ok: true, state, results, coveredEvents, damaged, recordsMalformed };
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

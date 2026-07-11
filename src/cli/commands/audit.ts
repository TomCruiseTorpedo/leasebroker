/**
 * `leasebroker audit` — view the audit log.
 *
 * Prints audit events from the hash-chained log. Optionally filters by type
 * or limits to the last N events.
 *
 * Usage:
 *   leasebroker audit
 *   leasebroker audit --last 20
 *   leasebroker audit --type issuance
 *   leasebroker audit --verify          (verify hash chain integrity)
 *   leasebroker audit --verify-anchor   (chain integrity + external anchors)
 *   leasebroker audit --by-workflow     (trust-per-workflow report, grouped by taskId)
 *
 * Output: JSON array of AuditEvent objects.
 */

import type { AuditEventType } from '../../contract/index.js';
import { loadAnchorRecords, readProofFile, verifyAnchors } from '../../anchor/index.js';
import { buildWorkflowReport } from '../../audit/index.js';
import type { CliState } from '../state.js';

export interface AuditOptions {
  last?: number;
  type?: AuditEventType;
  verify?: boolean;
  verifyAnchor?: boolean;
  byWorkflow?: boolean;
}

export function cmdAudit(state: CliState, opts: AuditOptions): void {
  if (opts.byWorkflow) {
    // A view over existing data, not new capability. A tampered log is still
    // viewable evidence (same stance as the event listing below).
    const events =
      state.auditIntegrity === 'intact' ? state.auditSink.read() : state.auditSink.readVerbatim();
    const report = buildWorkflowReport(events);
    console.log(
      JSON.stringify(
        { chain: state.auditIntegrity, totalEvents: events.length, ...report },
        null,
        2,
      ),
    );
    return;
  }

  if (opts.verifyAnchor) {
    // Chain integrity AND external anchors, judged locally (no network) —
    // the stored proofs either commit to the stored chain or they don't.
    // Verdict composition lives in summarizeAnchors (fail-closed policy).
    const events =
      state.auditIntegrity === 'intact' ? state.auditSink.read() : state.auditSink.readVerbatim();
    const load = loadAnchorRecords(state.stateDir);
    const verification = verifyAnchors(load, events, state.auditIntegrity, (f) =>
      readProofFile(state.stateDir, f),
    );
    const out = {
      ok: verification.ok,
      chain: state.auditIntegrity,
      anchors: verification.state,
      coveredEvents: verification.coveredEvents,
      totalEvents: events.length,
      damaged: verification.damaged,
      recordsMalformed: verification.recordsMalformed,
      detail: verification.results.map((r) => ({
        anchoredAt: r.record.anchoredAt,
        eventCount: r.record.eventCount,
        status: r.status,
        ...(r.bitcoinHeight !== undefined ? { bitcoinHeight: r.bitcoinHeight } : {}),
        detail: r.detail,
      })),
    };
    // Exit ladder: 1 = broken (tamper/contradiction — the alarm), 2 = degraded
    // (damaged proofs or bad record lines — re-anchor and investigate), 0 = clean.
    if (!verification.ok) {
      console.error(JSON.stringify(out, null, 2));
      process.exit(1);
    }
    console.log(JSON.stringify(out, null, 2));
    if (verification.damaged > 0 || verification.recordsMalformed) {
      process.exit(2);
    }
    return;
  }

  if (opts.verify) {
    // Judged against the STORED chain at load time (state.auditIntegrity).
    // Verifying the in-memory chain instead would be theatre: loading re-chained
    // events would always pass against their own recomputed hashes.
    if (state.auditIntegrity === 'intact') {
      console.log(JSON.stringify({ ok: true, message: 'Audit log hash chain is intact' }));
    } else {
      console.error(
        JSON.stringify({
          ok: false,
          error: 'Audit log fails stored hash-chain verification — possible tampering',
        }),
      );
      process.exit(1);
    }
    return;
  }

  // A tampered log must still be inspectable — it IS the evidence. Show it
  // verbatim (loadState already warned on stderr); an intact chain goes
  // through read()'s verified path.
  let events =
    state.auditIntegrity === 'intact' ? state.auditSink.read() : state.auditSink.readVerbatim();

  if (opts.type !== undefined) {
    events = events.filter((e) => e.type === opts.type);
  }

  if (opts.last !== undefined && opts.last > 0) {
    events = events.slice(-opts.last);
  }

  console.log(JSON.stringify(events, null, 2));
}

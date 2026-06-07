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
 *   leasebroker audit --verify     (verify hash chain integrity)
 *
 * Output: JSON array of AuditEvent objects.
 */

import type { AuditEventType } from '../../contract/index.js';
import type { CliState } from '../state.js';

export interface AuditOptions {
  last?: number;
  type?: AuditEventType;
  verify?: boolean;
}

export function cmdAudit(state: CliState, opts: AuditOptions): void {
  if (opts.verify) {
    // read() verifies the hash chain internally and throws if tampered.
    try {
      state.auditSink.read();
      console.log(JSON.stringify({ ok: true, message: 'Audit log hash chain is intact' }));
    } catch (err) {
      console.error(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }));
      process.exit(1);
    }
    return;
  }

  let events = state.auditSink.read();

  if (opts.type !== undefined) {
    events = events.filter((e) => e.type === opts.type);
  }

  if (opts.last !== undefined && opts.last > 0) {
    events = events.slice(-opts.last);
  }

  console.log(JSON.stringify(events, null, 2));
}

/**
 * `leasebroker approve <reqId>` — approve a pending (veto-required) request.
 *
 * Retrieves the pending request from the store, issues a lease, and prints
 * the granted token.
 *
 * Usage:
 *   leasebroker approve <reqId>
 *
 * Output (JSON):
 *   { "type": "granted", "token": "...", "leaseId": "..." }
 *   { "type": "denied", "reason": "..." }
 */

import type { CliState } from '../state.js';
import { saveState } from '../state.js';
import { wireComponents } from '../wire.js';

export interface ApproveOptions {
  reqId: string;
  rulesFile?: string;
}

export function cmdApprove(state: CliState, opts: ApproveOptions): void {
  const { broker } = wireComponents(state, opts.rulesFile);
  const outcome = broker.approve(opts.reqId);

  saveState(state);

  if (outcome.type === 'granted') {
    console.log(JSON.stringify({ type: 'granted', token: outcome.token, leaseId: outcome.lease.id }));
  } else {
    // denied (reqId not found)
    const reason = outcome.type === 'denied' ? outcome.reason : 'unexpected result';
    console.error(JSON.stringify({ type: 'denied', reason }));
    process.exit(2);
  }
}

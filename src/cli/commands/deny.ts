/**
 * `leasebroker deny <reqId>` — deny a pending (veto-required) request.
 *
 * Removes the pending request from the store and records a denial in
 * the audit log.
 *
 * Usage:
 *   leasebroker deny <reqId>
 *
 * Output:
 *   { "type": "denied", "reqId": "..." }
 */

import type { CliState } from '../state.js';
import { saveState } from '../state.js';
import { wireComponents } from '../wire.js';

export interface DenyOptions {
  reqId: string;
  rulesFile?: string;
}

export function cmdDeny(state: CliState, opts: DenyOptions): void {
  const { broker } = wireComponents(state, opts.rulesFile);
  broker.deny(opts.reqId);

  saveState(state);

  console.log(JSON.stringify({ type: 'denied', reqId: opts.reqId }));
}

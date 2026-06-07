/**
 * `leasebroker pending` — list all pending (veto-required) requests.
 *
 * Prints a JSON array of pending requests awaiting operator review.
 *
 * Usage:
 *   leasebroker pending
 *
 * Output (JSON array):
 *   [{ "reqId": "...", "request": { ... } }, ...]
 */

import type { CliState } from '../state.js';

export function cmdPending(state: CliState): void {
  const pending = state.pendingStore.list();
  console.log(JSON.stringify(pending, null, 2));
}

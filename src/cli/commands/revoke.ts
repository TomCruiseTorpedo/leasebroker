/**
 * `leasebroker revoke <leaseId>` — revoke an active lease.
 *
 * Adds the lease ID to the revocation list so that the enforcer denies
 * all subsequent calls from that lease.
 *
 * Usage:
 *   leasebroker revoke <leaseId>
 *
 * Output (JSON):
 *   { "type": "revoked", "leaseId": "..." }
 */

import type { CliState } from '../state.js';
import { saveState } from '../state.js';

export interface RevokeOptions {
  leaseId: string;
}

export function cmdRevoke(state: CliState, opts: RevokeOptions): void {
  state.revocationList.revoke(opts.leaseId);

  // Audit the revocation.
  state.auditSink.append({
    type: 'revocation',
    at: new Date().toISOString(),
    leaseId: opts.leaseId,
    detail: { reason: 'Revoked by operator via CLI' },
    prevHash: '',
    hash: '',
  });

  saveState(state);

  console.log(JSON.stringify({ type: 'revoked', leaseId: opts.leaseId }));
}

/**
 * Dashboard mutation actions — thin, typed wrappers over the state dir.
 *
 * These mirror the CLI commands (e.g. `cmdRevoke`) so a governance dashboard's
 * server functions can drive the same read-modify-write path the operator CLI
 * uses, instead of reconstructing the broker. Each action loads state, mutates,
 * and persists atomically per call.
 */
import { loadState, resolveStateDir, saveState } from '../cli/state.js';
import { wireComponents } from '../cli/wire.js';

export interface RevokeResult {
  type: 'revoked';
  leaseId: string;
}

export type ApproveResult =
  | { type: 'granted'; leaseId: string }
  | { type: 'denied'; reason: string };

export interface DenyResult {
  type: 'denied';
  reqId: string;
}

/**
 * Approve a pending (veto-required) request: reconstruct the broker (same wiring
 * as the CLI), issue the lease, persist. Mirrors `cmdApprove`.
 */
export function approvePending(reqId: string, stateDirOverride?: string): ApproveResult {
  const stateDir = resolveStateDir(stateDirOverride);
  const state = loadState(stateDir);
  const { broker } = wireComponents(state);
  const outcome = broker.approve(reqId);
  saveState(state);
  if (outcome.type === 'granted') return { type: 'granted', leaseId: outcome.lease.id };
  return {
    type: 'denied',
    reason: outcome.type === 'denied' ? outcome.reason : 'unexpected result',
  };
}

/** Deny a pending request: remove it and audit the denial. Mirrors `cmdDeny`. */
export function denyPending(reqId: string, stateDirOverride?: string): DenyResult {
  const stateDir = resolveStateDir(stateDirOverride);
  const state = loadState(stateDir);
  const { broker } = wireComponents(state);
  broker.deny(reqId);
  saveState(state);
  return { type: 'denied', reqId };
}

/**
 * Revoke a lease by id and append a `revocation` audit event.
 * Read-modify-write of the leasebroker state dir (same path as `leasebroker revoke`).
 */
export function revokeLease(leaseId: string, stateDirOverride?: string): RevokeResult {
  const stateDir = resolveStateDir(stateDirOverride);
  const state = loadState(stateDir);

  state.revocationList.revoke(leaseId);
  state.auditSink.append({
    type: 'revocation',
    at: new Date().toISOString(),
    leaseId,
    detail: { reason: 'Revoked by operator via dashboard' },
    prevHash: '',
    hash: '',
  });

  saveState(state);
  return { type: 'revoked', leaseId };
}

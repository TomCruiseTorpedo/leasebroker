/**
 * Server functions for the governance dashboard.
 *
 * These run server-only (createServerFn strips their bodies from the client
 * bundle) and import the leasebroker core's COMPILED, verified read-layer +
 * actions from `../../../dist`. The dashboard never reaches into the core's
 * TypeScript source — it consumes the same `dist` a package consumer would.
 */
import { createServerFn } from '@tanstack/react-start';
// Verified core modules (built via `npm run build` in the leasebroker root).
import { readDashboard } from '../../../dist/dashboard/read.js';
import { revokeLease, approvePending, denyPending } from '../../../dist/dashboard/actions.js';

/** Read-only snapshot: derived leases + audit feed + counts + integrity. */
export const getSnapshot = createServerFn({ method: 'GET' }).handler(() => {
  return readDashboard();
});

/** Revoke a lease (operator control action). */
export const revokeLeaseFn = createServerFn({ method: 'POST' })
  .validator((leaseId: string) => leaseId)
  .handler(({ data }) => {
    return revokeLease(data);
  });

/** Approve a pending (veto-required) request — issues the lease. */
export const approvePendingFn = createServerFn({ method: 'POST' })
  .validator((reqId: string) => reqId)
  .handler(({ data }) => {
    return approvePending(data);
  });

/** Deny a pending request — no lease issued. */
export const denyPendingFn = createServerFn({ method: 'POST' })
  .validator((reqId: string) => reqId)
  .handler(({ data }) => {
    return denyPending(data);
  });

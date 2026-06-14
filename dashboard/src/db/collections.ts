/**
 * TanStack DB collections — the live data layer.
 *
 * Each collection is a Query Collection that polls the `getSnapshot` server
 * function (refetchInterval) and exposes a reactive, incrementally-queryable
 * view via useLiveQuery. The leases collection also carries an optimistic
 * `onUpdate` handler so a revoke applies instantly client-side, then persists.
 *
 * Replaces the previous manual `router.invalidate()` polling.
 */
import { QueryClient } from '@tanstack/react-query';
import { createCollection } from '@tanstack/react-db';
import { queryCollectionOptions } from '@tanstack/query-db-collection';
import type { LeaseView } from '../../../dist/dashboard/read.js';
import type { AuditEvent } from '../../../dist/contract/index.js';
import { getSnapshot, revokeLeaseFn } from '../server/api';

export const queryClient = new QueryClient();

/** Leases — live table + optimistic revoke (status → 'revoked', then persist). */
export const leasesCollection = createCollection(
  queryCollectionOptions<LeaseView>({
    id: 'leases',
    queryKey: ['leases'],
    queryClient,
    refetchInterval: 4000,
    queryFn: async () => (await getSnapshot()).leases,
    getKey: (l) => l.id,
    onUpdate: async ({ transaction }) => {
      const { original } = transaction.mutations[0];
      await revokeLeaseFn({ data: original.id });
    },
  }),
);

/** Audit log — the live JSONL tail (read-only, hash is the stable key). */
export const auditCollection = createCollection(
  queryCollectionOptions<AuditEvent>({
    id: 'audit',
    queryKey: ['audit'],
    queryClient,
    refetchInterval: 4000,
    queryFn: async () => (await getSnapshot()).audit,
    getKey: (e) => e.hash,
  }),
);

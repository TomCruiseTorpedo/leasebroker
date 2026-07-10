import { useEffect, useState, type ReactNode } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { QueryClientProvider, useQuery } from '@tanstack/react-query';
import { useLiveQuery } from '@tanstack/react-db';
import { queryClient, leasesCollection, auditCollection } from '../db/collections';
import { getSnapshot, approvePendingFn, denyPendingFn } from '../server/api';
import { LeasesTable } from '../components/LeasesTable';
import { AuditFeed } from '../components/AuditFeed';
import { PendingPanel } from '../components/PendingPanel';

export const Route = createFileRoute('/')({ component: RouteComponent });

function RouteComponent() {
  return (
    <ClientOnly>
      <App />
    </ClientOnly>
  );
}

/**
 * Render children only on the client. TanStack DB is a client reactive store,
 * so its hooks (useLiveQuery) must not run during SSR. Server renders a shell;
 * the client mounts the live dashboard after hydration.
 */
function ClientOnly({ children }: { children: ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <Shell message="Loading console…" />;
  return <>{children}</>;
}

function Shell({ message }: { message: string }) {
  return (
    <div className="wrap">
      <div className="topbar">
        <div className="title">
          leasebroker <small>governance console</small>
        </div>
      </div>
      <div className="loading">{message}</div>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  );
}

function Dashboard() {
  // Live queries over the TanStack DB collections (incremental, reactive).
  const { data: leases = [] } = useLiveQuery((q) =>
    q.from({ l: leasesCollection }).orderBy(({ l }) => l.status, 'asc'),
  );
  const { data: audit = [] } = useLiveQuery((q) =>
    q.from({ a: auditCollection }).orderBy(({ a }) => a.at, 'desc'),
  );
  // Meta (integrity + pending) — small, not collection-shaped.
  const meta = useQuery({
    queryKey: ['meta'],
    queryFn: () => getSnapshot(),
    refetchInterval: 4000,
  });

  const pending = meta.data?.pending ?? [];
  // No optimistic default: a tamper-evidence badge must never claim "intact"
  // before the verification result has actually arrived.
  const integrity = meta.data?.integrity;
  const stateDir = meta.data?.stateDir;
  const counts = {
    active: leases.filter((l) => l.status === 'active').length,
    expired: leases.filter((l) => l.status === 'expired').length,
    revoked: leases.filter((l) => l.status === 'revoked').length,
    denials: audit.filter((e) => e.type === 'denial').length,
  };

  // Optimistic revoke: status flips instantly via the collection, then persists.
  const onRevoke = (leaseId: string) => {
    leasesCollection.update(leaseId, (d) => {
      d.status = 'revoked';
    });
  };
  const refreshAll = () => void queryClient.invalidateQueries();
  const onApprove = async (reqId: string) => {
    await approvePendingFn({ data: reqId });
    refreshAll();
  };
  const onDeny = async (reqId: string) => {
    await denyPendingFn({ data: reqId });
    refreshAll();
  };

  if (meta.isLoading && leases.length === 0) return <Shell message="Loading state…" />;

  return (
    <div className="wrap">
      <div className="topbar">
        <div className="title">
          leasebroker <small>governance console · live</small>
          {stateDir ? (
            <div className="statedir" title={stateDir}>
              state: {stateDir}
            </div>
          ) : null}
        </div>
        <div className="counts">
          <span className="count active">
            active <b>{counts.active}</b>
          </span>
          <span className="count expired">
            expired <b>{counts.expired}</b>
          </span>
          <span className="count revoked">
            revoked <b>{counts.revoked}</b>
          </span>
          <span className="count denials">
            denials <b>{counts.denials}</b>
          </span>
          {integrity ? <span className={`badge ${integrity}`}>log {integrity}</span> : null}
        </div>
      </div>
      <div className="grid">
        <div className="panel">
          <h2>Leases ({leases.length})</h2>
          <LeasesTable leases={leases} onRevoke={onRevoke} />
        </div>
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="panel">
            <h2>Pending approvals ({pending.length})</h2>
            <PendingPanel pending={pending} onApprove={onApprove} onDeny={onDeny} />
          </div>
          <div className="panel">
            <h2>Audit feed · live</h2>
            <AuditFeed events={audit} />
          </div>
        </div>
      </div>
    </div>
  );
}

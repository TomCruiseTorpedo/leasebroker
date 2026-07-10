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

  const [actionError, setActionError] = useState<string | null>(null);

  const pending = meta.data?.pending ?? [];
  // No optimistic default: a tamper-evidence badge must never claim "intact"
  // before the verification result has actually arrived.
  const integrity = meta.data?.integrity;
  const stateDir = meta.data?.stateDir;
  // The core refuses to persist over a tampered log (saveState throws
  // AuditTamperError), so every mutation would fail. Lock the controls to match
  // that fail-closed stance instead of letting the operator click into an error.
  const mutationsLocked = integrity === 'tampered';
  const counts = {
    active: leases.filter((l) => l.status === 'active').length,
    expired: leases.filter((l) => l.status === 'expired').length,
    revoked: leases.filter((l) => l.status === 'revoked').length,
    denials: audit.filter((e) => e.type === 'denial').length,
  };

  // Turn a server-thrown action error into an operator-facing line. A tampered
  // log serializes across the server-fn boundary as a plain Error, so match on
  // the message, not the class.
  const actionFailed = (verb: string) => (e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e);
    setActionError(
      /tamper|integrity|hash.chain/i.test(msg)
        ? `Could not ${verb}: the audit log failed integrity verification, so the broker refused to persist. Restore or archive the log first.`
        : `Could not ${verb}: ${msg}`,
    );
  };

  // Optimistic revoke: status flips instantly via the collection, then persists.
  // If persistence rejects (e.g. tampered log), TanStack DB rolls the row back;
  // surface the reason rather than letting it flip back silently.
  const onRevoke = (leaseId: string) => {
    setActionError(null);
    const tx = leasesCollection.update(leaseId, (d) => {
      d.status = 'revoked';
    });
    tx.isPersisted.promise.catch(actionFailed('revoke the lease'));
  };
  const refreshAll = () => void queryClient.invalidateQueries();
  const onApprove = async (reqId: string) => {
    setActionError(null);
    try {
      await approvePendingFn({ data: reqId });
      refreshAll();
    } catch (e) {
      actionFailed('approve the request')(e);
    }
  };
  const onDeny = async (reqId: string) => {
    setActionError(null);
    try {
      await denyPendingFn({ data: reqId });
      refreshAll();
    } catch (e) {
      actionFailed('deny the request')(e);
    }
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
      {mutationsLocked ? (
        <div className="banner warn" role="alert">
          Audit log failed stored hash-chain verification — governance controls are
          locked. The events below are preserved as evidence; restore or archive the
          log to re-enable revoke and approvals.
        </div>
      ) : null}
      {actionError ? (
        <div className="banner error" role="alert">
          <span>{actionError}</span>
          <button type="button" className="banner-dismiss" onClick={() => setActionError(null)}>
            dismiss
          </button>
        </div>
      ) : null}
      <div className="grid">
        <div className="panel">
          <h2>Leases ({leases.length})</h2>
          <LeasesTable leases={leases} onRevoke={onRevoke} disabled={mutationsLocked} />
        </div>
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="panel">
            <h2>Pending approvals ({pending.length})</h2>
            <PendingPanel
              pending={pending}
              onApprove={onApprove}
              onDeny={onDeny}
              disabled={mutationsLocked}
            />
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

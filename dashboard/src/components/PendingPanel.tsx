import type { PendingView } from '../../../dist/dashboard/read.js';
import type { Capability } from '../../../dist/contract/index.js';

function capSummary(caps: Capability[]): string {
  if (!caps.length) return '—';
  return caps
    .map((c) => {
      switch (c.kind) {
        case 'fs.read':
          return `fs.read·${c.paths.length}`;
        case 'fs.write':
          return `fs.write·${c.paths.length}`;
        case 'http.call':
          return `http·${c.endpoints.length}`;
        case 'spend':
          return `spend ${(c.capMinor / 100).toFixed(2)} ${c.currency}`;
        default:
          return 'unknown';
      }
    })
    .join(', ');
}

/** Veto-required requests awaiting an operator decision. */
export function PendingPanel({
  pending,
  onApprove,
  onDeny,
}: {
  pending: PendingView[];
  onApprove: (reqId: string) => void;
  onDeny: (reqId: string) => void;
}) {
  if (pending.length === 0) return <div className="empty">No pending approvals.</div>;
  return (
    <div>
      {pending.map((p) => (
        <div className="pending-row" key={p.reqId}>
          <div className="who">
            {p.agentId} · {p.taskId}{' '}
            <span className="scope">
              {capSummary(p.capabilities)} · {Math.round(p.requestedDurationMs / 60000)}m
            </span>
          </div>
          <div className="pending-actions">
            <button className="approve" onClick={() => onApprove(p.reqId)}>
              approve
            </button>
            <button className="revoke" onClick={() => onDeny(p.reqId)}>
              deny
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

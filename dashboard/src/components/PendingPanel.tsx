import type { PendingView } from '../../../dist/dashboard/read.js';
import { capSummary } from '../lib/capSummary';

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

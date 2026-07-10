import type { PendingView } from '../../../dist/dashboard/read.js';
import { capSummary } from '../lib/capSummary';

/** Veto-required requests awaiting an operator decision. */
export function PendingPanel({
  pending,
  onApprove,
  onDeny,
  disabled = false,
}: {
  pending: PendingView[];
  onApprove: (reqId: string) => void;
  onDeny: (reqId: string) => void;
  /** Lock approve/deny (e.g. audit log failed integrity verification). */
  disabled?: boolean;
}) {
  if (pending.length === 0) return <div className="empty">No pending approvals.</div>;
  const lockTitle = disabled
    ? 'Controls locked: audit log failed integrity verification'
    : undefined;
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
            <button
              className="approve"
              disabled={disabled}
              onClick={() => onApprove(p.reqId)}
              title={lockTitle}
            >
              approve
            </button>
            <button
              className="revoke"
              disabled={disabled}
              onClick={() => onDeny(p.reqId)}
              title={lockTitle}
            >
              deny
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

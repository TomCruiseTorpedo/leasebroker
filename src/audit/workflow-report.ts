/**
 * Trust-per-workflow report — a read-only view grouping audit events by taskId.
 *
 * Answers "which workflows does this broker trust, and was that trust later
 * wrong" with two deliberately separate rates (never one composite score):
 * - approvalRate   = granted / requested — is this workflow trusted?
 * - revocationRate = revoked / granted   — was granted trust later withdrawn?
 *
 * Attribution reality (verified against every production emit site):
 * - `request` / `issuance` events carry `detail.taskId` directly.
 * - `decision` / operator `denial` events carry only `requestId` — joined via
 *   a requestId → taskId map built from `request` events.
 * - `revocation` events carry only `leaseId` — joined via a leaseId → taskId
 *   map built from `issuance` events. (A requestId-only join would silently
 *   report revocationRate ≡ 0.)
 * - In-path proxy `use` / `denial` events carry `leaseId` + `detail.taskId`
 *   (attribution fields added alongside this report); the proxy's
 *   no-token-bound denial is inherently unattributable.
 *
 * Events that resolve to no taskId are counted in `unattributed`, never
 * silently dropped.
 */

import type { AuditEvent } from '../contract/index.js';

export interface WorkflowStats {
  taskId: string;
  /** Lease requests submitted for this workflow. */
  requested: number;
  /** Leases actually issued (includes veto-approved grants). */
  granted: number;
  /** Denials: policy decisions with effect `deny`, operator denials, and in-path proxy denials. */
  denied: number;
  /** Granted leases later revoked. */
  revoked: number;
  /** Permitted in-path tool calls (proxy `use` events). */
  used: number;
  /** granted / requested; 0 when requested is 0. */
  approvalRate: number;
  /** revoked / granted; 0 when granted is 0. */
  revocationRate: number;
}

export interface WorkflowReport {
  workflows: WorkflowStats[];
  /** Events relevant to the report that could not be attributed to a taskId. */
  unattributed: number;
}

function detailTaskId(ev: AuditEvent): string | undefined {
  const t = ev.detail['taskId'];
  return typeof t === 'string' ? t : undefined;
}

/** Build the per-workflow report from audit events (append order). */
export function buildWorkflowReport(events: AuditEvent[]): WorkflowReport {
  // Pass 1 — join maps from the events that carry taskId directly.
  const byRequestId = new Map<string, string>();
  const byLeaseId = new Map<string, string>();
  for (const ev of events) {
    const taskId = detailTaskId(ev);
    if (taskId === undefined) continue;
    if (ev.type === 'request' && ev.requestId !== undefined) {
      byRequestId.set(ev.requestId, taskId);
    }
    if (ev.type === 'issuance') {
      if (ev.requestId !== undefined) byRequestId.set(ev.requestId, taskId);
      if (ev.leaseId !== undefined) byLeaseId.set(ev.leaseId, taskId);
    }
  }

  const resolve = (ev: AuditEvent): string | undefined =>
    detailTaskId(ev) ??
    (ev.requestId !== undefined ? byRequestId.get(ev.requestId) : undefined) ??
    (ev.leaseId !== undefined ? byLeaseId.get(ev.leaseId) : undefined);

  // Pass 2 — count.
  const stats = new Map<string, WorkflowStats>();
  let unattributed = 0;

  const bump = (ev: AuditEvent, field: 'requested' | 'granted' | 'denied' | 'revoked' | 'used'): void => {
    const taskId = resolve(ev);
    if (taskId === undefined) {
      unattributed++;
      return;
    }
    let s = stats.get(taskId);
    if (s === undefined) {
      s = { taskId, requested: 0, granted: 0, denied: 0, revoked: 0, used: 0, approvalRate: 0, revocationRate: 0 };
      stats.set(taskId, s);
    }
    s[field]++;
  };

  for (const ev of events) {
    switch (ev.type) {
      case 'request':
        bump(ev, 'requested');
        break;
      case 'issuance':
        bump(ev, 'granted');
        break;
      case 'decision':
        if (ev.detail['effect'] === 'deny') bump(ev, 'denied');
        break;
      case 'denial':
        bump(ev, 'denied');
        break;
      case 'revocation':
        bump(ev, 'revoked');
        break;
      case 'use':
        bump(ev, 'used');
        break;
    }
  }

  const workflows = [...stats.values()]
    .map((s) => ({
      ...s,
      approvalRate: s.requested === 0 ? 0 : s.granted / s.requested,
      revocationRate: s.granted === 0 ? 0 : s.revoked / s.granted,
    }))
    .sort((a, b) => a.taskId.localeCompare(b.taskId));

  return { workflows, unattributed };
}

/**
 * Tests for the trust-per-workflow report.
 *
 * Required coverage:
 *   - Per-taskId counts against hand-computed expectations, ≥3 taskIds with
 *     mixed granted/denied/revoked outcomes.
 *   - The two join paths that don't carry taskId directly:
 *     decision/operator-denial via requestId, revocation via leaseId.
 *   - In-path proxy events (leaseId + detail.taskId shape).
 *   - Unattributable events counted, never silently dropped.
 *   - Rate edge cases (granted === 0, requested === 0).
 */

import { describe, expect, it } from 'vitest';
import type { AuditEvent } from '../contract/index.js';
import { InMemoryAuditSink } from './audit-sink.js';
import { buildWorkflowReport } from './workflow-report.js';

/** Append production-shaped events through the real sink (hash-chained). */
function fixture(): AuditEvent[] {
  const sink = new InMemoryAuditSink();
  const ev = (e: Partial<AuditEvent> & { type: AuditEvent['type']; detail: Record<string, unknown> }): void =>
    sink.append({ at: '2026-07-11T10:00:00.000Z', prevHash: '', hash: '', ...e } as AuditEvent);

  // t-alpha: requested → granted → used twice in-path → later revoked.
  ev({ type: 'request', requestId: 'r1', detail: { agentId: 'a1', taskId: 't-alpha' } });
  ev({ type: 'decision', requestId: 'r1', detail: { effect: 'allow' } });
  ev({ type: 'issuance', leaseId: 'l1', requestId: 'r1', detail: { agentId: 'a1', taskId: 't-alpha' } });
  // Proxy shape: leaseId + detail.taskId, no requestId.
  ev({ type: 'use', leaseId: 'l1', detail: { toolName: 'read_file', taskId: 't-alpha' } });
  ev({ type: 'use', leaseId: 'l1', detail: { toolName: 'read_file', taskId: 't-alpha' } });
  // Revocation shape: leaseId ONLY (CLI revoke / dashboard action).
  ev({ type: 'revocation', leaseId: 'l1', detail: { reason: 'Revoked by operator via CLI' } });

  // t-beta: requested → policy-denied at request time (decision effect deny, requestId only).
  ev({ type: 'request', requestId: 'r2', detail: { agentId: 'a1', taskId: 't-beta' } });
  ev({ type: 'decision', requestId: 'r2', detail: { effect: 'deny', reason: 'no matching rule' } });

  // t-gamma: requested → veto → operator denial (denial event, requestId only).
  ev({ type: 'request', requestId: 'r3', detail: { agentId: 'a2', taskId: 't-gamma' } });
  ev({ type: 'decision', requestId: 'r3', detail: { effect: 'veto-required' } });
  ev({ type: 'denial', requestId: 'r3', detail: { reason: 'Denied by operator' } });

  // t-delta: requested → granted → in-path denial (proxy shape) → not revoked.
  ev({ type: 'request', requestId: 'r4', detail: { agentId: 'a2', taskId: 't-delta' } });
  ev({ type: 'decision', requestId: 'r4', detail: { effect: 'allow' } });
  ev({ type: 'issuance', leaseId: 'l4', requestId: 'r4', detail: { agentId: 'a2', taskId: 't-delta' } });
  ev({ type: 'denial', leaseId: 'l4', detail: { toolName: 'write_file', reason: 'out of scope', taskId: 't-delta' } });

  // Unattributable: proxy no-token denial (no leaseId, no requestId, no taskId).
  ev({ type: 'denial', detail: { toolName: 'read_file', reason: 'no lease token bound to session' } });

  return sink.read();
}

describe('buildWorkflowReport', () => {
  const report = buildWorkflowReport(fixture());
  const byId = Object.fromEntries(report.workflows.map((w) => [w.taskId, w]));

  it('produces one row per taskId, sorted', () => {
    expect(report.workflows.map((w) => w.taskId)).toEqual(['t-alpha', 't-beta', 't-gamma', 't-delta'].sort());
  });

  it('t-alpha: granted, used twice, revoked — revocationRate 1', () => {
    expect(byId['t-alpha']).toMatchObject({
      requested: 1, granted: 1, denied: 0, revoked: 1, used: 2,
      approvalRate: 1, revocationRate: 1,
    });
  });

  it('t-beta: policy-denied via requestId join — revocationRate 0 when granted is 0', () => {
    expect(byId['t-beta']).toMatchObject({
      requested: 1, granted: 0, denied: 1, revoked: 0, used: 0,
      approvalRate: 0, revocationRate: 0,
    });
  });

  it('t-gamma: operator denial via requestId join', () => {
    expect(byId['t-gamma']).toMatchObject({ requested: 1, granted: 0, denied: 1 });
  });

  it('t-delta: in-path denial attributed, lease not revoked', () => {
    expect(byId['t-delta']).toMatchObject({
      requested: 1, granted: 1, denied: 1, revoked: 0, used: 0,
      approvalRate: 1, revocationRate: 0,
    });
  });

  it('counts the unattributable no-token denial instead of dropping it', () => {
    expect(report.unattributed).toBe(1);
  });

  it('revocation attributed via leaseId even with NO taskId/requestId on the event', () => {
    // Direct regression guard for the requestId-only-join trap.
    expect(byId['t-alpha']?.revoked).toBe(1);
  });

  it('empty log → empty report', () => {
    expect(buildWorkflowReport([])).toEqual({ workflows: [], unattributed: 0 });
  });

  it('non-report events (allow/veto decisions) count nothing', () => {
    const total = report.workflows.reduce(
      (n, w) => n + w.requested + w.granted + w.denied + w.revoked + w.used,
      0,
    );
    // 4 requests + 2 issuances + 3 denials(1 policy,1 operator,1 in-path) + 1 revocation + 2 uses
    expect(total).toBe(12);
  });
});

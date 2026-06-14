/**
 * Tests for the dashboard read-layer fold (deriveLeases).
 * Pure — no filesystem, no clock dependence (fixed `now`).
 */
import { describe, it, expect } from 'vitest';
import type { AuditEvent } from '../contract/index.js';
import { deriveLeases } from './read.js';

const NOW = new Date('2026-06-07T12:00:00Z');

function issuance(
  leaseId: string,
  expiresAt: string,
  detail: Record<string, unknown> = {},
): AuditEvent {
  return {
    type: 'issuance',
    at: '2026-06-07T11:00:00Z',
    leaseId,
    requestId: `req-${leaseId}`,
    detail: {
      agentId: 'agent-x',
      taskId: 'task-1',
      expiresAt,
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/**'] }],
      kid: 'k1',
      ...detail,
    },
    prevHash: '',
    hash: `hash-${leaseId}`,
  } as AuditEvent;
}

function other(type: 'request' | 'decision' | 'denial'): AuditEvent {
  return {
    type,
    at: '2026-06-07T11:00:00Z',
    detail: {},
    prevHash: '',
    hash: `hash-${type}`,
  } as AuditEvent;
}

describe('deriveLeases', () => {
  const isRevoked = (id: string) => id === 'lease-revoked';

  it('classifies active / expired / revoked from a single fold', () => {
    const events: AuditEvent[] = [
      issuance('lease-active', '2026-06-07T18:00:00Z'), // future → active
      issuance('lease-expired', '2026-06-07T06:00:00Z'), // past → expired
      issuance('lease-revoked', '2026-06-07T18:00:00Z'), // future but revoked → revoked
    ];
    const leases = deriveLeases(events, { isRevoked, now: NOW });

    expect(leases).toHaveLength(3);
    const byId = Object.fromEntries(leases.map((l) => [l.id, l.status]));
    expect(byId['lease-active']).toBe('active');
    expect(byId['lease-expired']).toBe('expired');
    expect(byId['lease-revoked']).toBe('revoked');
  });

  it('reconstructs full lease fields from the issuance detail', () => {
    const [lease] = deriveLeases([issuance('lease-1', '2026-06-07T18:00:00Z')], {
      isRevoked,
      now: NOW,
    });
    expect(lease).toMatchObject({
      id: 'lease-1',
      agentId: 'agent-x',
      taskId: 'task-1',
      issuedAt: '2026-06-07T11:00:00Z',
      expiresAt: '2026-06-07T18:00:00Z',
      kid: 'k1',
    });
    expect(lease?.capabilities).toEqual([{ kind: 'fs.read', paths: ['/tmp/**'] }]);
  });

  it('ignores non-issuance events', () => {
    const events: AuditEvent[] = [
      other('request'),
      other('decision'),
      other('denial'),
      issuance('lease-1', '2026-06-07T18:00:00Z'),
    ];
    expect(deriveLeases(events, { isRevoked, now: NOW })).toHaveLength(1);
  });

  it('joins spend ledger entries when provided', () => {
    const spend = (id: string) =>
      id === 'lease-1' ? { spent: 250, cap: 1000 } : undefined;
    const [lease] = deriveLeases([issuance('lease-1', '2026-06-07T18:00:00Z')], {
      isRevoked,
      spend,
      now: NOW,
    });
    expect(lease?.spentMinor).toBe(250);
    expect(lease?.capMinor).toBe(1000);
  });

  it('falls back to event time when expiresAt is missing in detail', () => {
    const ev = issuance('lease-1', '2026-06-07T18:00:00Z');
    // strip expiresAt from detail
    delete (ev.detail as Record<string, unknown>)['expiresAt'];
    const [lease] = deriveLeases([ev], { isRevoked, now: NOW });
    expect(lease?.expiresAt).toBe('2026-06-07T11:00:00Z'); // == ev.at → already expired
    expect(lease?.status).toBe('expired');
  });
});

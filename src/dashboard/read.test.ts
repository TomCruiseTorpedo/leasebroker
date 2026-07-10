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

/**
 * Integrity verification against the STORED chain (file-backed).
 *
 * Regression guard for the load-rechains-the-log bug: loading a file through
 * InMemoryAuditSink.append() recomputes hashes, so verification must happen
 * against the hashes as written on disk, never a re-chain.
 */
import { mkdtempSync, rmSync, readFileSync as readF, writeFileSync as writeF } from 'node:fs';
import { tmpdir } from 'node:os';
import { join as joinPath } from 'node:path';
import { InMemoryAuditSink } from '../audit/index.js';
import { saveAuditSink } from '../cli/state.js';
import { readDashboard } from './read.js';

describe('readDashboard integrity (stored chain)', () => {
  let dir: string;

  function writeValidLog(): void {
    const sink = new InMemoryAuditSink();
    sink.append({ type: 'request', at: '2026-06-07T10:00:00Z', requestId: 'r1', detail: { agentId: 'a' } } as never);
    sink.append({
      type: 'issuance',
      at: '2026-06-07T10:00:01Z',
      leaseId: 'lease-1',
      requestId: 'r1',
      detail: { agentId: 'a', taskId: 't', expiresAt: '2099-01-01T00:00:00Z', capabilities: [], kid: 'k1' },
    } as never);
    sink.append({ type: 'use', at: '2026-06-07T10:00:02Z', leaseId: 'lease-1', detail: {} } as never);
    saveAuditSink(dir, sink);
  }

  it('intact file reads intact, events and leases present', () => {
    dir = mkdtempSync(joinPath(tmpdir(), 'lb-read-'));
    writeValidLog();
    const snap = readDashboard(dir);
    expect(snap.integrity).toBe('intact');
    expect(snap.audit.length).toBe(3);
    expect(snap.leases.length).toBe(1);
    expect(snap.stateDir).toBe(dir);
    rmSync(dir, { recursive: true, force: true });
  });

  it('edited event content is detected as tampered (stored hash mismatch)', () => {
    dir = mkdtempSync(joinPath(tmpdir(), 'lb-read-'));
    writeValidLog();
    const path = joinPath(dir, 'audit.jsonl');
    const lines = readF(path, 'utf8').trim().split('\n');
    const ev = JSON.parse(lines[1]!) as { detail: Record<string, unknown> };
    ev.detail['agentId'] = 'attacker'; // mutate content, keep stored hash
    lines[1] = JSON.stringify(ev);
    writeF(path, lines.join('\n') + '\n');
    const snap = readDashboard(dir);
    expect(snap.integrity).toBe('tampered');
    expect(snap.audit.length).toBe(3); // log still visible alongside the flag
    rmSync(dir, { recursive: true, force: true });
  });

  it('a deleted event is detected as tampered (linkage break)', () => {
    dir = mkdtempSync(joinPath(tmpdir(), 'lb-read-'));
    writeValidLog();
    const path = joinPath(dir, 'audit.jsonl');
    const lines = readF(path, 'utf8').trim().split('\n');
    lines.splice(1, 1); // remove the middle event
    writeF(path, lines.join('\n') + '\n');
    const snap = readDashboard(dir);
    expect(snap.integrity).toBe('tampered');
    rmSync(dir, { recursive: true, force: true });
  });

  it('missing state dir is empty and intact, not tampered', () => {
    const snap = readDashboard(joinPath(tmpdir(), 'lb-read-definitely-missing'));
    expect(snap.integrity).toBe('intact');
    expect(snap.audit).toEqual([]);
    expect(snap.leases).toEqual([]);
  });
});

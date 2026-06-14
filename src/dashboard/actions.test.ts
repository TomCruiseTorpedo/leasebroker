/**
 * Tests for dashboard mutation actions. Uses a real temp state dir (no mocks),
 * and cross-checks the result via the read-layer.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { approvePending, denyPending, revokeLease } from './actions.js';
import { readDashboard } from './read.js';

/** Seed a pending.json with one veto-required request. */
function seedPending(dir: string, reqId: string) {
  writeFileSync(
    join(dir, 'pending.json'),
    JSON.stringify({
      [reqId]: {
        agentId: 'agent-p',
        taskId: 'task-p',
        capabilities: [{ kind: 'fs.read', paths: ['/tmp/**'] }],
        requestedDurationMs: 60_000,
      },
    }),
  );
}

describe('revokeLease', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'lb-dash-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('revokes a lease id and appends a (valid hash-chained) revocation event', () => {
    const res = revokeLease('lease-x', dir);
    expect(res).toEqual({ type: 'revoked', leaseId: 'lease-x' });

    const revoked = JSON.parse(readFileSync(join(dir, 'revoked.json'), 'utf8')) as string[];
    expect(revoked).toContain('lease-x');

    const snap = readDashboard(dir);
    expect(snap.integrity).toBe('intact'); // chain re-verifies after the write
    expect(
      snap.audit.some((e) => e.type === 'revocation' && e.leaseId === 'lease-x'),
    ).toBe(true);
  });
});

describe('approvePending / denyPending', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'lb-dash-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('approve issues a lease and clears the pending request', () => {
    seedPending(dir, 'req-approve');
    const res = approvePending('req-approve', dir);
    expect(res.type).toBe('granted');

    const snap = readDashboard(dir);
    expect(snap.pending).toHaveLength(0); // consumed
    expect(snap.leases.some((l) => l.status === 'active' && l.agentId === 'agent-p')).toBe(true);
    expect(snap.integrity).toBe('intact');
  });

  it('deny removes the pending request (no lease issued)', () => {
    seedPending(dir, 'req-deny');
    const res = denyPending('req-deny', dir);
    expect(res).toEqual({ type: 'denied', reqId: 'req-deny' });

    const snap = readDashboard(dir);
    expect(snap.pending).toHaveLength(0);
    expect(snap.leases).toHaveLength(0); // nothing issued
  });
});

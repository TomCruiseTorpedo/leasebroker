/**
 * smoke.test.ts — top-level integration smoke test.
 *
 * Imports entirely from the public barrel (src/index.ts) to verify the barrel
 * exports work and that the full stack composes correctly end-to-end.
 *
 * This test exercises every layer: contract → signing → policy → audit → broker → enforce.
 * It is intentionally coarse-grained; fine-grained coverage lives in each lane's own tests.
 */

import { describe, it, expect } from 'vitest';
import {
  // Signing
  generateKeyPair,
  PasetoV4PublicSigner,
  // Policy
  DeclarativePolicyEngine,
  loadRules,
  // Audit state stores
  InMemoryAuditSink,
  InMemoryPendingStore,
  InMemoryRevocationList,
  InMemorySpendLedger,
  // Broker
  Broker,
  // Enforce
  LeaseEnforcer,
} from './index.js';

describe('leasebroker public API smoke test', () => {
  // ── Shared setup ────────────────────────────────────────────────────────
  const kp = generateKeyPair('smoke-k1');
  const signer = new PasetoV4PublicSigner(kp);
  const audit = new InMemoryAuditSink();
  const pendingStore = new InMemoryPendingStore();
  const rules = loadRules([
    { ruleId: 'allow-fs-read', effect: 'allow', capabilityKind: 'fs.read' },
    { ruleId: 'allow-spend', effect: 'allow', capabilityKind: 'spend' },
  ]);
  const policy = new DeclarativePolicyEngine(rules);
  const broker = new Broker(policy, signer, audit, pendingStore, kp.kid);
  const revList = new InMemoryRevocationList();
  const spendLedger = new InMemorySpendLedger();
  const enforcer = new LeaseEnforcer(signer, revList, spendLedger);

  // ── Lease issuance ───────────────────────────────────────────────────────

  it('issues a lease for an allowed capability', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-1',
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/safe/**'] }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;
    expect(result.token).toMatch(/^v4\.public\./);
  });

  it('denies a request with no matching allow rule', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-deny',
      capabilities: [{ kind: 'http.call', endpoints: ['api.example.com/**'] }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('denied');
  });

  // ── Enforcement ──────────────────────────────────────────────────────────

  it('allows an in-scope action on a valid lease', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-2',
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/safe/**'] }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;

    const check = enforcer.check(result.token, { kind: 'fs.read', path: '/tmp/safe/hello.txt' });
    expect(check.ok).toBe(true);
  });

  it('denies an out-of-scope action', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-3',
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/safe/**'] }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;

    const check = enforcer.check(result.token, { kind: 'fs.read', path: '/tmp/private/secret.txt' });
    expect(check.ok).toBe(false);
  });

  it('denies a forged token', () => {
    const check = enforcer.check('v4.public.not-a-real-token', {
      kind: 'fs.read',
      path: '/tmp/safe/hello.txt',
    });
    expect(check.ok).toBe(false);
  });

  // ── Spend cap enforcement ────────────────────────────────────────────────

  it('allows spend within cap and denies over-cap', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-spend',
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 100 }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;

    // 80 within cap → ok
    const c1 = enforcer.check(result.token, { kind: 'spend', currency: 'USD', amountMinor: 80 });
    expect(c1.ok).toBe(true);

    // 80 + 50 = 130 > 100 → denied
    const c2 = enforcer.check(result.token, { kind: 'spend', currency: 'USD', amountMinor: 50 });
    expect(c2.ok).toBe(false);
    expect(c2.reason).toMatch(/cap/i);
  });

  // ── Revocation ───────────────────────────────────────────────────────────

  it('denies a revoked lease', () => {
    const result = broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-revoke',
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/safe/**'] }],
      requestedDurationMs: 60_000,
    });
    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;

    // Verify it works before revocation
    const before = enforcer.check(result.token, { kind: 'fs.read', path: '/tmp/safe/file.txt' });
    expect(before.ok).toBe(true);

    // Revoke it
    revList.revoke(result.lease.id);

    // Now the same token should be rejected
    const after = enforcer.check(result.token, { kind: 'fs.read', path: '/tmp/safe/file.txt' });
    expect(after.ok).toBe(false);
    expect(after.reason).toMatch(/revoked/i);
  });

  // ── Audit log ────────────────────────────────────────────────────────────

  it('records audit events for every request', () => {
    const initialCount = audit.read().length;
    broker.request({
      agentId: 'smoke-agent',
      taskId: 'smoke-task-audit',
      capabilities: [{ kind: 'fs.read', paths: ['/tmp/safe/**'] }],
      requestedDurationMs: 60_000,
    });
    const events = audit.read();
    expect(events.length).toBeGreaterThan(initialCount);
    // Must include a 'request' and 'issuance' event
    const types = events.slice(initialCount).map((e) => e.type);
    expect(types).toContain('request');
    expect(types).toContain('issuance');
  });
});

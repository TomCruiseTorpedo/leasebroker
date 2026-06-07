/**
 * Tests for the Broker — issuance orchestration (policy + sign + audit + veto).
 *
 * Test coverage:
 *   - Grant path: policy grants → lease issued, token verifiable, audit trail correct
 *   - Deny path: policy denies → no lease, denial reason returned, audit trail correct
 *   - Veto path (approve): policy veto-required → pending, then approve → lease issued
 *   - Veto path (deny): policy veto-required → pending, then deny → no lease issued
 *   - Validation: malformed request rejected before policy evaluation
 *   - Scope: issued lease capabilities are a subset of requested
 */

import { beforeEach, describe, expect, it } from 'vitest';

import type { AuditEvent, LeaseRequest, PolicyRule } from '../contract/index.js';
import { InMemoryAuditSink } from '../audit/audit-sink.js';
import { InMemoryPendingStore } from '../audit/pending-store.js';
import { generateKeyPair } from '../signing/keygen.js';
import { PasetoV4PublicSigner } from '../signing/signer.js';
import { DeclarativePolicyEngine } from '../policy/engine.js';

import { Broker } from './broker.js';
import type { GrantedResult } from './broker.js';

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const KID = 'test-key-1';

/** A typical lease request for an agent that reads from /data/**. */
function makeFsReadRequest(overrides?: Partial<LeaseRequest>): LeaseRequest {
  return {
    agentId: 'agent-abc',
    taskId: 'task-xyz',
    capabilities: [{ kind: 'fs.read', paths: ['/data/report.txt'] }],
    requestedDurationMs: 60_000,
    ...overrides,
  };
}

/** A minimal allow-rule that matches the makeFsReadRequest fixtures. */
const allowFsReadRule: PolicyRule = {
  ruleId: 'allow-fs-read',
  capabilityKind: 'fs.read',
  effect: 'allow',
  paths: ['/data/**'],
};

/** A veto-required rule for fs.read. */
const vetoFsReadRule: PolicyRule = {
  ruleId: 'veto-fs-read',
  capabilityKind: 'fs.read',
  effect: 'veto-required',
};

/** Collect all audit events of a given type from the sink. */
function eventsOfType(
  sink: InMemoryAuditSink,
  type: AuditEvent['type'],
): AuditEvent[] {
  return sink.read().filter(e => e.type === type);
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

function makeBroker(rules: PolicyRule[]): {
  broker: Broker;
  audit: InMemoryAuditSink;
  pending: InMemoryPendingStore;
  signer: PasetoV4PublicSigner;
} {
  const kp = generateKeyPair(KID);
  const signer = new PasetoV4PublicSigner(kp);
  const policy = new DeclarativePolicyEngine(rules);
  const audit = new InMemoryAuditSink();
  const pending = new InMemoryPendingStore();
  const broker = new Broker(policy, signer, audit, pending, KID);
  return { broker, audit, pending, signer };
}

// ---------------------------------------------------------------------------
// Grant path
// ---------------------------------------------------------------------------

describe('Broker — grant path', () => {
  let broker: Broker;
  let audit: InMemoryAuditSink;
  let signer: PasetoV4PublicSigner;

  beforeEach(() => {
    ({ broker, audit, signer } = makeBroker([allowFsReadRule]));
  });

  it('returns a granted result with a verifiable token', () => {
    const req = makeFsReadRequest();
    const result = broker.request(req);

    expect(result.type).toBe('granted');
    if (result.type !== 'granted') return;

    // Token must be a PASETO v4.public token
    expect(result.token).toMatch(/^v4\.public\./);

    // Token must be verifiable by the signer
    const verified = signer.verify(result.token);
    expect('lease' in verified).toBe(true);
  });

  it('returns a lease with correct agent/task metadata', () => {
    const req = makeFsReadRequest({ agentId: 'my-agent', taskId: 'my-task' });
    const result = broker.request(req) as GrantedResult;

    expect(result.lease.agentId).toBe('my-agent');
    expect(result.lease.taskId).toBe('my-task');
  });

  it('issues a lease with the correct kid', () => {
    const result = broker.request(makeFsReadRequest()) as GrantedResult;
    expect(result.lease.kid).toBe(KID);
  });

  it('issued scope equals requested capabilities (subset invariant)', () => {
    const req = makeFsReadRequest();
    const result = broker.request(req) as GrantedResult;
    // Issued capabilities must equal the requested (all allowed; cannot exceed)
    expect(result.lease.capabilities).toEqual(req.capabilities);
  });

  it('sets issuedAt and expiresAt correctly', () => {
    const before = Date.now();
    const req = makeFsReadRequest({ requestedDurationMs: 30_000 });
    const result = broker.request(req) as GrantedResult;
    const after = Date.now();

    const issuedMs = new Date(result.lease.issuedAt).getTime();
    const expiresMs = new Date(result.lease.expiresAt).getTime();

    expect(issuedMs).toBeGreaterThanOrEqual(before);
    expect(issuedMs).toBeLessThanOrEqual(after);
    expect(expiresMs - issuedMs).toBeCloseTo(30_000, -2); // within ~100ms
  });

  it('appends request, decision, and issuance audit events', () => {
    broker.request(makeFsReadRequest());

    expect(eventsOfType(audit, 'request')).toHaveLength(1);
    expect(eventsOfType(audit, 'decision')).toHaveLength(1);
    expect(eventsOfType(audit, 'issuance')).toHaveLength(1);
  });

  it('decision audit event records grant effect', () => {
    broker.request(makeFsReadRequest());

    const [decisionEvent] = eventsOfType(audit, 'decision');
    expect(decisionEvent?.detail.effect).toBe('grant');
  });

  it('issuance audit event carries leaseId and requestId', () => {
    const result = broker.request(makeFsReadRequest()) as GrantedResult;

    const [issuanceEvent] = eventsOfType(audit, 'issuance');
    expect(issuanceEvent?.leaseId).toBe(result.lease.id);
    expect(issuanceEvent?.requestId).toBeDefined();
  });

  it('audit log passes hash-chain integrity check', () => {
    broker.request(makeFsReadRequest());
    // read() verifies the chain; throws on tamper
    expect(() => audit.read()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Deny path
// ---------------------------------------------------------------------------

describe('Broker — deny path', () => {
  it('returns a denied result when no matching allow-rule exists', () => {
    // No rules → deny-by-default
    const { broker } = makeBroker([]);
    const result = broker.request(makeFsReadRequest());

    expect(result.type).toBe('denied');
    if (result.type !== 'denied') return;
    expect(result.reason).toBeTruthy();
  });

  it('appends request and decision audit events (no issuance)', () => {
    const { broker, audit } = makeBroker([]);
    broker.request(makeFsReadRequest());

    expect(eventsOfType(audit, 'request')).toHaveLength(1);
    expect(eventsOfType(audit, 'decision')).toHaveLength(1);
    expect(eventsOfType(audit, 'issuance')).toHaveLength(0);
  });

  it('decision audit event records deny effect', () => {
    const { broker, audit } = makeBroker([]);
    broker.request(makeFsReadRequest());

    const [decisionEvent] = eventsOfType(audit, 'decision');
    expect(decisionEvent?.detail.effect).toBe('deny');
  });

  it('returns denied for a structurally invalid request', () => {
    const { broker } = makeBroker([allowFsReadRule]);
    // Missing required fields — cast to bypass TypeScript checks for the test
    const badReq = { agentId: '', taskId: 'task', capabilities: [], requestedDurationMs: 1000 } as unknown as LeaseRequest;
    const result = broker.request(badReq);

    expect(result.type).toBe('denied');
  });
});

// ---------------------------------------------------------------------------
// Veto path — pending then approve
// ---------------------------------------------------------------------------

describe('Broker — veto path (pending → approve)', () => {
  let broker: Broker;
  let audit: InMemoryAuditSink;
  let pending: InMemoryPendingStore;
  let signer: PasetoV4PublicSigner;

  beforeEach(() => {
    ({ broker, audit, pending, signer } = makeBroker([vetoFsReadRule]));
  });

  it('returns pending result when policy yields veto-required', () => {
    const result = broker.request(makeFsReadRequest());

    expect(result.type).toBe('pending');
    if (result.type !== 'pending') return;
    expect(typeof result.reqId).toBe('string');
  });

  it('stores the request in the PendingStore', () => {
    const result = broker.request(makeFsReadRequest());
    if (result.type !== 'pending') throw new Error('expected pending');

    expect(pending.get(result.reqId)).toBeDefined();
  });

  it('appends request and decision events but NOT an issuance event', () => {
    broker.request(makeFsReadRequest());

    expect(eventsOfType(audit, 'request')).toHaveLength(1);
    expect(eventsOfType(audit, 'decision')).toHaveLength(1);
    expect(eventsOfType(audit, 'issuance')).toHaveLength(0);
  });

  it('approve yields a granted lease after veto-required', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    const approveResult = broker.approve(pendingResult.reqId);
    expect(approveResult.type).toBe('granted');
    if (approveResult.type !== 'granted') return;

    // Token must be verifiable
    const verified = signer.verify(approveResult.token);
    expect('lease' in verified).toBe(true);
  });

  it('approve removes the request from PendingStore', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.approve(pendingResult.reqId);
    expect(pending.get(pendingResult.reqId)).toBeUndefined();
  });

  it('approve appends an issuance audit event', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.approve(pendingResult.reqId);
    expect(eventsOfType(audit, 'issuance')).toHaveLength(1);
  });

  it('approve returns denied for an unknown reqId', () => {
    const result = broker.approve('non-existent-req-id');
    expect(result.type).toBe('denied');
  });

  it('double-approve cannot issue a second lease', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    // First approve succeeds
    const first = broker.approve(pendingResult.reqId);
    expect(first.type).toBe('granted');

    // Second approve: request has been removed from pending, so it's denied
    const second = broker.approve(pendingResult.reqId);
    expect(second.type).toBe('denied');
  });
});

// ---------------------------------------------------------------------------
// Veto path — pending then deny
// ---------------------------------------------------------------------------

describe('Broker — veto path (pending → deny)', () => {
  let broker: Broker;
  let audit: InMemoryAuditSink;
  let pending: InMemoryPendingStore;

  beforeEach(() => {
    ({ broker, audit, pending } = makeBroker([vetoFsReadRule]));
  });

  it('deny removes the request from PendingStore', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.deny(pendingResult.reqId);
    expect(pending.get(pendingResult.reqId)).toBeUndefined();
  });

  it('deny appends a denial audit event', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.deny(pendingResult.reqId);
    expect(eventsOfType(audit, 'denial')).toHaveLength(1);
  });

  it('deny yields NO issuance event', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.deny(pendingResult.reqId);
    expect(eventsOfType(audit, 'issuance')).toHaveLength(0);
  });

  it('approve after deny returns denied (nothing to approve)', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');

    broker.deny(pendingResult.reqId);
    const result = broker.approve(pendingResult.reqId);
    expect(result.type).toBe('denied');
  });

  it('audit log passes hash-chain integrity after full veto-deny sequence', () => {
    const pendingResult = broker.request(makeFsReadRequest());
    if (pendingResult.type !== 'pending') throw new Error('expected pending');
    broker.deny(pendingResult.reqId);

    expect(() => audit.read()).not.toThrow();
  });
});

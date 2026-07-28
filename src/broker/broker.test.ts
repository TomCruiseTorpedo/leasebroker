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
import { InMemoryDurationLedger } from '../audit/duration-ledger.js';
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

// ---------------------------------------------------------------------------
// Duration budget — the renewal-accretion fix
// ---------------------------------------------------------------------------

describe('Broker — duration budget', () => {
  const HOUR = 3_600_000;

  /** Build a broker whose fs.read rule carries a duration budget. */
  function makeBudgetedBroker(
    maxTotalDurationMs: number,
    durationHalfLifeMs: number,
    extra?: Partial<PolicyRule>,
  ) {
    const kp = generateKeyPair(KID);
    const signer = new PasetoV4PublicSigner(kp);
    const rule: PolicyRule = {
      ruleId: 'budgeted-read',
      capabilityKind: 'fs.read',
      effect: 'allow',
      paths: ['/data/**'],
      maxTotalDurationMs,
      durationHalfLifeMs,
      ...extra,
    };
    const policy = new DeclarativePolicyEngine([rule]);
    const audit = new InMemoryAuditSink();
    const pending = new InMemoryPendingStore();
    const ledger = new InMemoryDurationLedger();
    const broker = new Broker(policy, signer, audit, pending, KID, ledger);
    return { broker, audit, ledger, pending };
  }

  it('a thousand short renewals consume the SAME budget as one long lease', () => {
    // This is the hole. Broker.request used to be stateless across requests,
    // so 1000 sequential 60s leases cost exactly what one 60s lease cost and
    // an agent could assemble standing permission a minute at a time. The
    // package description — capability leases INSTEAD OF standing permissions
    // — was untrue while that held.
    const budget = 2 * HOUR;
    const { broker } = makeBudgetedBroker(budget, 6 * HOUR);

    let totalGrantedMs = 0;
    let denials = 0;

    for (let i = 0; i < 1000; i += 1) {
      const res = broker.request(makeFsReadRequest({ taskId: `task-${i}` }));
      if (res.type === 'granted') {
        const lease = (res as GrantedResult).lease;
        totalGrantedMs +=
          new Date(lease.expiresAt).getTime() - new Date(lease.issuedAt).getTime();
      } else {
        denials += 1;
      }
    }

    // Decay makes a little headroom regenerate during the loop, so the total
    // is bounded by the budget rather than exactly equal to it. The point is
    // that it is BOUNDED at all — it used to be 1000 * 60s = ~16.7 hours.
    expect(totalGrantedMs).toBeLessThanOrEqual(budget * 1.05);
    expect(totalGrantedMs).toBeGreaterThan(0);
    expect(denials).toBeGreaterThan(0); // the budget actually bit
  });

  it('rotating taskId does not buy a fresh budget', () => {
    // taskId is agent-declared. A budget keyed on it would reset every time
    // the agent invented a new one — which is why the key is the matched rule.
    const { broker, ledger } = makeBudgetedBroker(HOUR, 6 * HOUR);
    broker.request(makeFsReadRequest({ taskId: 'first', requestedDurationMs: 30 * 60_000 }));
    broker.request(makeFsReadRequest({ taskId: 'second', requestedDurationMs: 30 * 60_000 }));

    // Both charged the same key, so the budget is spent.
    expect(ledger.headroomMs('budgeted-read', HOUR, 6 * HOUR, Date.now())).toBeLessThan(60_000);
  });

  it('rotating agentId does not buy a fresh budget either', () => {
    const { broker, ledger } = makeBudgetedBroker(HOUR, 6 * HOUR);
    broker.request(makeFsReadRequest({ agentId: 'a', requestedDurationMs: 30 * 60_000 }));
    broker.request(makeFsReadRequest({ agentId: 'b', requestedDurationMs: 30 * 60_000 }));
    expect(ledger.headroomMs('budgeted-read', HOUR, 6 * HOUR, Date.now())).toBeLessThan(60_000);
  });

  it('CLAMPS a legitimate long task rather than denying it', () => {
    // Clamping is the point. Denying an over-long request is what taught
    // agents to max out and renew.
    const { broker } = makeBudgetedBroker(HOUR, 6 * HOUR);
    const res = broker.request(makeFsReadRequest({ requestedDurationMs: 4 * HOUR }));

    expect(res.type).toBe('granted');
    const lease = (res as GrantedResult).lease;
    const grantedMs =
      new Date(lease.expiresAt).getTime() - new Date(lease.issuedAt).getTime();
    expect(grantedMs).toBeLessThanOrEqual(HOUR);
    expect(grantedMs).toBeGreaterThan(0);
  });

  it('denies with a named, non-permanent reason once headroom is gone', () => {
    // A zero-length lease would be a denial dressed as a grant, so exhaustion
    // is reported as what it is — and says the budget regenerates, so a caller
    // knows to wait rather than hammer.
    const { broker } = makeBudgetedBroker(60_000, 6 * HOUR);
    broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));
    const res = broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));

    expect(res.type).toBe('denied');
    if (res.type === 'denied') {
      expect(res.reason).toMatch(/budget exhausted/i);
      expect(res.reason).toContain('budgeted-read');
      expect(res.reason).toMatch(/not a permanent denial/i);
    }
  });

  it('never issues a sub-second lease from a nearly-exhausted budget', () => {
    // Headroom decays continuously, so it approaches zero asymptotically and
    // is almost never exactly zero. Without a minimum grantable duration the
    // broker would keep issuing sub-millisecond leases that expire before they
    // can be used — a denial dressed as a grant, and worse than a denial
    // because the caller is told it succeeded. This assertion was FLAKY before
    // the floor existed: whether it passed depended on how many milliseconds
    // elapsed between the two calls.
    const { broker } = makeBudgetedBroker(60_000, 6 * HOUR);
    const first = broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));
    expect(first.type).toBe('granted');

    for (let i = 0; i < 5; i += 1) {
      const res = broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));
      expect(res.type).toBe('denied');
    }
  });

  it('issues whole milliseconds only', () => {
    const { broker } = makeBudgetedBroker(90_000, 6 * HOUR);
    broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));
    const res = broker.request(makeFsReadRequest({ requestedDurationMs: 60_000 }));
    if (res.type === 'granted') {
      const lease = (res as GrantedResult).lease;
      const ms = new Date(lease.expiresAt).getTime() - new Date(lease.issuedAt).getTime();
      expect(Number.isInteger(ms)).toBe(true);
    }
  });

  it('leaves an unbudgeted rule completely unbounded (opt-in control)', () => {
    const { broker } = makeBroker([allowFsReadRule]);
    for (let i = 0; i < 50; i += 1) {
      expect(broker.request(makeFsReadRequest()).type).toBe('granted');
    }
  });

  it('FAILS CLOSED when a rule declares a budget but no ledger is wired', () => {
    // A declared budget silently going unenforced is exactly the silent
    // non-enforcement this control exists to remove.
    const kp = generateKeyPair(KID);
    const signer = new PasetoV4PublicSigner(kp);
    const policy = new DeclarativePolicyEngine([
      {
        ruleId: 'budgeted-read',
        capabilityKind: 'fs.read',
        effect: 'allow',
        paths: ['/data/**'],
        maxTotalDurationMs: HOUR,
        durationHalfLifeMs: 6 * HOUR,
      },
    ]);
    // No ledger passed.
    const broker = new Broker(policy, signer, new InMemoryAuditSink(), new InMemoryPendingStore(), KID);

    const res = broker.request(makeFsReadRequest());
    expect(res.type).toBe('denied');
    if (res.type === 'denied') {
      expect(res.reason).toMatch(/no DurationLedger is wired/i);
    }
  });

  it('charges the budget on the APPROVE path too', () => {
    // Otherwise an agent whose requests are veto-required routes around the
    // budget entirely, as long as a human keeps clicking approve.
    const kp = generateKeyPair(KID);
    const signer = new PasetoV4PublicSigner(kp);
    const policy = new DeclarativePolicyEngine([
      {
        ruleId: 'veto-budgeted',
        capabilityKind: 'fs.read',
        effect: 'veto-required',
        maxTotalDurationMs: HOUR,
        durationHalfLifeMs: 6 * HOUR,
      },
    ]);
    const ledger = new InMemoryDurationLedger();
    const broker = new Broker(policy, signer, new InMemoryAuditSink(), new InMemoryPendingStore(), KID, ledger);

    const pendingRes = broker.request(makeFsReadRequest({ requestedDurationMs: 30 * 60_000 }));
    expect(pendingRes.type).toBe('pending');
    if (pendingRes.type !== 'pending') return;

    expect(ledger.spentMs('veto-budgeted', 6 * HOUR, Date.now())).toBe(0); // nothing yet
    const approved = broker.approve(pendingRes.reqId);
    expect(approved.type).toBe('granted');
    expect(ledger.spentMs('veto-budgeted', 6 * HOUR, Date.now())).toBeGreaterThan(0);
  });

  it('records granted-vs-requested duration in the issuance audit event', () => {
    const { broker, audit } = makeBudgetedBroker(HOUR, 6 * HOUR);
    broker.request(makeFsReadRequest({ requestedDurationMs: 4 * HOUR }));

    const issuance = eventsOfType(audit, 'issuance')[0];
    expect(issuance?.detail['requestedDurationMs']).toBe(4 * HOUR);
    expect(issuance?.detail['grantedDurationMs']).toBeLessThanOrEqual(HOUR);
    // A lease silently shorter than requested is something an operator needs
    // to see in the log rather than infer.
    expect(issuance?.detail['clampedBy']).toBeDefined();
  });
});

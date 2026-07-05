/**
 * A2A lease extension tests (ADR-F) — covers the spec scenarios:
 * extension-unaware rejection, missing/invalid lease rejection, sticky
 * conflict-safe context binding, and the pending-veto pause.
 */

import { describe, expect, it } from 'vitest';

import type { Action, Enforcer, VerifyResult } from '../contract/index.js';
import {
  attachLeaseToken,
  declaresLeaseExtension,
  extractLeaseToken,
  LEASE_EXT_URI,
  leaseCardExtension,
  parseExtensionsHeader,
  type LeaseCarryingMessage,
} from './extension.js';
import { A2aLeaseBinding } from './binding.js';
import {
  A2A_TASK_STATE_PINS,
  evaluateA2aLeaseGate,
  EXTENSION_SUPPORT_REQUIRED_ERROR,
  type A2aGateDeps,
  type A2aGateRequest,
} from './gate.js';

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

const ACTION: Action = { kind: 'fs.read', path: './data/report.csv' };

/** Enforcer stub: 'good-token' passes, everything else fails with a reason. */
const fakeEnforcer: Pick<Enforcer, 'check'> = {
  check(token: string): VerifyResult {
    return token === 'good-token'
      ? { ok: true }
      : { ok: false, reason: `token '${token}' failed verification` };
  },
};

function gateRequest(over: Partial<A2aGateRequest> = {}): A2aGateRequest {
  return {
    declaredExtensions: [LEASE_EXT_URI],
    metadata: { [LEASE_EXT_URI]: { token: 'good-token' } },
    contextId: 'ctx-1',
    action: ACTION,
    ...over,
  };
}

function deps(over: Partial<A2aGateDeps> = {}): A2aGateDeps {
  return { binding: new A2aLeaseBinding(), enforcer: fakeEnforcer, ...over };
}

// ---------------------------------------------------------------------------
// Extension helpers
// ---------------------------------------------------------------------------

describe('leaseCardExtension', () => {
  it('declares the versioned URI, a description, and required:true by default', () => {
    const entry = leaseCardExtension();
    expect(entry.uri).toBe(LEASE_EXT_URI);
    expect(entry.required).toBe(true);
    expect(entry.description.length).toBeGreaterThan(0);
  });

  it('allows opting into advisory (required:false) declaration', () => {
    expect(leaseCardExtension({ required: false }).required).toBe(false);
  });
});

describe('parseExtensionsHeader / declaresLeaseExtension', () => {
  it('parses comma-separated URIs with whitespace tolerance', () => {
    const declared = parseExtensionsHeader(`  ${LEASE_EXT_URI} , https://other/ext `);
    expect(declared).toEqual([LEASE_EXT_URI, 'https://other/ext']);
    expect(declaresLeaseExtension(declared)).toBe(true);
  });

  it('treats a missing header as declaring nothing', () => {
    expect(parseExtensionsHeader(undefined)).toEqual([]);
    expect(parseExtensionsHeader(null)).toEqual([]);
    expect(declaresLeaseExtension([])).toBe(false);
  });
});

describe('attachLeaseToken / extractLeaseToken', () => {
  it('round-trips: attach writes the URI-keyed payload and the extensions entry', () => {
    const message = attachLeaseToken<LeaseCarryingMessage>({ metadata: { keep: 1 } }, 'tok-1');
    expect(message.extensions).toContain(LEASE_EXT_URI);
    expect(message.metadata?.['keep']).toBe(1); // existing metadata preserved
    expect(extractLeaseToken(message.metadata)).toBe('tok-1');
  });

  it('is pure — the input message is not mutated', () => {
    const original = { metadata: {} };
    attachLeaseToken(original, 'tok-1');
    expect(original.metadata).toEqual({});
  });

  it('extracts undefined for absent or malformed payloads (fails safe)', () => {
    expect(extractLeaseToken(undefined)).toBeUndefined();
    expect(extractLeaseToken({})).toBeUndefined();
    expect(extractLeaseToken({ [LEASE_EXT_URI]: 'not-an-object' })).toBeUndefined();
    expect(extractLeaseToken({ [LEASE_EXT_URI]: { token: '' } })).toBeUndefined();
  });

  it('ignores unknown extra keys in the payload (profile §Versioning)', () => {
    expect(
      extractLeaseToken({ [LEASE_EXT_URI]: { token: 'tok-1', future: true } }),
    ).toBe('tok-1');
  });
});

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

describe('A2aLeaseBinding', () => {
  it('binds, is idempotent for the same token, and conflicts on a different one', () => {
    const binding = new A2aLeaseBinding();
    expect(binding.bind('ctx', 'T1')).toEqual({ ok: true });
    expect(binding.bind('ctx', 'T1')).toEqual({ ok: true });
    const conflict = binding.bind('ctx', 'T2');
    expect(conflict.ok).toBe(false);
    expect(binding.tokenFor('ctx')).toBe('T1');
  });

  it('releases bindings', () => {
    const binding = new A2aLeaseBinding();
    binding.bind('ctx', 'T1');
    binding.release('ctx');
    expect(binding.tokenFor('ctx')).toBeUndefined();
    expect(binding.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// The deny ladder (spec scenarios)
// ---------------------------------------------------------------------------

describe('gate stage 1 — extension support (spec: extension-unaware client)', () => {
  it('rejects at the protocol level with the pinned error triple', () => {
    const decision = evaluateA2aLeaseGate(
      gateRequest({ declaredExtensions: ['https://something/else'] }),
      deps(),
    );
    expect(decision.outcome).toBe('reject-protocol');
    if (decision.outcome === 'reject-protocol') {
      expect(decision.error).toBe(EXTENSION_SUPPORT_REQUIRED_ERROR);
      expect(decision.error.jsonrpcCode).toBe(-32008);
      expect(decision.error.httpStatus).toBe(400);
      expect(decision.error.grpcStatus).toBe('FAILED_PRECONDITION');
    }
  });
});

describe('gate stage 2 — lease (spec: missing or invalid lease rejects the task)', () => {
  it('rejects when no token is presented and none is bound', () => {
    const decision = evaluateA2aLeaseGate(gateRequest({ metadata: {} }), deps());
    expect(decision).toMatchObject({
      outcome: 'reject-task',
      taskState: A2A_TASK_STATE_PINS.denied,
    });
  });

  it('rejects with the enforcement reason when the token fails the pipeline', () => {
    const decision = evaluateA2aLeaseGate(
      gateRequest({ metadata: { [LEASE_EXT_URI]: { token: 'expired-token' } } }),
      deps(),
    );
    expect(decision.outcome).toBe('reject-task');
    if (decision.outcome === 'reject-task') {
      expect(decision.reason).toContain('expired-token');
    }
  });
});

describe('gate context binding (spec: sticky and conflict-safe)', () => {
  it('enforces against the bound token when later messages omit it', () => {
    const binding = new A2aLeaseBinding();
    const d = deps({ binding });

    const first = evaluateA2aLeaseGate(gateRequest(), d);
    expect(first).toEqual({ outcome: 'allow', token: 'good-token' });
    expect(binding.tokenFor('ctx-1')).toBe('good-token');

    const second = evaluateA2aLeaseGate(gateRequest({ metadata: {} }), d);
    expect(second).toEqual({ outcome: 'allow', token: 'good-token' });
  });

  it('rejects a different token on an already-bound context', () => {
    const binding = new A2aLeaseBinding();
    const d = deps({ binding });
    evaluateA2aLeaseGate(gateRequest(), d); // binds good-token

    const swapped = evaluateA2aLeaseGate(
      gateRequest({ metadata: { [LEASE_EXT_URI]: { token: 'other-token' } } }),
      d,
    );
    expect(swapped).toMatchObject({
      outcome: 'reject-task',
      taskState: A2A_TASK_STATE_PINS.denied,
      reason: expect.stringContaining('different lease token'),
    });
    expect(binding.tokenFor('ctx-1')).toBe('good-token'); // binding intact
  });

  it('does not bind a context when enforcement fails', () => {
    const binding = new A2aLeaseBinding();
    evaluateA2aLeaseGate(
      gateRequest({ metadata: { [LEASE_EXT_URI]: { token: 'bad-token' } } }),
      deps({ binding }),
    );
    expect(binding.tokenFor('ctx-1')).toBeUndefined();
  });
});

describe('gate stage 3 — veto (spec: pending veto pauses instead of denying)', () => {
  it('pauses to auth-required when approval is pending', () => {
    const decision = evaluateA2aLeaseGate(
      gateRequest({ metadata: {} }),
      deps({ hasPendingApproval: (ctx) => ctx === 'ctx-1' }),
    );
    expect(decision).toMatchObject({
      outcome: 'pause-task',
      taskState: A2A_TASK_STATE_PINS.vetoPending,
    });
  });

  it('a presented token takes priority over a pending approval', () => {
    const decision = evaluateA2aLeaseGate(
      gateRequest(),
      deps({ hasPendingApproval: () => true }),
    );
    expect(decision).toEqual({ outcome: 'allow', token: 'good-token' });
  });
});

describe('gate stage 4 — allow', () => {
  it('allows a valid token and hands it back for audit/forwarding', () => {
    const decision = evaluateA2aLeaseGate(gateRequest(), deps());
    expect(decision).toEqual({ outcome: 'allow', token: 'good-token' });
  });
});

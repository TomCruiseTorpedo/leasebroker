/**
 * Tests for leasebroker contract Zod schemas.
 *
 * Verifies that schemas:
 *   - Accept valid, well-formed inputs
 *   - Reject malformed inputs (missing scope, unknown kind, float money)
 */

import { describe, it, expect } from 'vitest';
import {
  CapabilitySchema,
  LeaseRequestSchema,
  LeaseSchema,
  PolicyRuleSchema,
} from './schemas.js';

// ---------------------------------------------------------------------------
// CapabilitySchema
// ---------------------------------------------------------------------------

describe('CapabilitySchema', () => {
  describe('fs.read', () => {
    it('accepts a valid fs.read capability', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'fs.read',
        paths: ['./data/**', './config/*.json'],
      });
      expect(result.success).toBe(true);
    });

    it('rejects fs.read with missing paths', () => {
      const result = CapabilitySchema.safeParse({ kind: 'fs.read' });
      expect(result.success).toBe(false);
    });

    it('rejects fs.read with empty paths array', () => {
      const result = CapabilitySchema.safeParse({ kind: 'fs.read', paths: [] });
      expect(result.success).toBe(false);
    });
  });

  describe('fs.write', () => {
    it('accepts a valid fs.write capability', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'fs.write',
        paths: ['./output/**'],
      });
      expect(result.success).toBe(true);
    });

    it('rejects fs.write with missing paths', () => {
      const result = CapabilitySchema.safeParse({ kind: 'fs.write' });
      expect(result.success).toBe(false);
    });
  });

  describe('http.call', () => {
    it('accepts a valid http.call capability', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'http.call',
        endpoints: ['https://api.example.com/v1/**'],
      });
      expect(result.success).toBe(true);
    });

    it('rejects http.call with missing endpoints', () => {
      const result = CapabilitySchema.safeParse({ kind: 'http.call' });
      expect(result.success).toBe(false);
    });

    it('rejects http.call with empty endpoints array', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'http.call',
        endpoints: [],
      });
      expect(result.success).toBe(false);
    });
  });

  describe('spend', () => {
    it('accepts a valid spend capability with integer capMinor', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        currency: 'USD',
        capMinor: 1000,
      });
      expect(result.success).toBe(true);
    });

    it('accepts spend with capMinor = 0 (zero-cap is valid)', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        currency: 'USD',
        capMinor: 0,
      });
      expect(result.success).toBe(true);
    });

    it('rejects spend capability with float capMinor (money must be integer)', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        currency: 'USD',
        capMinor: 10.5,
      });
      expect(result.success).toBe(false);
    });

    it('rejects spend capability with negative capMinor', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        currency: 'USD',
        capMinor: -100,
      });
      expect(result.success).toBe(false);
    });

    it('rejects spend capability with missing currency', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        capMinor: 1000,
      });
      expect(result.success).toBe(false);
    });

    it('rejects spend capability with missing capMinor', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'spend',
        currency: 'USD',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('unknown kind', () => {
    it('rejects an unknown capability kind', () => {
      const result = CapabilitySchema.safeParse({
        kind: 'exec.shell',
        command: 'rm -rf /',
      });
      expect(result.success).toBe(false);
    });

    it('rejects a capability with no kind field', () => {
      const result = CapabilitySchema.safeParse({
        paths: ['./data/**'],
      });
      expect(result.success).toBe(false);
    });

    it('rejects a completely empty object', () => {
      const result = CapabilitySchema.safeParse({});
      expect(result.success).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// LeaseRequestSchema
// ---------------------------------------------------------------------------

describe('LeaseRequestSchema', () => {
  const validRequest = {
    agentId: 'agent-001',
    taskId: 'task-abc',
    capabilities: [{ kind: 'fs.read', paths: ['./data/**'] }],
    requestedDurationMs: 3_600_000,
  };

  it('accepts a valid lease request', () => {
    const result = LeaseRequestSchema.safeParse(validRequest);
    expect(result.success).toBe(true);
  });

  it('accepts a request with multiple capabilities', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/**'] },
        { kind: 'spend', currency: 'USD', capMinor: 500 },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects a request with missing agentId', () => {
    const { agentId: _agentId, ...rest } = validRequest;
    const result = LeaseRequestSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a request with empty agentId', () => {
    const result = LeaseRequestSchema.safeParse({ ...validRequest, agentId: '' });
    expect(result.success).toBe(false);
  });

  it('rejects a request with missing taskId', () => {
    const { taskId: _taskId, ...rest } = validRequest;
    const result = LeaseRequestSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a request with empty capabilities array (missing scope)', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      capabilities: [],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a request with missing capabilities field (missing scope)', () => {
    const { capabilities: _capabilities, ...rest } = validRequest;
    const result = LeaseRequestSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a request with a malformed capability (unknown kind)', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      capabilities: [{ kind: 'network.ssh', host: 'prod-server' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a request with float capMinor in a spend capability', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 9.99 }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a request with missing requestedDurationMs', () => {
    const { requestedDurationMs: _duration, ...rest } = validRequest;
    const result = LeaseRequestSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a request with zero duration', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      requestedDurationMs: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a request with negative duration', () => {
    const result = LeaseRequestSchema.safeParse({
      ...validRequest,
      requestedDurationMs: -1000,
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// LeaseSchema
// ---------------------------------------------------------------------------

describe('LeaseSchema', () => {
  const validLease = {
    id: 'lease-xyz-789',
    agentId: 'agent-001',
    taskId: 'task-abc',
    capabilities: [{ kind: 'fs.read', paths: ['./data/**'] }],
    issuedAt: '2024-06-01T10:00:00.000Z',
    expiresAt: '2024-06-01T11:00:00.000Z',
    kid: 'key-2024-06',
  };

  it('accepts a valid lease', () => {
    const result = LeaseSchema.safeParse(validLease);
    expect(result.success).toBe(true);
  });

  it('accepts a lease with multiple capabilities', () => {
    const result = LeaseSchema.safeParse({
      ...validLease,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/**'] },
        { kind: 'http.call', endpoints: ['https://api.example.com/**'] },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects a lease with missing id', () => {
    const { id: _id, ...rest } = validLease;
    const result = LeaseSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a lease with missing agentId', () => {
    const { agentId: _agentId, ...rest } = validLease;
    const result = LeaseSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a lease with empty capabilities (missing scope)', () => {
    const result = LeaseSchema.safeParse({ ...validLease, capabilities: [] });
    expect(result.success).toBe(false);
  });

  it('rejects a lease with an invalid issuedAt datetime', () => {
    const result = LeaseSchema.safeParse({
      ...validLease,
      issuedAt: 'not-a-date',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a lease with an invalid expiresAt datetime', () => {
    const result = LeaseSchema.safeParse({
      ...validLease,
      expiresAt: '2024-06-01',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a lease with missing kid', () => {
    const { kid: _kid, ...rest } = validLease;
    const result = LeaseSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects a lease with float capMinor in spend capability', () => {
    const result = LeaseSchema.safeParse({
      ...validLease,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 1.5 }],
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PolicyRuleSchema
// ---------------------------------------------------------------------------

describe('PolicyRuleSchema', () => {
  it('accepts a minimal valid allow rule', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-001',
      effect: 'allow',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a veto-required rule', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-high-risk',
      effect: 'veto-required',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a fully-specified rule for fs.read', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-fs-read',
      agentId: 'agent-001',
      capabilityKind: 'fs.read',
      effect: 'allow',
      maxDurationMs: 3_600_000,
      paths: ['./data/**', './config/*.json'],
    });
    expect(result.success).toBe(true);
  });

  it('accepts a fully-specified rule for spend with integer maxCapMinor', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-spend',
      capabilityKind: 'spend',
      effect: 'allow',
      maxCapMinor: 5000,
      currency: 'USD',
    });
    expect(result.success).toBe(true);
  });

  it('rejects a rule with float maxCapMinor (money must be integer)', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-bad-money',
      effect: 'allow',
      maxCapMinor: 50.75,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with negative maxCapMinor', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-neg',
      effect: 'allow',
      maxCapMinor: -100,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with missing ruleId', () => {
    const result = PolicyRuleSchema.safeParse({ effect: 'allow' });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with empty ruleId', () => {
    const result = PolicyRuleSchema.safeParse({ ruleId: '', effect: 'allow' });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with an invalid effect', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-bad',
      effect: 'permit',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with an unknown capabilityKind', () => {
    const result = PolicyRuleSchema.safeParse({
      ruleId: 'rule-exec',
      effect: 'allow',
      capabilityKind: 'exec.shell',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with missing effect', () => {
    const result = PolicyRuleSchema.safeParse({ ruleId: 'rule-no-effect' });
    expect(result.success).toBe(false);
  });
});

/**
 * Tests for DeclarativePolicyEngine and loadRules.
 *
 * Covers:
 *   - allow-match → grant
 *   - no-match    → deny (deny-by-default)
 *   - high-risk   → veto-required
 *   - malformed rule rejected by loadRules
 */

import { describe, it, expect } from 'vitest';
import { DeclarativePolicyEngine } from './engine.js';
import { loadRules } from './loader.js';
import type { LeaseRequest, PolicyRule } from '../contract/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const baseRequest: LeaseRequest = {
  agentId: 'agent-1',
  taskId: 'task-1',
  capabilities: [{ kind: 'fs.read', paths: ['./data/file.txt'] }],
  requestedDurationMs: 60_000,
};

// ---------------------------------------------------------------------------
// allow-match → grant
// ---------------------------------------------------------------------------

describe('DeclarativePolicyEngine — allow-match grants', () => {
  it('grants when a matching allow-rule covers an fs.read capability', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'allow-read', effect: 'allow', capabilityKind: 'fs.read' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate(baseRequest);

    expect(decision.effect).toBe('grant');
    expect(decision.ruleId).toBe('allow-read');
  });

  it('returns the matching ruleId in the decision', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'my-rule', effect: 'allow', capabilityKind: 'fs.read' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate(baseRequest);

    expect(decision.ruleId).toBe('my-rule');
  });

  it('grants when agentId matches the rule', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'agent-specific',
        agentId: 'agent-1',
        effect: 'allow',
        capabilityKind: 'fs.read',
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('grant');
  });

  it('grants an fs.read within the allowed /** path pattern', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'data-read',
        effect: 'allow',
        capabilityKind: 'fs.read',
        paths: ['./data/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'fs.read', paths: ['./data/reports/q1.csv'] }],
    });
    expect(decision.effect).toBe('grant');
  });

  it('grants an fs.write within the allowed path pattern', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'write-output',
        effect: 'allow',
        capabilityKind: 'fs.write',
        paths: ['./output/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'fs.write', paths: ['./output/result.json'] }],
    });
    expect(decision.effect).toBe('grant');
  });

  it('grants an http.call to an allowed endpoint', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'allow-api',
        effect: 'allow',
        capabilityKind: 'http.call',
        endpoints: ['api.example.com/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'http.call', endpoints: ['api.example.com/v1/users'] }],
    });
    expect(decision.effect).toBe('grant');
  });

  it('grants a spend capability within the cap limit', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'spend-ok',
        effect: 'allow',
        capabilityKind: 'spend',
        currency: 'USD',
        maxCapMinor: 1000,
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 500 }],
    });
    expect(decision.effect).toBe('grant');
  });

  it('grants a spend capability exactly at the cap limit', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'spend-exact',
        effect: 'allow',
        capabilityKind: 'spend',
        maxCapMinor: 500,
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 500 }],
    });
    expect(decision.effect).toBe('grant');
  });

  it('grants when the rule has no capabilityKind filter (wildcard)', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'wildcard', effect: 'allow' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('grant');
  });

  it('grants within maxDurationMs', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'short-lease',
        effect: 'allow',
        capabilityKind: 'fs.read',
        maxDurationMs: 120_000,
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('grant'); // 60s < 120s
  });

  it('grants multiple capabilities when all match allow-rules', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'allow-read', effect: 'allow', capabilityKind: 'fs.read' },
      { ruleId: 'allow-http', effect: 'allow', capabilityKind: 'http.call' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/**'] },
        { kind: 'http.call', endpoints: ['api.example.com/v1'] },
      ],
    });
    expect(decision.effect).toBe('grant');
  });
});

// ---------------------------------------------------------------------------
// no-match → deny
// ---------------------------------------------------------------------------

describe('DeclarativePolicyEngine — no-match denies', () => {
  it('denies when there are no rules at all', () => {
    const engine = new DeclarativePolicyEngine([]);
    const decision = engine.evaluate(baseRequest);

    expect(decision.effect).toBe('deny');
    expect(decision.reason).toMatch(/no matching allow-rule/i);
  });

  it('denies when agentId does not match the rule', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'other-agent', agentId: 'agent-X', effect: 'allow', capabilityKind: 'fs.read' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('deny');
  });

  it('denies when capability kind does not match the rule', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'write-only', effect: 'allow', capabilityKind: 'fs.write' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('deny'); // request is fs.read
  });

  it('denies when requested path is outside the allowed paths', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'public-only',
        effect: 'allow',
        capabilityKind: 'fs.read',
        paths: ['./public/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'fs.read', paths: ['./secrets/keys.pem'] }],
    });
    expect(decision.effect).toBe('deny');
  });

  it('denies when one of multiple requested paths is outside the allowed paths', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'data-only',
        effect: 'allow',
        capabilityKind: 'fs.read',
        paths: ['./data/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/file.txt', './secrets/token'] },
      ],
    });
    expect(decision.effect).toBe('deny');
  });

  it('denies when requested duration exceeds maxDurationMs', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'short-only',
        effect: 'allow',
        capabilityKind: 'fs.read',
        maxDurationMs: 30_000, // 30s
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    expect(engine.evaluate(baseRequest).effect).toBe('deny'); // 60s > 30s
  });

  it('denies when spend exceeds maxCapMinor', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'low-spend',
        effect: 'allow',
        capabilityKind: 'spend',
        maxCapMinor: 100,
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 500 }],
    });
    expect(decision.effect).toBe('deny');
  });

  it('denies when spend currency does not match', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'usd-only',
        effect: 'allow',
        capabilityKind: 'spend',
        currency: 'USD',
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'spend', currency: 'EUR', capMinor: 100 }],
    });
    expect(decision.effect).toBe('deny');
  });

  it('denies when one capability in a multi-capability request has no rule', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'allow-read', effect: 'allow', capabilityKind: 'fs.read' },
      // no http.call rule
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/**'] },
        { kind: 'http.call', endpoints: ['api.example.com/v1'] },
      ],
    });
    expect(decision.effect).toBe('deny');
  });

  it('denies an http.call to an endpoint outside the allowed list', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'allow-api-v1',
        effect: 'allow',
        capabilityKind: 'http.call',
        endpoints: ['api.example.com/v1/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'http.call', endpoints: ['evil.example.com/steal'] }],
    });
    expect(decision.effect).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// high-risk → veto-required
// ---------------------------------------------------------------------------

describe('DeclarativePolicyEngine — high-risk yields veto-required', () => {
  it('returns veto-required for a capability matching a veto-required rule', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'high-risk-spend',
        effect: 'veto-required',
        capabilityKind: 'spend',
        maxCapMinor: 100_000,
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'spend', currency: 'USD', capMinor: 50_000 }],
    });

    expect(decision.effect).toBe('veto-required');
    expect(decision.ruleId).toBe('high-risk-spend');
    expect(decision.reason).toMatch(/veto/i);
  });

  it('veto-required dominates allow when multiple capabilities are requested', () => {
    const rules: PolicyRule[] = [
      { ruleId: 'allow-read', effect: 'allow', capabilityKind: 'fs.read' },
      { ruleId: 'veto-spend', effect: 'veto-required', capabilityKind: 'spend' },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [
        { kind: 'fs.read', paths: ['./data/**'] },
        { kind: 'spend', currency: 'USD', capMinor: 500 },
      ],
    });

    expect(decision.effect).toBe('veto-required');
    expect(decision.ruleId).toBe('veto-spend');
  });

  it('returns veto-required for fs.read matching a veto-required rule', () => {
    const rules: PolicyRule[] = [
      {
        ruleId: 'veto-sensitive',
        effect: 'veto-required',
        capabilityKind: 'fs.read',
        paths: ['./sensitive/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate({
      ...baseRequest,
      capabilities: [{ kind: 'fs.read', paths: ['./sensitive/config.json'] }],
    });

    expect(decision.effect).toBe('veto-required');
  });

  it('veto-required rule does not fire when scope is outside the rule paths', () => {
    // A veto-required rule for ./sensitive/** should NOT match a request for ./data/**
    // → because no rule matches → deny, not veto-required
    const rules: PolicyRule[] = [
      {
        ruleId: 'veto-sensitive',
        effect: 'veto-required',
        capabilityKind: 'fs.read',
        paths: ['./sensitive/**'],
      },
    ];
    const engine = new DeclarativePolicyEngine(rules);
    const decision = engine.evaluate(baseRequest); // requests ./data/file.txt

    expect(decision.effect).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// loadRules — malformed rule rejection
// ---------------------------------------------------------------------------

describe('loadRules — malformed rule rejected', () => {
  it('loads a valid rules array', () => {
    const raw = [
      { ruleId: 'r1', effect: 'allow', capabilityKind: 'fs.read' },
    ];
    const rules = loadRules(raw);
    expect(rules).toHaveLength(1);
    expect(rules[0]?.ruleId).toBe('r1');
    expect(rules[0]?.effect).toBe('allow');
  });

  it('loads an empty rules array', () => {
    const rules = loadRules([]);
    expect(rules).toHaveLength(0);
  });

  it('rejects a rule missing ruleId', () => {
    expect(() => loadRules([{ effect: 'allow' }])).toThrow(/invalid policy rules/i);
  });

  it('rejects a rule with an empty ruleId', () => {
    expect(() => loadRules([{ ruleId: '', effect: 'allow' }])).toThrow();
  });

  it('rejects a rule with an invalid effect value', () => {
    // 'permit' is not a valid effect (valid: 'allow' | 'veto-required')
    expect(() =>
      loadRules([{ ruleId: 'r1', effect: 'permit' }])
    ).toThrow();
  });

  it('rejects a rule with a non-integer maxCapMinor (money must be integer)', () => {
    expect(() =>
      loadRules([{ ruleId: 'r1', effect: 'allow', maxCapMinor: 1.5 }])
    ).toThrow();
  });

  it('rejects a rule with a negative maxCapMinor', () => {
    expect(() =>
      loadRules([{ ruleId: 'r1', effect: 'allow', maxCapMinor: -100 }])
    ).toThrow();
  });

  it('rejects a rule with an unknown capabilityKind', () => {
    expect(() =>
      loadRules([{ ruleId: 'r1', effect: 'allow', capabilityKind: 'exec.shell' }])
    ).toThrow();
  });

  it('rejects a non-array input', () => {
    expect(() => loadRules({ ruleId: 'r1', effect: 'allow' })).toThrow();
  });

  it('rejects null input', () => {
    expect(() => loadRules(null)).toThrow();
  });

  it('rejects a string input', () => {
    expect(() => loadRules('not an array')).toThrow();
  });

  it('rejects an array containing a non-object element', () => {
    expect(() => loadRules(['not-a-rule'])).toThrow();
  });

  it('includes error details in the thrown error message', () => {
    let caught: Error | null = null;
    try {
      loadRules([{ effect: 'allow' }]); // missing ruleId
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).not.toBeNull();
    expect(caught?.message).toMatch(/ruleId/i);
  });
});

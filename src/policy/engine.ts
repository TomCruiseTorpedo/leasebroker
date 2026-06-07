/**
 * DeclarativePolicyEngine — the v1 policy engine (ADR-C).
 *
 * Evaluates a LeaseRequest against a set of declarative allow-rules.
 * Deny-by-default: if no allow-rule matches a requested capability, the
 * entire request is denied with a reason.
 *
 * -- CEDAR EXTENSION SEAM (ADR-C) ----------------------------------------
 *
 * This class implements the `PolicyEngine` interface from the contract.
 * To swap in a Cedar-backed engine (or any other policy language):
 *
 *   1. Create a new class (e.g. `CedarPolicyEngine`) in a sibling module,
 *      e.g. `src/policy/cedar-engine.ts`.
 *   2. Implement `PolicyEngine.evaluate(request: LeaseRequest): Decision`.
 *   3. Pass the new engine to the broker's constructor instead of
 *      `DeclarativePolicyEngine`. No other code changes are required.
 *
 * Consumers (broker, CLI, enforce) depend only on the `PolicyEngine`
 * interface from `src/contract/`. The seam is the interface boundary.
 *
 * Mapping to Cedar concepts (for the future implementor):
 *   - `PolicyRule`          ≈ Cedar `permit` policy
 *   - `effect: 'veto-required'` ≈ Cedar `permit` with a side-effect flag
 *   - `agentId`             ≈ Cedar principal
 *   - `capabilityKind`      ≈ Cedar resource type / action group
 *   - `paths` / `endpoints` ≈ Cedar resource attributes
 *   - `maxCapMinor`         ≈ Cedar context condition
 *
 * -------------------------------------------------------------------------
 */

import type {
  Capability,
  Decision,
  LeaseRequest,
  PolicyEngine,
  PolicyRule,
} from '../contract/index.js';

/** Implements the `PolicyEngine` interface over declarative allow-rules. */
export class DeclarativePolicyEngine implements PolicyEngine {
  readonly #rules: readonly PolicyRule[];

  /**
   * @param rules - Validated `PolicyRule[]`, typically produced by `loadRules`.
   */
  constructor(rules: readonly PolicyRule[]) {
    this.#rules = rules;
  }

  /**
   * Evaluate the request against the loaded allow-rules.
   *
   * Algorithm:
   *   - For each requested capability, find the first matching rule.
   *   - If any capability has no matching rule → deny (deny-by-default).
   *   - If all capabilities match, the aggregate effect is:
   *       - `veto-required` if any matched rule yields `veto-required`.
   *       - `grant` if all matched rules yield `allow`.
   */
  evaluate(request: LeaseRequest): Decision {
    if (request.capabilities.length === 0) {
      return { effect: 'deny', reason: 'No capabilities requested' };
    }

    let aggregateEffect: 'grant' | 'veto-required' = 'grant';
    let topRuleId: string | undefined;

    for (const cap of request.capabilities) {
      const matched = this.#findMatchingRule(request, cap);

      if (matched === null) {
        return {
          effect: 'deny',
          reason: `No matching allow-rule for capability kind '${cap.kind}'` +
            (request.agentId ? ` (agent: '${request.agentId}')` : ''),
        };
      }

      if (matched.effect === 'veto-required') {
        // veto-required beats allow; record the first veto-causing rule.
        if (aggregateEffect !== 'veto-required') {
          aggregateEffect = 'veto-required';
          topRuleId = matched.ruleId;
        }
      } else if (aggregateEffect === 'grant') {
        topRuleId = matched.ruleId;
      }
    }

    if (aggregateEffect === 'veto-required') {
      return {
        effect: 'veto-required',
        reason: `Request requires human veto approval (rule: ${topRuleId ?? 'unknown'})`,
        ruleId: topRuleId,
      };
    }

    return {
      effect: 'grant',
      reason: 'All capabilities matched allow-rules',
      ruleId: topRuleId,
    };
  }

  /** Return the first rule that matches the given capability in the request, or null. */
  #findMatchingRule(request: LeaseRequest, cap: Capability): PolicyRule | null {
    for (const rule of this.#rules) {
      if (this.#ruleMatches(rule, request, cap)) {
        return rule;
      }
    }
    return null;
  }

  /** Returns true if `rule` applies to this `cap` within this `request`. */
  #ruleMatches(rule: PolicyRule, request: LeaseRequest, cap: Capability): boolean {
    // Filter by agent
    if (rule.agentId !== undefined && rule.agentId !== request.agentId) {
      return false;
    }

    // Filter by capability kind
    if (rule.capabilityKind !== undefined && rule.capabilityKind !== cap.kind) {
      return false;
    }

    // Filter by requested duration
    if (
      rule.maxDurationMs !== undefined &&
      request.requestedDurationMs > rule.maxDurationMs
    ) {
      return false;
    }

    // Kind-specific scope check
    return this.#scopeIsAllowed(rule, cap);
  }

  /** Returns true if `rule` covers the scope of `cap`. */
  #scopeIsAllowed(rule: PolicyRule, cap: Capability): boolean {
    switch (cap.kind) {
      case 'fs.read':
      case 'fs.write': {
        // No path restriction in the rule → covers any path.
        if (rule.paths === undefined || rule.paths.length === 0) return true;
        // Every requested path must be covered by at least one rule path pattern.
        return cap.paths.every(reqPath =>
          rule.paths!.some(rulePath => pathIsCovered(reqPath, rulePath))
        );
      }

      case 'http.call': {
        if (rule.endpoints === undefined || rule.endpoints.length === 0) return true;
        return cap.endpoints.every(reqEndpoint =>
          rule.endpoints!.some(ruleEndpoint => pathIsCovered(reqEndpoint, ruleEndpoint))
        );
      }

      case 'spend': {
        // Currency must match if the rule specifies one.
        if (rule.currency !== undefined && rule.currency !== cap.currency) {
          return false;
        }
        // Requested cap must not exceed the rule's maximum.
        if (rule.maxCapMinor !== undefined && cap.capMinor > rule.maxCapMinor) {
          return false;
        }
        return true;
      }

      default: {
        // Unknown capability kind — deny (deny-by-default, ADR-C).
        // TypeScript exhaustiveness check.
        const _exhaustive: never = cap;
        void _exhaustive;
        return false;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Path/endpoint matching helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if `requested` is covered by `rulePattern`.
 *
 * Matching rules:
 * - Exact: `requested === rulePattern`
 * - `/**` suffix: covers the base dir and all descendants
 *   e.g. `./data/**` covers `./data/file.txt` and `./data/sub/file.txt`
 * - `/*` suffix: covers immediate children only (no further nesting)
 *   e.g. `./data/*` covers `./data/file.txt` but NOT `./data/sub/file.txt`
 */
function pathIsCovered(requested: string, rulePattern: string): boolean {
  if (rulePattern === requested) return true;

  if (rulePattern.endsWith('/**')) {
    const base = rulePattern.slice(0, -3); // strip `/**`
    return requested === base || requested.startsWith(base + '/');
  }

  if (rulePattern.endsWith('/*')) {
    const base = rulePattern.slice(0, -2); // strip `/*`
    if (!requested.startsWith(base + '/')) return false;
    const rest = requested.slice(base.length + 1);
    return rest.length > 0 && !rest.includes('/');
  }

  return false;
}

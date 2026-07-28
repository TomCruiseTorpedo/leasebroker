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
  MatchedRule,
  PolicyEngine,
  PolicyRule,
} from '../contract/index.js';
import { canonicalizePath } from '../contract/index.js';

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

    // Every rule that matched, deduplicated by ruleId — one rule can cover
    // several capabilities in the same request and must only be charged once.
    const matchedRules = new Map<string, MatchedRule>();

    // The tightest single-lease bound across all matched rules. Starts at the
    // requested duration and only ever shrinks: a lease granted under several
    // rules must respect the shortest of them.
    let grantedDurationMs = request.requestedDurationMs;

    for (const cap of request.capabilities) {
      const matched = this.#findMatchingRule(request, cap);

      if (matched === null) {
        return {
          effect: 'deny',
          reason: `No matching allow-rule for capability kind '${cap.kind}'` +
            (request.agentId ? ` (agent: '${request.agentId}')` : ''),
        };
      }

      // CLAMP, do not deny. An over-long request used to make the rule fail to
      // match and fall through to a denial, which taught agents to request
      // exactly the maximum and renew forever — the very accretion the
      // duration budget exists to stop. Shortening the lease answers the
      // request honestly instead of punishing it.
      if (matched.maxDurationMs !== undefined) {
        grantedDurationMs = Math.min(grantedDurationMs, matched.maxDurationMs);
      }

      if (!matchedRules.has(matched.ruleId)) {
        matchedRules.set(matched.ruleId, {
          ruleId: matched.ruleId,
          ...(matched.maxTotalDurationMs !== undefined
            ? { maxTotalDurationMs: matched.maxTotalDurationMs }
            : {}),
          ...(matched.durationHalfLifeMs !== undefined
            ? { durationHalfLifeMs: matched.durationHalfLifeMs }
            : {}),
        });
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

    const clamped = grantedDurationMs < request.requestedDurationMs;

    if (aggregateEffect === 'veto-required') {
      return {
        effect: 'veto-required',
        reason: `Request requires human veto approval (rule: ${topRuleId ?? 'unknown'})`,
        ruleId: topRuleId,
        grantedDurationMs,
        matchedRules: [...matchedRules.values()],
      };
    }

    return {
      effect: 'grant',
      reason: clamped
        ? `All capabilities matched allow-rules; duration clamped to ${grantedDurationMs}ms ` +
          `by rule maxDurationMs (requested ${request.requestedDurationMs}ms)`
        : 'All capabilities matched allow-rules',
      ruleId: topRuleId,
      grantedDurationMs,
      matchedRules: [...matchedRules.values()],
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
    // Filter by agent.
    //
    // `request.agentId` IS NOT AUTHENTICATED. It is a self-declared string on
    // the incoming request: `Broker.request` takes no credential, and there is
    // no inbound token, mTLS or signature at request time. So an agent selects
    // which rules apply to it by choosing what to call itself.
    //
    // That is a DELIBERATE scope boundary, not a bug — see
    // specs/lease-broker/spec.md: "NOT an identity provider / not user
    // authentication … assuming agent identity is established upstream." The
    // system authenticates LEASES (PASETO v4.public, verified on every call),
    // not REQUESTERS.
    //
    // What it means in practice: an agent-scoped rule is exactly as strong as
    // whatever establishes identity upstream, and this repo neither provides
    // nor checks that. A rule with no `agentId` does not depend on it at all.
    // Anything keyed on the matched rule inherits the same dependency —
    // notably the per-rule duration budget, whose whole purpose is to bound
    // total granted authority. Do not add a security control that keys on
    // `agentId` (or on `taskId`, which is self-declared in the same way)
    // without first closing this, or the control can be reset by renaming.
    if (rule.agentId !== undefined && rule.agentId !== request.agentId) {
      return false;
    }

    // Filter by capability kind
    if (rule.capabilityKind !== undefined && rule.capabilityKind !== cap.kind) {
      return false;
    }

    // NO duration filter here, deliberately.
    //
    // This used to reject the rule when requestedDurationMs exceeded
    // rule.maxDurationMs, so an over-long request fell through every rule and
    // was denied. That is an incentive bug: the only way to get a grant was to
    // ask for at most the maximum, so agents learned to ask for exactly the
    // maximum and then renew, forever — which is precisely the standing-
    // permission accretion the duration budget exists to stop. The policy was
    // training the behaviour it meant to prevent.
    //
    // Duration is now a CLAMP applied in evaluate() rather than a match
    // condition: the rule still matches and the lease is simply shortened.
    // Asking for more than allowed gets you the allowance, not a refusal.

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
          rule.endpoints!.some(ruleEndpoint => endpointIsCovered(reqEndpoint, ruleEndpoint))
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
 * Glob coverage test, on strings taken exactly as given.
 *
 * Matching rules:
 * - Exact: `requested === pattern`
 * - `/**` suffix: covers the base dir and all descendants
 *   e.g. `data/**` covers `data/file.txt` and `data/sub/file.txt`
 * - `/*` suffix: covers immediate children only (no further nesting)
 *   e.g. `data/*` covers `data/file.txt` but NOT `data/sub/file.txt`
 *
 * This is a string-PREFIX test and performs no normalization, which is why it
 * is private: callers must pick `pathIsCovered` or `endpointIsCovered` so the
 * canonicalization decision is made explicitly rather than by default.
 */
function globIsCovered(requested: string, pattern: string): boolean {
  if (pattern === requested) return true;

  if (pattern.endsWith('/**')) {
    const base = pattern.slice(0, -3); // strip `/**`
    return requested === base || requested.startsWith(base + '/');
  }

  if (pattern.endsWith('/*')) {
    const base = pattern.slice(0, -2); // strip `/*`
    if (!requested.startsWith(base + '/')) return false;
    const rest = requested.slice(base.length + 1);
    return rest.length > 0 && !rest.includes('/');
  }

  return false;
}

/**
 * Returns true if the filesystem path `requested` is covered by `rulePattern`.
 *
 * Canonicalizes BOTH sides first. Without that, the prefix test above reports
 * `./data/../../.ssh/id_rsa` as covered by `./data/**` — it carries the prefix
 * while actually climbing out of the directory. The enforcer's minimatch
 * resolves the segments and disagrees, so the broker would MINT and audit-log
 * a lease it believed was scoped to `./data` while it actually named `~/.ssh`,
 * with the denial arriving only later at use time.
 *
 * Schema validation already canonicalizes requests and stored policy rules;
 * repeating it here covers a library caller who constructs capabilities
 * directly and never passes a schema. `canonicalizePath` is idempotent.
 */
function pathIsCovered(requested: string, rulePattern: string): boolean {
  return globIsCovered(canonicalizePath(requested), canonicalizePath(rulePattern));
}

/**
 * Returns true if the HTTP endpoint `requested` is covered by `rulePattern`.
 *
 * Same glob grammar, deliberately WITHOUT path canonicalization: these are
 * URLs, and a filesystem normalizer would rewrite them wrongly (`https://a//b`
 * would collapse to `https:/a/b`). Endpoint matching has its own, separate
 * weakness — it compares a DECLARED endpoint string and nothing intercepts
 * sockets — which is the egress question, not this one.
 */
function endpointIsCovered(requested: string, rulePattern: string): boolean {
  return globIsCovered(requested, rulePattern);
}

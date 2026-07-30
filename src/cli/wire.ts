/**
 * Dependency injection wiring for the CLI.
 *
 * Creates and wires all concrete implementations:
 *   - PasetoV4PublicSigner (from signing lane)
 *   - DeclarativePolicyEngine (from policy lane)
 *   - InMemory* stores (from audit lane)
 *   - Broker (from broker lane)
 *   - LeaseEnforcer (from enforce lane)
 *
 * Consumers receive fully-wired objects via the `wireComponents` function.
 */

import { Broker } from '../broker/index.js';
import { LeaseEnforcer } from '../enforce/index.js';
import { DeclarativePolicyEngine, loadRules } from '../policy/index.js';
import { PasetoV4PublicSigner } from '../signing/index.js';
import type { CliState } from './state.js';
import { loadPolicyRules } from './state.js';

export interface WiredComponents {
  broker: Broker;
  enforcer: LeaseEnforcer;
  signer: PasetoV4PublicSigner;
  /**
   * Rule IDs that are scoped to a specific `agentId`.
   *
   * Surfaced because those rules depend on an identity this system does not
   * establish — see `agentScopedRuleWarning`.
   */
  agentScopedRuleIds: string[];
}

/**
 * Warning text for a policy that contains agent-scoped rules, or null when it
 * does not.
 *
 * WHY THIS EXISTS. `LeaseRequest.agentId` is a self-declared string: the broker
 * takes no credential, and nothing verifies it. leasebroker is deliberately NOT
 * an identity provider — the spec says so, and the design is coherent because
 * what it authenticates is LEASES (PASETO, verified on every call) rather than
 * requesters. But a rule written as `agentId: "reporting-bot"` reads like a
 * restriction, and its strength is entirely inherited from whatever establishes
 * identity upstream. If nothing does, an agent selects which rules apply to it
 * by choosing what to call itself.
 *
 * Documenting that in the spec was not enough: the dependency is invisible at
 * the moment it actually operates. This states it where the rules are loaded,
 * naming the specific rules, so an operator is told about THEIR policy rather
 * than a general caveat they must go looking for.
 *
 * Rules without `agentId` do not depend on this at all, which is why a policy
 * that has none stays silent.
 */
export function agentScopedRuleWarning(agentScopedRuleIds: readonly string[]): string | null {
  if (agentScopedRuleIds.length === 0) return null;
  return (
    `leasebroker: NOTE — ${agentScopedRuleIds.length} policy rule(s) are scoped to an agentId ` +
    `(${agentScopedRuleIds.join(', ')}). agentId is SELF-DECLARED and is not verified here: ` +
    'leasebroker governs capabilities and assumes agent identity is established upstream. ' +
    'Those rules are exactly as strong as that upstream. Rules without an agentId are unaffected.'
  );
}

/**
 * Wire all concrete implementations together.
 *
 * @param state      Loaded CLI state (stores + key pair).
 * @param rulesFile  Optional path to a policy rules JSON file.
 *                   Falls back to the policy.json in the state dir.
 */
export function wireComponents(state: CliState, rulesFile?: string): WiredComponents {
  const kp = state.keyPair;

  // Signer
  const signer = new PasetoV4PublicSigner(kp);

  // Policy engine
  const rawRules = loadPolicyRules(state.stateDir, rulesFile);
  const rules = rawRules.length > 0 ? loadRules(rawRules) : [];
  const policy = new DeclarativePolicyEngine(rules);

  // Broker (wire via interfaces from contract).
  // The duration ledger is passed unconditionally: a rule that declares a
  // budget with no ledger wired fails closed inside the broker, and there is
  // no reason for the CLI to be the path that trips it.
  const broker = new Broker(
    policy,
    signer,
    state.auditSink,
    state.pendingStore,
    kp.kid,
    state.durationLedger,
  );

  // Enforcer
  const enforcer = new LeaseEnforcer(signer, state.revocationList, state.spendLedger);

  const agentScopedRuleIds = rules
    .filter((rule) => rule.agentId !== undefined)
    .map((rule) => rule.ruleId);

  return { broker, enforcer, signer, agentScopedRuleIds };
}

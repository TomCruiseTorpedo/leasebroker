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

  // Broker (wire via interfaces from contract)
  const broker = new Broker(policy, signer, state.auditSink, state.pendingStore, kp.kid);

  // Enforcer
  const enforcer = new LeaseEnforcer(signer, state.revocationList, state.spendLedger);

  return { broker, enforcer, signer };
}

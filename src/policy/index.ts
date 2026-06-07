/**
 * Policy lane — declarative allow-rule `PolicyEngine` implementation (ADR-C).
 *
 * Exports:
 *   - `DeclarativePolicyEngine` — implements `PolicyEngine` from the contract
 *   - `loadRules` — validates raw rule data via zod (rejects malformed rules)
 *
 * Usage:
 * ```ts
 * import { DeclarativePolicyEngine, loadRules } from './policy/index.js';
 * import type { PolicyEngine } from './contract/index.js';
 *
 * const rules = loadRules(JSON.parse(rulesJson));
 * const engine: PolicyEngine = new DeclarativePolicyEngine(rules);
 * const decision = engine.evaluate(request);
 * ```
 *
 * Types and interfaces (`PolicyEngine`, `PolicyRule`, `Decision`, etc.) are
 * imported from `src/contract/` — never redefined here.
 *
 * Cedar seam: see the comment block in `engine.ts` for how to swap in a
 * Cedar-backed `PolicyEngine` implementation without touching any consumers.
 */

export { DeclarativePolicyEngine } from './engine.js';
export { loadRules } from './loader.js';

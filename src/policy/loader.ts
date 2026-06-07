/**
 * Policy rule loader — validates raw data as `PolicyRule[]` via zod.
 *
 * Rules are stored as plain data (JSON, YAML, etc.) and loaded at startup.
 * This module is the trust boundary: any malformed or invalid rule is
 * rejected before it can influence the policy engine.
 */

import { z } from 'zod';
import { PolicyRuleSchema } from '../contract/index.js';
import type { PolicyRule } from '../contract/index.js';

const PolicyRulesArraySchema = z.array(PolicyRuleSchema);

/**
 * Load and validate an array of policy rules from raw (unknown) data.
 *
 * Typically called with the result of `JSON.parse(fs.readFileSync(...))`.
 *
 * @param raw - Arbitrary data to validate as a `PolicyRule[]`.
 * @returns A validated `PolicyRule[]`, safe to pass to `DeclarativePolicyEngine`.
 * @throws {Error} If the input is not a valid array of `PolicyRule` objects.
 *
 * @example
 * ```ts
 * import { loadRules } from './loader.js';
 * import { DeclarativePolicyEngine } from './engine.js';
 *
 * const raw = JSON.parse(await fs.readFile('policy.json', 'utf8'));
 * const rules = loadRules(raw);           // throws on malformed rules
 * const engine = new DeclarativePolicyEngine(rules);
 * ```
 */
export function loadRules(raw: unknown): PolicyRule[] {
  const result = PolicyRulesArraySchema.safeParse(raw);
  if (!result.success) {
    const details = result.error.issues
      .map(issue => {
        const path = issue.path.length > 0 ? `[${issue.path.join('.')}] ` : '';
        return `${path}${issue.message}`;
      })
      .join('; ');
    throw new Error(`Invalid policy rules: ${details}`);
  }
  return result.data;
}

/**
 * `leasebroker policy` — view and manage policy rules.
 *
 * Subcommands:
 *   leasebroker policy show [--rules-file <path>]   Print loaded rules as JSON
 *   leasebroker policy load --rules-file <path>     Load rules from file and save to state dir
 *
 * Usage:
 *   leasebroker policy show
 *   leasebroker policy show --rules-file ./my-rules.json
 *   leasebroker policy load --rules-file ./my-rules.json
 */

import { readFileSync } from 'node:fs';
import { loadRules } from '../../policy/index.js';
import type { CliState } from '../state.js';
import { loadPolicyRules, savePolicyRules } from '../state.js';

export interface PolicyOptions {
  subcommand: 'show' | 'load';
  rulesFile?: string;
}

export function cmdPolicy(state: CliState, opts: PolicyOptions): void {
  if (opts.subcommand === 'show') {
    const rules = loadPolicyRules(state.stateDir, opts.rulesFile);
    console.log(JSON.stringify(rules, null, 2));
    return;
  }

  if (opts.subcommand === 'load') {
    if (!opts.rulesFile) {
      console.error('Error: --rules-file is required for policy load');
      process.exit(1);
    }
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(opts.rulesFile, 'utf8'));
    } catch (err) {
      console.error('Error reading rules file:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
    try {
      const rules = loadRules(raw);
      savePolicyRules(state.stateDir, rules);
      console.log(JSON.stringify({ loaded: rules.length, rules }, null, 2));
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  }
}

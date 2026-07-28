/**
 * Duration ledger — bounds total GRANTED lease time per policy rule.
 *
 * THE HOLE THIS CLOSES. `Broker.request` was stateless across requests: it
 * never consulted its own issuance history, so a thousand sequential 60-second
 * leases cost exactly what one 60-second lease cost. Renewal was unlimited, and
 * an agent could assemble standing permission one minute at a time. That makes
 * the product's central claim — capability leases INSTEAD OF standing
 * permissions — untrue as written.
 *
 * WHAT THE BUDGET IS KEYED ON, AND WHY IT MATTERS MOST. The key is the
 * `ruleId` of the policy rule that matched. Two rejected alternatives:
 *
 *   - Anything the AGENT reports — `taskId`, `agentId`, parent-lease lineage,
 *     a generation counter. All are self-declared strings that nothing
 *     verifies, so a fresh value resets any counter keyed on them. A budget an
 *     agent can reset by renaming itself is not a budget.
 *   - The exact granted SCOPE. Broker-controlled, so not defeated by renaming,
 *     but defeated by splitting: `data/a/**`, `data/b/**` and `data/c/**` are
 *     three distinct keys with three fresh budgets whose union is `data/**`
 *     forever. All three match the same `data/**` RULE, which is why the key
 *     sits at the rule.
 *
 * A rule is authored by a human and selected by the broker, so it is the
 * coarsest thing an agent cannot choose for itself. (Caveat worth knowing: a
 * rule scoped with `agentId` is selected by an unauthenticated string — see the
 * note in `policy/engine.ts`. A rule without `agentId` is unaffected.)
 *
 * DECAY RATHER THAN A FIXED WINDOW. Spend decays exponentially, so headroom
 * regenerates continuously. A cap with no refill is a lifetime budget: because
 * the broker CLAMPS rather than denies, exhaustion would produce zero-length
 * leases — a deny wearing a clamp's clothing — and a long-lived agent would be
 * permanently locked out. A fixed-window reset avoids that but creates a
 * sawtooth and a predictable burn-then-wait-for-midnight game. Decay has
 * neither a cliff nor a reset to schedule around. The half-life IS the policy
 * statement: short approximates a rate limit, long approximates a hard budget
 * with slow forgiveness.
 *
 * DELIBERATELY UNLIKE `InMemorySpendLedger`: this ledger does NOT store the
 * cap. The spend ledger's `setCap` updates an existing key, so a ledger cloned
 * from it would silently reset a budget every time the same key was seen again
 * — exactly the accretion bug this exists to stop. Here the cap and half-life
 * are read from the matched rule on every call and never persisted, so the
 * stored state is only what was actually spent and when.
 */

import type { DurationLedger } from '../contract/index.js';

/** Persisted per-key state: decayed spend and the instant it was computed. */
export interface DurationLedgerEntry {
  /** Granted milliseconds accrued against this key, as of `updatedAt`. */
  spentMs: number;
  /** Epoch ms at which `spentMs` was last recomputed. */
  updatedAt: number;
}

/** Serialised ledger shape, keyed by ruleId. */
export type StoredDurationLedger = Record<string, DurationLedgerEntry>;

export class InMemoryDurationLedger implements DurationLedger {
  readonly #ledger = new Map<string, DurationLedgerEntry>();

  /**
   * Decayed spend for `key` as of `now`.
   *
   * `spent * 2^(-elapsed / halfLife)` — after one half-life, half of what was
   * spent has been forgiven.
   */
  spentMs(key: string, halfLifeMs: number, now: number): number {
    const entry = this.#ledger.get(key);
    if (entry === undefined) return 0;

    // Clock skew: a backwards jump would make `elapsed` negative and the
    // exponent positive, INFLATING recorded spend. Clamp to zero — a stalled
    // clock must never invent budget consumption, and it must never refund it
    // either (that direction is handled by the exponent being <= 0).
    const elapsed = Math.max(0, now - entry.updatedAt);

    // A non-positive or non-finite half-life cannot arrive from a validated
    // policy file (the schema requires positive), but a library caller could
    // pass one. Treat it as "no decay" — fail closed, never as instant refill.
    if (!Number.isFinite(halfLifeMs) || halfLifeMs <= 0) return entry.spentMs;

    return entry.spentMs * Math.pow(2, -elapsed / halfLifeMs);
  }

  /** Remaining grantable milliseconds under `capMs`. Never negative. */
  headroomMs(key: string, capMs: number, halfLifeMs: number, now: number): number {
    return Math.max(0, capMs - this.spentMs(key, halfLifeMs, now));
  }

  /**
   * Record `grantedMs` against `key`.
   *
   * Decays first, then adds, then stamps `now` — so the stored value is always
   * "spend as of updatedAt" and decay is never applied twice to the same
   * interval.
   */
  accrue(key: string, grantedMs: number, halfLifeMs: number, now: number): void {
    const decayed = this.spentMs(key, halfLifeMs, now);
    this.#ledger.set(key, { spentMs: decayed + Math.max(0, grantedMs), updatedAt: now });
  }

  /** Snapshot for persistence. */
  toJSON(): StoredDurationLedger {
    const out: StoredDurationLedger = {};
    for (const [key, entry] of this.#ledger.entries()) {
      out[key] = { spentMs: entry.spentMs, updatedAt: entry.updatedAt };
    }
    return out;
  }

  /**
   * Rebuild from a persisted snapshot.
   *
   * Malformed entries are skipped rather than throwing: this state is an
   * accounting record, not evidence, and a corrupt entry should not take the
   * broker down. Skipping forgives spend (the key restarts at zero), which is
   * the permissive direction — but the alternative, inventing a spend figure,
   * would silently deny work on numbers nobody wrote.
   */
  static fromJSON(data: unknown): InMemoryDurationLedger {
    const ledger = new InMemoryDurationLedger();
    if (typeof data !== 'object' || data === null) return ledger;
    for (const [key, raw] of Object.entries(data as Record<string, unknown>)) {
      if (typeof raw !== 'object' || raw === null) continue;
      const { spentMs, updatedAt } = raw as Partial<DurationLedgerEntry>;
      if (typeof spentMs !== 'number' || !Number.isFinite(spentMs) || spentMs < 0) continue;
      if (typeof updatedAt !== 'number' || !Number.isFinite(updatedAt)) continue;
      ledger.#ledger.set(key, { spentMs, updatedAt });
    }
    return ledger;
  }
}

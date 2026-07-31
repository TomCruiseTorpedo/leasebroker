/**
 * LeaseEnforcer — implements the Enforcer contract (ADR-B).
 *
 * Evaluation order (deny on first failure):
 *   1. Verify token signature (Signer)
 *   2. Check not expired
 *   3. Check not revoked (RevocationList)
 *   4. Check action is within scope (path globs / endpoint allow-list)
 *   5. Charge or reserve spend (SpendLedger) — only for spend actions
 *
 * Depends on the audit lane's InMemorySpendLedger (concrete) to call
 * setCap lazily when a spend-capable lease is first encountered.  The
 * enforce lane explicitly depends on the audit lane (see plan.md module map).
 *
 * ---------------------------------------------------------------------------
 * TWO ENTRY POINTS, BECAUSE ENFORCEMENT RUNS BEFORE THE WORK IT AUTHORISES
 * ---------------------------------------------------------------------------
 *
 * Step 5 happens BEFORE the caller performs the action — that is what an
 * in-path enforcement point is. So a spend charged in step 5 is charged for
 * work that has not happened yet, and used to stay charged when the work then
 * failed. See `audit/spend-ledger.ts` for the full account of that hole.
 *
 *   `check`            charges immediately and irreversibly.
 *   `checkAndReserve`  places a hold the caller must `settle` or `release`.
 *
 * Which one is correct depends on ONE property of the caller: can it observe
 * whether the authorized work actually landed?
 *
 *   - `LeasebrokerProxy` owns the downstream call and sees its outcome, so it
 *     uses `checkAndReserve` and resolves the hold either way.
 *   - `a2a/gate.ts` returns an `allow` verdict and the work happens somewhere
 *     it never sees, so it uses `check`. Handing it a reservation would mean
 *     placing holds nobody ever settles — every one of which the TTL would
 *     eventually hand back, turning real spend into free spend. Charging up
 *     front is the fail-closed choice for a caller that cannot report back.
 *
 * `check` is therefore not a legacy path to migrate away from. It is the
 * correct behaviour for callers outside the settle protocol, and it is what an
 * `Enforcer` implementation that omits the optional methods falls back to.
 */

import { minimatch } from 'minimatch';
import type {
  Action,
  Enforcer,
  Lease,
  RevocationList,
  SettleOutcome,
  Signer,
  VerifyResult,
} from '../contract/index.js';
import { canonicalizePath } from '../contract/index.js';
import type { InMemorySpendLedger } from '../audit/index.js';

// ---------------------------------------------------------------------------
// LeaseEnforcer
// ---------------------------------------------------------------------------

export class LeaseEnforcer implements Enforcer {
  /**
   * Set of leaseIds whose spend caps have already been registered with the
   * ledger.  Caps are registered lazily on the first spend-action check.
   */
  private readonly registeredCaps = new Set<string>();

  constructor(
    private readonly signer: Signer,
    private readonly revocationList: RevocationList,
    private readonly spendLedger: InMemorySpendLedger,
  ) {}

  /**
   * Check whether the presented token authorises the given action, charging
   * any spend immediately and irreversibly.
   *
   * For callers that own the downstream call and can report its outcome, use
   * `checkAndReserve` instead — see the header note.
   *
   * @returns `{ ok: true }` if permitted, `{ ok: false, reason }` if denied.
   */
  check(token: string, action: Action): VerifyResult {
    return this.evaluate(token, action, undefined);
  }

  /**
   * As `check`, but spend is held rather than charged.
   *
   * The held amount counts against the cap from this moment, so authorizing
   * work consumes headroom before the work happens — a downstream that never
   * reports back cannot buy capacity by staying silent, it can only freeze its
   * own. The caller MUST resolve the hold:
   *
   *   - `settle(reservationId, now)` once the work has landed;
   *   - `release(reservationId)` when it demonstrably has not.
   *
   * A hold that is never resolved lapses after the ledger's TTL, which returns
   * the headroom but NOT the obligation: a late settle still charges.
   *
   * @returns `{ ok: true, reservationId }` when the action is a spend,
   *   `{ ok: true }` when it is not (nothing to reserve), else
   *   `{ ok: false, reason }`.
   */
  checkAndReserve(token: string, action: Action, nowMs: number): VerifyResult {
    return this.evaluate(token, action, nowMs);
  }

  /** Convert a reservation from `checkAndReserve` into settled spend. */
  settle(reservationId: string, nowMs: number): SettleOutcome {
    return this.spendLedger.settle(reservationId, nowMs);
  }

  /** Hand a reservation's headroom back without charging it. */
  release(reservationId: string): void {
    this.spendLedger.release(reservationId);
  }

  /**
   * The shared ADR-B pipeline.
   *
   * `nowMs` is the mode switch, deliberately: it is the one input a reserving
   * check needs and an immediate charge does not, so the two cannot be
   * configured into disagreement.
   */
  private evaluate(token: string, action: Action, nowMs: number | undefined): VerifyResult {
    // ── Step 1: Verify signature ───────────────────────────────────────────
    const verifyResult = this.signer.verify(token);
    if (!('lease' in verifyResult)) {
      return verifyResult; // already { ok: false, reason }
    }
    const { lease } = verifyResult;

    // ── Step 2: Check not expired ──────────────────────────────────────────
    if (new Date() >= new Date(lease.expiresAt)) {
      return { ok: false, reason: 'lease has expired' };
    }

    // ── Step 3: Check not revoked ──────────────────────────────────────────
    if (this.revocationList.isRevoked(lease.id)) {
      return { ok: false, reason: 'lease has been revoked' };
    }

    // ── Step 4: Scope check ────────────────────────────────────────────────
    const scopeResult = checkScope(lease, action);
    if (!scopeResult.ok) {
      return scopeResult;
    }

    // ── Step 5: Spend charge or hold (spend actions only) ──────────────────
    if (action.kind === 'spend') {
      // Register cap lazily on first encounter of this lease.
      if (!this.registeredCaps.has(lease.id)) {
        for (const cap of lease.capabilities) {
          if (cap.kind === 'spend') {
            this.spendLedger.setCap(lease.id, cap.capMinor);
            break;
          }
        }
        this.registeredCaps.add(lease.id);
      }

      if (nowMs === undefined) {
        const accrued = this.spendLedger.accrue(lease.id, action.amountMinor);
        if (!accrued) {
          return { ok: false, reason: 'spend cap exceeded' };
        }
        return { ok: true };
      }

      const reservationId = this.spendLedger.reserve(lease.id, action.amountMinor, nowMs);
      if (reservationId === undefined) {
        return { ok: false, reason: 'spend cap exceeded' };
      }
      return { ok: true, reservationId };
    }

    return { ok: true };
  }
}

// ---------------------------------------------------------------------------
// Scope-check helper (module-private)
// ---------------------------------------------------------------------------

/**
 * Check whether `action` is covered by any capability in the lease.
 *
 * Matching rules:
 *   - fs.read / fs.write : action.path must match at least one glob in cap.paths
 *   - http.call          : action.endpoint must match at least one pattern in cap.endpoints
 *   - spend              : cap.currency must equal action.currency (amount is checked by SpendLedger)
 *
 * Deny-by-default: no matching capability → denied.
 */
function checkScope(lease: Lease, action: Action): VerifyResult {
  for (const cap of lease.capabilities) {
    if (cap.kind !== action.kind) continue;

    if (action.kind === 'fs.read' && cap.kind === 'fs.read') {
      // An Action arrives at RUNTIME and never passes through a Zod schema, so
      // it is canonicalized here with the same normalizer the request schema
      // and the policy engine use. BOTH sides of the comparison must be
      // canonical: normalizing only one turns an agreement into a mismatch (a
      // lease scoped to 'data/**' would stop matching './data/file.txt').
      // canonicalizePath is idempotent, so re-normalizing costs nothing.
      const requested = canonicalizePath(action.path);
      if (cap.paths.some((p) => minimatch(requested, canonicalizePath(p)))) return { ok: true };
    } else if (action.kind === 'fs.write' && cap.kind === 'fs.write') {
      const requested = canonicalizePath(action.path);
      if (cap.paths.some((p) => minimatch(requested, canonicalizePath(p)))) return { ok: true };
    } else if (action.kind === 'http.call' && cap.kind === 'http.call') {
      // Endpoints are URLs and are deliberately NOT run through a filesystem
      // path normalizer — see the note in contract/schemas.ts.
      if (cap.endpoints.some((e) => minimatch(action.endpoint, e))) return { ok: true };
    } else if (action.kind === 'spend' && cap.kind === 'spend') {
      if (cap.currency === action.currency) return { ok: true };
    }
  }

  return {
    ok: false,
    reason: `action '${action.kind}' is not permitted by the lease scope`,
  };
}

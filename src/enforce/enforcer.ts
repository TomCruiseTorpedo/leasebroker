/**
 * LeaseEnforcer — implements the Enforcer contract (ADR-B).
 *
 * Evaluation order (deny on first failure):
 *   1. Verify token signature (Signer)
 *   2. Check not expired
 *   3. Check not revoked (RevocationList)
 *   4. Check action is within scope (path globs / endpoint allow-list)
 *   5. Accrue spend (SpendLedger) — only for spend actions
 *
 * Depends on the audit lane's InMemorySpendLedger (concrete) to call
 * setCap lazily when a spend-capable lease is first encountered.  The
 * enforce lane explicitly depends on the audit lane (see plan.md module map).
 */

import { minimatch } from 'minimatch';
import type {
  Action,
  Enforcer,
  Lease,
  RevocationList,
  Signer,
  VerifyResult,
} from '../contract/index.js';
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
   * Check whether the presented token authorises the given action.
   *
   * @returns `{ ok: true }` if permitted, `{ ok: false, reason }` if denied.
   */
  check(token: string, action: Action): VerifyResult {
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

    // ── Step 5: Spend accrual (spend actions only) ─────────────────────────
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

      const accrued = this.spendLedger.accrue(lease.id, action.amountMinor);
      if (!accrued) {
        return { ok: false, reason: 'spend cap exceeded' };
      }
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
      if (cap.paths.some((p) => minimatch(action.path, p))) return { ok: true };
    } else if (action.kind === 'fs.write' && cap.kind === 'fs.write') {
      if (cap.paths.some((p) => minimatch(action.path, p))) return { ok: true };
    } else if (action.kind === 'http.call' && cap.kind === 'http.call') {
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

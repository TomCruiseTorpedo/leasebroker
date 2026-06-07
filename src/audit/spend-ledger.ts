/**
 * In-memory spend ledger.
 *
 * Implements the SpendLedger interface from src/contract.
 *
 * Tracks cumulative spend per lease against a registered cap.
 *
 * Design notes:
 * - The spend cap lives in the lease (SpendCapability.capMinor) and is immutable
 *   after issuance. The ledger is the mutable counterpart that tracks accrued spend.
 * - `setCap` (a concrete-class-only method) is called by the broker when a lease
 *   bearing a spend capability is issued. It registers the cap so that `accrue`
 *   can enforce it.
 * - `accrue` is atomic: the cap check and the write happen together, so concurrent
 *   callers cannot both pass a check that a sequential view would fail.
 * - Money is always in integer minor units (e.g. cents). No float arithmetic.
 * - "At-cap" accruals are permitted: spending exactly to the cap returns true.
 *   Only spending *beyond* the cap returns false.
 */

import type { SpendLedger } from '../contract/index.js';

interface LedgerEntry {
  spent: number;
  cap: number;
}

export class InMemorySpendLedger implements SpendLedger {
  private readonly ledger = new Map<string, LedgerEntry>();

  /**
   * Register the spend cap for a lease.
   *
   * Must be called before the first `accrue` for this leaseId.
   * This method is NOT part of the SpendLedger interface — it is called by the
   * broker when issuing a lease that includes a `spend` capability.
   *
   * If called again for an existing leaseId, the cap is updated (allows re-issuance).
   */
  setCap(leaseId: string, capMinor: number): void {
    const existing = this.ledger.get(leaseId);
    if (existing !== undefined) {
      existing.cap = capMinor;
    } else {
      this.ledger.set(leaseId, { spent: 0, cap: capMinor });
    }
  }

  /**
   * Attempt to accrue `amountMinor` against the lease's spend cap.
   *
   * @returns `true` if the accrual is within the cap (at-cap is allowed) and was recorded.
   * @returns `false` if accruing would breach the cap — the amount is NOT recorded.
   * @throws {Error} if no cap has been registered for this leaseId via `setCap`.
   */
  accrue(leaseId: string, amountMinor: number): boolean {
    const entry = this.ledger.get(leaseId);
    if (entry === undefined) {
      throw new Error(
        `SpendLedger: no cap registered for lease "${leaseId}". ` +
          `Call setCap(leaseId, capMinor) when the lease is issued.`,
      );
    }
    if (entry.spent + amountMinor > entry.cap) {
      // Would exceed the cap — deny and leave spent unchanged.
      return false;
    }
    // At-cap or below — accrue and allow.
    entry.spent += amountMinor;
    return true;
  }

  /**
   * Return the total amount accrued against this lease in integer minor units.
   * Returns 0 for unknown leaseIds.
   */
  spent(leaseId: string): number {
    return this.ledger.get(leaseId)?.spent ?? 0;
  }
}

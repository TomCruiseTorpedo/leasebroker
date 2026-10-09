/**
 * In-memory spend ledger.
 *
 * Implements the SpendLedger interface from src/contract.
 *
 * Tracks cumulative spend per lease against a registered cap.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE ARE TWO WAYS TO SPEND, AND WHICH ONE YOU WANT
 * ---------------------------------------------------------------------------
 *
 * THE HOLE THIS CLOSES. Enforcement runs BEFORE the work it authorises. The
 * enforcer checked the cap and charged in the same step, then the proxy made
 * the downstream call — so a call that timed out, threw, or was refused had
 * already consumed the caller's cap, permanently, with no way to give it back.
 * This ledger is the ONLY spend control in the system, so an unreliable
 * downstream silently ratcheted a caller to zero and the lease became unusable
 * without anything having been spent.
 *
 * `reserve` → `settle` / `release` is the fix. `reserve` takes the headroom at
 * authorize time; `settle` converts it to spend once the work has landed;
 * `release` hands it back when the work demonstrably did not.
 *
 * WHY NOT SIMPLY CHARGE ON SUCCESS. The obvious fix — leave the cap untouched
 * until the call reports success — is a trust inversion: the party being
 * metered decides when it gets metered, so anything that never reports success
 * is never billed and unlimited authorized work costs nothing. Reserving at
 * authorize time is what keeps the money failing closed: headroom is consumed
 * BEFORE the work is allowed to happen, and the cap bounds work in flight
 * whatever the downstream subsequently says or withholds.
 *
 * THE TTL RELEASES THE HOLD, NOT THE OBLIGATION. A reservation stops counting
 * against headroom once `holdTtlMs` has passed, so a downstream that never
 * answers cannot freeze a caller's budget forever. It is NOT deleted: a late
 * `settle` still charges. Deleting on lapse would rebuild the hole one layer
 * down — stall past the TTL, then succeed, and the charge would have nowhere to
 * land. Lapsed-then-settled is reported distinctly (`settled-after-lapse`)
 * because it is the one case that can push `spent` past `cap`: the headroom was
 * handed back and may have been re-lent in the meantime. Recording the
 * overshoot is the honest option — dropping the charge is free work, and
 * clamping it understates a bill that was really incurred. Subsequent reserves
 * then fail, which is the correct direction to fail in.
 *
 * RESERVE-THEN-SETTLE IS NOT ATOMIC, AND IS NOT PRETENDING TO BE. Two writes
 * separated by a network call cannot be a transaction. What IS guaranteed is
 * ordering and direction: the reserve lands before the work is authorized, and
 * every non-atomic window resolves toward charging rather than toward free
 * work. What is NOT guaranteed: a process that dies mid-call loses its
 * in-flight reservations (deliberately not persisted — `cli/state.ts`
 * serialises `spent`/`cap` only, because a reservation whose settler no longer
 * exists would freeze headroom forever), so spend that really happened can be
 * under-recorded across a restart.
 *
 * WHAT `accrue` IS NOW. The original one-shot charge, kept because it is part
 * of the published `SpendLedger` interface and because callers that own no
 * downstream call have nothing to settle. It charges immediately and
 * irreversibly, which is the right default for a caller that does not
 * participate in the settle protocol: such a caller fails closed rather than
 * reserving something nobody will ever settle.
 *
 * Design notes:
 * - The spend cap lives in the lease (SpendCapability.capMinor) and is immutable
 *   after issuance. The ledger is the mutable counterpart that tracks accrued spend.
 * - `setCap` (a concrete-class-only method) is called by the broker when a lease
 *   bearing a spend capability is issued. It registers the cap so that `accrue`
 *   and `reserve` can enforce it.
 * - `accrue` and `reserve` are each atomic in themselves: the cap check and the
 *   write happen together, so concurrent callers cannot both pass a check that a
 *   sequential view would fail.
 * - Money is always in integer minor units (e.g. cents). No float arithmetic.
 * - "At-cap" accruals are permitted: spending exactly to the cap returns true.
 *   Only spending *beyond* the cap returns false.
 * - `now` is a parameter rather than read internally, so TTL behaviour is
 *   testable without waiting for wall-clock time to pass (same convention as
 *   `audit/duration-ledger.ts`).
 */

import type { SettleOutcome, SpendLedger } from '../contract/index.js';

export type { SettleOutcome };

interface LedgerEntry {
  spent: number;
  cap: number;
}

/** An amount held against a cap, awaiting settle or release. */
interface Reservation {
  leaseId: string;
  amountMinor: number;
  /**
   * Epoch ms after which this reservation stops counting against headroom.
   * The obligation survives: a `settle` after this instant still charges.
   */
  lapsesAtMs: number;
  /** Optional caller-supplied idempotency key — see `reserve`. */
  key?: string;
}

/** How long a reservation holds headroom before it lapses. */
export const DEFAULT_HOLD_TTL_MS = 300_000; // 5 minutes

export class InMemorySpendLedger implements SpendLedger {
  /**
   * NOTE: this field is read by name through a cast in `cli/state.ts`
   * (`saveSpendLedger` / `loadSpendLedger`). Renaming it — including to a `#`
   * private — breaks persistence at runtime rather than at compile time.
   */
  private readonly ledger = new Map<string, LedgerEntry>();

  /** Live reservations by id. Deliberately not persisted. */
  private readonly reservations = new Map<string, Reservation>();

  private reservationCounter = 0;

  constructor(private readonly holdTtlMs: number = DEFAULT_HOLD_TTL_MS) {}

  /**
   * Register the spend cap for a lease.
   *
   * Must be called before the first `accrue` or `reserve` for this leaseId.
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
   * Charge `amountMinor` immediately and irreversibly.
   *
   * Prefer `reserve`/`settle`/`release` when the caller owns a downstream call
   * that can fail — that is what gives the amount a way back. Use this when
   * there is nothing to settle: the charge is final the moment it returns true.
   *
   * Outstanding holds count against the cap here too, so an immediate charge
   * cannot spend headroom another in-flight call has already reserved.
   *
   * @param nowMs Epoch ms, used only to tell live holds from lapsed ones.
   *   Optional so the published `SpendLedger` signature is unchanged, but pass
   *   it whenever `reserve` is being called with synthetic timestamps: reading
   *   the wall clock here while holds were placed on a test clock makes every
   *   hold look lapsed, and this method would silently stop respecting them.
   * @returns `true` if the charge is within the cap (at-cap is allowed) and was recorded.
   * @returns `false` if charging would breach the cap — the amount is NOT recorded.
   * @throws {Error} if no cap has been registered for this leaseId via `setCap`.
   */
  accrue(leaseId: string, amountMinor: number, nowMs: number = Date.now()): boolean {
    const entry = this.requireEntry(leaseId);
    if (this.wouldBreachCap(entry, leaseId, amountMinor, nowMs)) {
      // Would exceed the cap — deny and leave spent unchanged.
      return false;
    }
    // At-cap or below — accrue and allow.
    entry.spent += amountMinor;
    return true;
  }

  /**
   * Hold `amountMinor` against the lease's cap, pending settle or release.
   *
   * The held amount counts against the cap from this moment, so the cap bounds
   * authorized-but-unsettled work, not merely completed work.
   *
   * @param key Optional idempotency key. If a LIVE reservation already carries
   *   this key, its id is returned instead of a second hold being taken — so a
   *   retry that re-enters while the first attempt is still in flight does not
   *   double-hold. This is the seam for the proxy-owned request correlator that
   *   MCP revision 2026-07-28 Multi Round-Trip retries need (migration decision
   *   D3); it is NOT that correlator. It does not dedupe a retry arriving after
   *   the first attempt settled, because the reservation is gone by then.
   *   Closing that needs a memo of settled keys, which is D3's to add — the
   *   parameter and the stored `key` are here so it lands as an extension
   *   rather than a rewrite.
   *
   * @returns The reservation id, or `undefined` if the hold would breach the cap.
   * @throws {Error} if no cap has been registered for this leaseId via `setCap`.
   */
  reserve(
    leaseId: string,
    amountMinor: number,
    nowMs: number,
    key?: string,
  ): string | undefined {
    const entry = this.requireEntry(leaseId);

    if (key !== undefined) {
      for (const [id, existing] of this.reservations) {
        if (existing.key === key && existing.leaseId === leaseId) return id;
      }
    }

    if (this.wouldBreachCap(entry, leaseId, amountMinor, nowMs)) return undefined;

    this.reservationCounter += 1;
    const id = `${leaseId}#${this.reservationCounter}`;
    this.reservations.set(id, {
      leaseId,
      amountMinor,
      lapsesAtMs: nowMs + this.holdTtlMs,
      ...(key !== undefined ? { key } : {}),
    });
    return id;
  }

  /**
   * Convert a reservation into settled spend.
   *
   * Charges whether or not the hold has lapsed — a lapsed hold means the
   * headroom went back, not that the obligation went away. See the header note
   * on why a lapse must not delete the reservation.
   */
  settle(reservationId: string, nowMs: number): SettleOutcome {
    const reservation = this.reservations.get(reservationId);
    if (reservation === undefined) return 'unknown';

    const entry = this.ledger.get(reservation.leaseId);
    if (entry === undefined) return 'unknown';

    this.reservations.delete(reservationId);
    entry.spent += reservation.amountMinor;
    return nowMs >= reservation.lapsesAtMs ? 'settled-after-lapse' : 'settled';
  }

  /**
   * Hand a reservation's headroom back without charging.
   *
   * @returns `true` if a reservation was released, `false` if the id was
   *   unknown (already settled, already released, or never existed).
   */
  release(reservationId: string): boolean {
    return this.reservations.delete(reservationId);
  }

  /**
   * Total currently held against this lease — reservations that are neither
   * settled nor released nor lapsed. Lapsed holds are excluded because they no
   * longer occupy headroom, even though they can still be settled.
   */
  reserved(leaseId: string, nowMs: number): number {
    let held = 0;
    for (const reservation of this.reservations.values()) {
      if (reservation.leaseId === leaseId && nowMs < reservation.lapsesAtMs) {
        held += reservation.amountMinor;
      }
    }
    return held;
  }

  /**
   * Return the total SETTLED spend against this lease in integer minor units.
   * Reserved-but-unsettled amounts are NOT included — this is what the caller
   * has actually been billed, not what is currently held.
   * Returns 0 for unknown leaseIds.
   */
  spent(leaseId: string): number {
    return this.ledger.get(leaseId)?.spent ?? 0;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private requireEntry(leaseId: string): LedgerEntry {
    const entry = this.ledger.get(leaseId);
    if (entry === undefined) {
      throw new Error(
        `SpendLedger: no cap registered for lease "${leaseId}". ` +
          `Call setCap(leaseId, capMinor) when the lease is issued.`,
      );
    }
    return entry;
  }

  /** Settled spend plus live holds plus the proposed amount, against the cap. */
  private wouldBreachCap(
    entry: LedgerEntry,
    leaseId: string,
    amountMinor: number,
    nowMs: number,
  ): boolean {
    return entry.spent + this.reserved(leaseId, nowMs) + amountMinor > entry.cap;
  }
}

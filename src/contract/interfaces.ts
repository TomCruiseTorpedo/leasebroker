/**
 * Interfaces for the leasebroker contract.
 *
 * Consumers depend on these interfaces, not on implementations.
 * This makes the implementations swappable without touching consumers (ADR-A/C/D).
 *
 * No runtime logic here — interfaces only.
 */

import type {
  Action,
  AuditEvent,
  Decision,
  Lease,
  LeaseRequest,
  SettleOutcome,
  VerifyResult,
} from './types.js';

// ---------------------------------------------------------------------------
// Signer (ADR-A)
// ---------------------------------------------------------------------------

/**
 * Signs leases into tokens and verifies tokens back into leases.
 *
 * The canonical implementation uses PASETO v4.public (Ed25519) on @noble/ed25519.
 * The `Signer` interface keeps that choice behind a seam — a future swap is
 * non-breaking for all consumers.
 */
export interface Signer {
  /**
   * Issue a PASETO v4.public token encoding the given lease.
   * @returns The signed token string (wire form of the lease).
   */
  issue(lease: Lease): string;

  /**
   * Verify a token and decode the lease it carries.
   * @returns `{ lease }` on success, or a `VerifyResult` with `ok: false` on failure.
   *
   * Note: this checks only cryptographic integrity and decoding.
   * Expiry and revocation are checked separately by the Enforcer.
   */
  verify(token: string): { lease: Lease } | VerifyResult;
}

// ---------------------------------------------------------------------------
// PolicyEngine (ADR-C)
// ---------------------------------------------------------------------------

/**
 * Evaluates a lease request against policy and returns a decision.
 *
 * The canonical v1 implementation uses declarative allow-rules.
 * The interface leaves a seam for a Cedar-backed engine to drop in later.
 * Deny-by-default: no matching allow-rule → deny.
 */
export interface PolicyEngine {
  /**
   * Evaluate the request and return exactly one decision.
   */
  evaluate(request: LeaseRequest): Decision;
}

// ---------------------------------------------------------------------------
// AuditSink
// ---------------------------------------------------------------------------

/**
 * Append-only, hash-chained audit log.
 *
 * Every event carries `prevHash` and `hash` forming a tamper-evident chain.
 * Implementors MUST NOT allow deletion or modification of existing events.
 */
export interface AuditSink {
  /**
   * Append a new event to the log.
   * The implementation is responsible for setting `prevHash` and `hash`
   * if they are not already set by the caller.
   */
  append(event: AuditEvent): void;

  /** Read all events in append order. */
  read(): AuditEvent[];
}

// ---------------------------------------------------------------------------
// PendingStore (ADR-D)
// ---------------------------------------------------------------------------

/**
 * Storage for veto-required requests awaiting human approval.
 *
 * A request sits in the PendingStore until the operator calls
 * `leasebroker approve <reqId>` or `leasebroker deny <reqId>`.
 */
export interface PendingStore {
  /** Persist a pending request awaiting human approval. */
  put(reqId: string, request: LeaseRequest): void;

  /** Retrieve a pending request by ID. Returns undefined if not found. */
  get(reqId: string): LeaseRequest | undefined;

  /** List all pending requests. */
  list(): Array<{ reqId: string; request: LeaseRequest }>;

  /**
   * Resolve a pending request.
   * The caller (broker) is responsible for issuing a lease on 'approve'
   * and recording the denial on 'deny'. The PendingStore simply removes
   * the entry after resolution.
   */
  resolve(reqId: string, decision: 'approve' | 'deny'): void;
}

// ---------------------------------------------------------------------------
// RevocationList (ADR-D)
// ---------------------------------------------------------------------------

/**
 * Tracks revoked leases.
 * Enforcement points check `isRevoked` before permitting any action.
 */
export interface RevocationList {
  /** Revoke an active lease by ID. */
  revoke(leaseId: string): void;

  /** Returns true if the lease has been revoked. */
  isRevoked(leaseId: string): boolean;
}

// ---------------------------------------------------------------------------
// SpendLedger (ADR-B)
// ---------------------------------------------------------------------------

/**
 * Tracks cumulative spend per lease.
 *
 * Spend is NOT stored in the lease (which is immutable after issuance).
 * The lease carries the cap; the SpendLedger tracks accrued spend.
 * Money is always in integer minor units — no float arithmetic.
 *
 * This interface is the IMMEDIATE-CHARGE surface. The two-phase surface
 * (`reserve` → `settle`/`release`, which is what gives a failed downstream call
 * its money back) lives on the concrete `InMemorySpendLedger`, alongside the
 * reasoning for the split. Enforcement points already depend on the concrete
 * class, so the two-phase methods are deliberately not required here: an
 * external implementor that only provides `accrue` keeps working and keeps
 * failing closed.
 */
export interface SpendLedger {
  /**
   * Attempt to accrue `amountMinor` against the lease's spend cap.
   *
   * The charge is IRREVERSIBLE. If the caller owns a downstream call that can
   * fail, prefer the concrete ledger's `reserve`/`settle`/`release`.
   *
   * @param nowMs Epoch ms, used only to tell live spend reservations from
   *   lapsed ones. Defaults to the wall clock.
   * @returns `true` if the accrual is within the cap and was recorded.
   * @returns `false` if accruing would breach the cap (action must be denied).
   */
  accrue(leaseId: string, amountMinor: number, nowMs?: number): boolean;

  /**
   * Return the total SETTLED spend against this lease in minor units.
   * Amounts merely reserved are not included.
   */
  spent(leaseId: string): number;
}

// ---------------------------------------------------------------------------
// DurationLedger
// ---------------------------------------------------------------------------

/**
 * Tracks total GRANTED lease duration per policy rule, with exponential decay.
 *
 * Where the SpendLedger bounds what a single lease may spend, this bounds how
 * much lease time a rule may hand out in total — the control that stops an
 * agent assembling standing permission out of unlimited short renewals.
 *
 * Keyed on the matched `ruleId`, never on anything the agent reports. See
 * `audit/duration-ledger.ts` for why that key and not the granted scope.
 *
 * `now` is a parameter rather than read internally so decay is testable
 * without waiting for wall-clock time to pass.
 */
export interface DurationLedger {
  /** Decayed spend for `key` as of `now`, in milliseconds. */
  spentMs(key: string, halfLifeMs: number, now: number): number;

  /** Remaining grantable milliseconds under `capMs`. Never negative. */
  headroomMs(key: string, capMs: number, halfLifeMs: number, now: number): number;

  /** Record `grantedMs` of issued lease time against `key`. */
  accrue(key: string, grantedMs: number, halfLifeMs: number, now: number): void;
}

// ---------------------------------------------------------------------------
// Enforcer (ADR-B)
// ---------------------------------------------------------------------------

/**
 * Per-call enforcement: composes all checks into a single VerifyResult.
 *
 * Evaluation order (deny on first failure):
 *   1. Verify token signature (Signer)
 *   2. Check not expired
 *   3. Check not revoked (RevocationList)
 *   4. Check action is within scope
 *   5. Check/accrue spend (SpendLedger) — for spend capabilities
 */
/**
 * The verdict from `Enforcer.check`, plus the lease the verdict was reached
 * against.
 *
 * `lease` is present whenever the token's SIGNATURE validated — including on
 * denials from expiry, revocation, scope or spend, where the token was genuine
 * and simply did not authorize this call. It is absent only when there was
 * nothing trustworthy to report: the signature failed, or the token did not
 * decode.
 *
 * It is returned because the enforcer has already verified and decoded the
 * lease, and a caller that needs signature-backed attribution for the audit
 * trail would otherwise have to either repeat the verification or read the
 * token's claims without checking them. The second option is the dangerous one:
 * an audit record naming a lease id lifted from an unverified token reads as
 * authoritative while asserting something no signature backs, and the hash
 * chain seals it just as faithfully as a true one.
 */
export type EnforceResult =
  | {
      ok: true;
      reason?: string;
      /**
       * REQUIRED on the permitted path. An enforcer only permits a call after
       * verifying the token's signature, so at that point the lease is in hand
       * and there is no honest reason to withhold it. Requiring it here is what
       * lets a caller emit a `use` event — which the audit contract will not let
       * it state without a lease id — with no defensive runtime check.
       */
      lease: Lease;
      /**
       * Set when the check placed a spend RESERVATION the caller is obliged to
       * resolve — `Enforcer.settle` once the authorized work has landed, or
       * `Enforcer.release` when it demonstrably has not. Present only from
       * `Enforcer.checkAndReserve`; `check` charges immediately and never sets it.
       */
      reservationId?: string;
    }
  | {
      ok: false;
      reason?: string;
      /** Present unless the signature failed or the token did not decode. */
      lease?: Lease;
      /**
       * Never set on a denial: nothing was reserved. Declared (as `undefined`)
       * so the field reads off the whole union without a narrowing step, as it
       * did when this verdict was the flat `VerifyResult`.
       */
      reservationId?: undefined;
    };

export interface Enforcer {
  /**
   * Check whether the presented token authorises the given action.
   *
   * Spend is charged IMMEDIATELY and IRREVERSIBLY here. That is deliberate for
   * callers that do not own the downstream call and so have nothing to settle
   * (`a2a/gate.ts` is one): they fail closed rather than placing a hold nobody
   * will ever resolve. A caller that DOES own the downstream call — and can
   * therefore tell whether the work landed — should use `checkAndReserve`.
   *
   * @returns `{ ok: true, lease }` if permitted, or `{ ok: false, reason }` if
   *          denied — carrying `lease` too whenever the signature validated.
   */
  check(token: string, action: Action): EnforceResult;

  /**
   * As `check`, but spend is RESERVED rather than charged: the amount counts
   * against the cap immediately, and the caller must resolve it with `settle`
   * (the work landed) or `release` (it did not).
   *
   * Optional so that adding it is not a breaking change for existing
   * implementors. Callers must fall back to `check` when it is absent — the
   * fallback charges immediately, which is the safe direction.
   *
   * @param nowMs Epoch ms, passed in rather than read internally so hold expiry
   *   is testable without waiting for wall-clock time.
   * @returns `{ ok: true, lease, reservationId }` if permitted, else `{ ok: false, reason }`
    *   (carrying `lease` too whenever the signature validated).
   */
  checkAndReserve?(token: string, action: Action, nowMs: number): EnforceResult;

  /** Convert a reservation from `checkAndReserve` into settled spend. */
  settle?(reservationId: string, nowMs: number): SettleOutcome;

  /** Hand a reservation's headroom back without charging it. */
  release?(reservationId: string): void;
}

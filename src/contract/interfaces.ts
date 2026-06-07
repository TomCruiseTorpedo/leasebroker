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
 */
export interface SpendLedger {
  /**
   * Attempt to accrue `amountMinor` against the lease's spend cap.
   * @returns `true` if the accrual is within the cap and was recorded.
   * @returns `false` if accruing would breach the cap (action must be denied).
   */
  accrue(leaseId: string, amountMinor: number): boolean;

  /** Return the total amount accrued against this lease in minor units. */
  spent(leaseId: string): number;
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
export interface Enforcer {
  /**
   * Check whether the presented token authorises the given action.
   * @returns `{ ok: true }` if permitted, or `{ ok: false, reason }` if denied.
   */
  check(token: string, action: Action): VerifyResult;
}

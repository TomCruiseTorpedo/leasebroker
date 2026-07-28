/**
 * Broker — issuance orchestration (policy + sign + audit + veto).
 *
 * Orchestrates the lease issuance lifecycle:
 *   1. Validate incoming LeaseRequest via zod (trust-boundary enforcement)
 *   2. Audit the incoming request
 *   3. Evaluate policy (PolicyEngine.evaluate)
 *   4. Audit the decision
 *   5a. grant   → issue lease via Signer.issue, audit issuance, return token
 *   5b. veto-required → PendingStore.put (NO lease issued), return pending reqId
 *   5c. deny    → audit denial, return denial reason
 *
 * approve(reqId) retrieves the pending request and issues under normal grant rules.
 * deny(reqId) removes from pending and audits the denial; no lease is issued.
 *
 * Design constraints (from the attached args and plan):
 * - Depends on contract INTERFACES via constructor injection; never on concrete classes.
 * - Issued scope is always a subset of (or equal to) the requested scope.
 * - The `kid` for issued leases is a constructor parameter; it must match the
 *   Signer's active signing key so verification succeeds.
 */

import { randomUUID } from 'node:crypto';

import type {
  AuditSink,
  Decision,
  DurationLedger,
  Lease,
  LeaseRequest,
  PolicyEngine,
  PendingStore,
  Signer,
} from '../contract/index.js';
import { LeaseRequestSchema } from '../contract/index.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** A lease was successfully issued. */
export type GrantedResult = {
  type: 'granted';
  /** PASETO v4.public token — the wire form of the lease. */
  token: string;
  /** The issued Lease (structured claims). */
  lease: Lease;
};

/**
 * The policy required human veto approval before a lease can be issued.
 * The caller should surface `reqId` to the operator (e.g. via CLI).
 */
export type PendingResult = {
  type: 'pending';
  /** ID of the stored pending request. Use with `approve`/`deny`. */
  reqId: string;
};

/** The request was denied (no lease issued). */
export type DeniedResult = {
  type: 'denied';
  reason: string;
};

/** Union of all possible outcomes from `Broker.request` or `Broker.approve`. */
export type IssueResult = GrantedResult | PendingResult | DeniedResult;

/**
 * Shortest lease worth issuing, in milliseconds.
 *
 * Below this the budget is treated as exhausted and the request is DENIED
 * rather than clamped. Because headroom decays continuously it approaches zero
 * asymptotically and is almost never exactly zero — without a floor, an
 * exhausted budget would keep issuing sub-millisecond leases that expire
 * before they can be used. That is a denial dressed as a grant, which is worse
 * than a denial: the caller is told it succeeded and has to discover otherwise.
 *
 * One second, because a lease that cannot survive a single round trip cannot
 * be acted upon.
 */
const MIN_GRANTABLE_DURATION_MS = 1000;

// ---------------------------------------------------------------------------
// Broker
// ---------------------------------------------------------------------------

/**
 * Issuance orchestrator for the leasebroker.
 *
 * All dependencies are injected as contract interfaces — never as concrete
 * implementations — so each component is swappable without changing this class.
 */
export class Broker {
  readonly #policy: PolicyEngine;
  readonly #signer: Signer;
  readonly #audit: AuditSink;
  readonly #pending: PendingStore;
  /** Key ID embedded in every issued lease (must match the Signer's active key). */
  readonly #kid: string;
  /**
   * Bounds total granted lease time per policy rule.
   *
   * Optional for backwards compatibility — but a rule that DECLARES a budget
   * with no ledger wired is a misconfiguration, and fails closed rather than
   * letting the budget go silently unenforced. See `#issueLease`.
   */
  readonly #durationLedger: DurationLedger | undefined;

  /**
   * @param policy  Evaluates lease requests against policy rules.
   * @param signer  Signs leases into PASETO tokens and verifies them.
   * @param audit   Append-only, hash-chained audit log.
   * @param pending Storage for veto-required requests awaiting human review.
   * @param kid     Key ID for issued leases (must match the Signer's active kid).
   * @param durationLedger Optional; required by rules that declare a duration budget.
   */
  constructor(
    policy: PolicyEngine,
    signer: Signer,
    audit: AuditSink,
    pending: PendingStore,
    kid: string,
    durationLedger?: DurationLedger,
  ) {
    this.#policy = policy;
    this.#signer = signer;
    this.#audit = audit;
    this.#pending = pending;
    this.#kid = kid;
    this.#durationLedger = durationLedger;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Process a lease request.
   *
   * Validates, evaluates, and dispatches to grant / veto / deny.
   * Audit events are appended for every request and every decision.
   *
   * @returns `GrantedResult` — lease issued and token returned
   * @returns `PendingResult` — veto required; awaiting human approval
   * @returns `DeniedResult`  — request was denied by policy or validation
   */
  request(req: LeaseRequest): IssueResult {
    // 1. Validate at the trust boundary
    const parsed = LeaseRequestSchema.safeParse(req);
    if (!parsed.success) {
      return {
        type: 'denied',
        reason: `Invalid request: ${parsed.error.message}`,
      };
    }
    const validReq = parsed.data;
    const reqId = randomUUID();

    // 2. Audit the incoming request
    this.#appendRequestEvent(reqId, validReq);

    // 3. Evaluate policy
    const decision = this.#policy.evaluate(validReq);

    // 4. Audit the decision
    this.#appendDecisionEvent(reqId, decision.effect, decision.reason, decision.ruleId);

    // 5. Dispatch on effect
    if (decision.effect === 'deny') {
      return { type: 'denied', reason: decision.reason };
    }

    if (decision.effect === 'veto-required') {
      // Store for human review — NO lease is issued yet.
      this.#pending.put(reqId, validReq);
      return { type: 'pending', reqId };
    }

    // effect === 'grant': issue the lease
    return this.#issueLease(reqId, validReq, decision);
  }

  /**
   * Approve a pending (veto-required) request.
   *
   * The human operator approved the veto. The request is removed from the
   * PendingStore and a lease is issued under the same grant rules as a
   * normal approval (same scope, same duration math, same audit trail).
   *
   * @returns `GrantedResult` — lease issued
   * @returns `DeniedResult`  — reqId not found in pending
   */
  approve(reqId: string): IssueResult {
    const req = this.#pending.get(reqId);
    if (req === undefined) {
      return {
        type: 'denied',
        reason: `No pending request found for reqId "${reqId}"`,
      };
    }

    // Re-evaluate rather than issuing blind.
    //
    // Two reasons. The duration budget must bind at EVERY issuance point: if
    // approval skipped it, an agent could route around the budget entirely by
    // arranging for its requests to be veto-required. And policy may have
    // changed while the request sat in the queue — a human approving a veto is
    // approving THIS request, not overriding a rule that now forbids it.
    const decision = this.#policy.evaluate(req);

    if (decision.effect === 'deny') {
      // Consume the pending entry: it has been dealt with, just not granted.
      this.#pending.resolve(reqId, 'deny');
      this.#appendDecisionEvent(reqId, 'deny', decision.reason, decision.ruleId);
      return {
        type: 'denied',
        reason: `Policy now denies this request: ${decision.reason}`,
      };
    }

    // A 'veto-required' verdict here is expected — the human just supplied the
    // approval it was waiting for. Remove from pending before issuing, so
    // re-approval cannot double-issue.
    this.#pending.resolve(reqId, 'approve');

    return this.#issueLease(reqId, req, decision);
  }

  /**
   * Deny a pending (veto-required) request.
   *
   * Removes from pending and appends a denial audit event. No lease is issued.
   * No-op if the reqId is not found.
   */
  deny(reqId: string): void {
    const req = this.#pending.get(reqId);
    this.#pending.resolve(reqId, 'deny');

    this.#audit.append({
      type: 'denial',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        reason: 'Denied by operator',
        agentId: req?.agentId,
      },
      prevHash: '',
      hash: '',
    });
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Build and sign a lease from the approved request, then audit the issuance.
   *
   * Issued scope = the requested capabilities (a subset of or equal to what was
   * requested, which the policy has already validated against the allow-rules).
   */
  #issueLease(reqId: string, req: LeaseRequest, decision: Decision): IssueResult {
    const now = new Date();
    const nowMs = now.getTime();

    // Policy ceiling: already clamped to the tightest matched rule's
    // maxDurationMs by the engine.
    let durationMs = decision.grantedDurationMs ?? req.requestedDurationMs;

    // Budget ceiling: clamp further to the smallest headroom across EVERY
    // matched rule that carries a budget. All of them are charged, so all of
    // them must be able to afford it — otherwise bundling a capability whose
    // rule has a large allowance would dilute a tight one.
    const budgeted = (decision.matchedRules ?? []).filter(
      (r) => r.maxTotalDurationMs !== undefined,
    );

    let bindingRuleId: string | undefined;

    if (budgeted.length > 0) {
      if (this.#durationLedger === undefined) {
        // Fail closed and say why. A declared budget that goes unenforced
        // because nobody wired the ledger is exactly the silent-non-
        // enforcement this whole control exists to remove.
        const reason =
          `rule(s) ${budgeted.map((r) => r.ruleId).join(', ')} declare a duration budget ` +
          `but no DurationLedger is wired into the Broker — refusing to issue rather than ` +
          `granting an unbudgeted lease`;
        this.#appendDecisionEvent(reqId, 'deny', reason, decision.ruleId);
        return { type: 'denied', reason };
      }

      for (const rule of budgeted) {
        const capMs = rule.maxTotalDurationMs as number;
        const halfLifeMs = rule.durationHalfLifeMs as number;
        const headroom = this.#durationLedger.headroomMs(rule.ruleId, capMs, halfLifeMs, nowMs);
        if (headroom < durationMs) {
          durationMs = headroom;
          bindingRuleId = rule.ruleId;
        }
      }
    }

    // Whole milliseconds only — decay is continuous, so headroom arrives as a
    // fraction and an expiry timestamp with a fractional millisecond is
    // meaningless.
    durationMs = Math.floor(durationMs);

    if (durationMs < MIN_GRANTABLE_DURATION_MS) {
      // Exhausted, not merely clamped. Granting a zero-length lease would be a
      // denial dressed as a grant, so it is reported as what it is — with the
      // rule that ran out and the fact that headroom regenerates, so the
      // caller knows to wait rather than to retry immediately in a loop.
      const reason =
        `duration budget exhausted for rule '${bindingRuleId ?? decision.ruleId ?? 'unknown'}' ` +
        `— remaining headroom is under the ${MIN_GRANTABLE_DURATION_MS}ms minimum grantable ` +
        `lease. Headroom regenerates continuously (exponential decay), so this will succeed ` +
        `again after time passes; it is not a permanent denial`;
      this.#appendDecisionEvent(reqId, 'deny', reason, bindingRuleId ?? decision.ruleId);
      return { type: 'denied', reason };
    }

    const issuedAt = now.toISOString();
    const expiresAt = new Date(nowMs + durationMs).toISOString();

    const lease: Lease = {
      id: randomUUID(),
      agentId: req.agentId,
      taskId: req.taskId,
      // Issued scope is a subset of (or equal to) requested scope.
      // Policy already validated that requested capabilities are within bounds.
      capabilities: req.capabilities,
      issuedAt,
      expiresAt,
      kid: this.#kid,
    };

    const token = this.#signer.issue(lease);

    // Charge EVERY budgeted rule the lease was granted under. Charging only
    // the binding one would let the others hand out the same time for free.
    // Accrue after signing succeeds, so a failed issuance costs no budget.
    if (this.#durationLedger !== undefined) {
      for (const rule of budgeted) {
        this.#durationLedger.accrue(
          rule.ruleId,
          durationMs,
          rule.durationHalfLifeMs as number,
          nowMs,
        );
      }
    }

    this.#audit.append({
      type: 'issuance',
      at: new Date().toISOString(),
      leaseId: lease.id,
      requestId: reqId,
      detail: {
        agentId: lease.agentId,
        taskId: lease.taskId,
        issuedAt,
        expiresAt,
        capabilities: lease.capabilities,
        // Record what was actually granted against what was asked for. A lease
        // silently shorter than requested is exactly the kind of thing an
        // operator needs to see in the log rather than infer.
        requestedDurationMs: req.requestedDurationMs,
        grantedDurationMs: durationMs,
        ...(durationMs < req.requestedDurationMs
          ? { clampedBy: bindingRuleId ?? decision.ruleId ?? 'rule maxDurationMs' }
          : {}),
        ...(budgeted.length > 0
          ? { budgetedRules: budgeted.map((r) => r.ruleId) }
          : {}),
      },
      prevHash: '',
      hash: '',
    });

    return { type: 'granted', token, lease };
  }

  #appendRequestEvent(reqId: string, req: LeaseRequest): void {
    this.#audit.append({
      type: 'request',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        agentId: req.agentId,
        taskId: req.taskId,
        capabilities: req.capabilities,
        requestedDurationMs: req.requestedDurationMs,
      },
      prevHash: '',
      hash: '',
    });
  }

  #appendDecisionEvent(
    reqId: string,
    effect: 'grant' | 'deny' | 'veto-required',
    reason: string,
    ruleId?: string,
  ): void {
    this.#audit.append({
      type: 'decision',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        effect,
        reason,
        ...(ruleId !== undefined ? { ruleId } : {}),
      },
      prevHash: '',
      hash: '',
    });
  }
}

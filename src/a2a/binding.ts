/**
 * A2A context binding — contextId → lease token (ADR-F, profile §Context binding).
 *
 * A2A has no initialize handshake and no transport session, so the MCP-side
 * `sessionId → token` binding (LeasebrokerProxy) cannot port. Binding is
 * per-context: the first message of a contextId that presents a token binds
 * the context; later messages may omit the token; a DIFFERENT token for an
 * already-bound context is rejected (no mid-context token swapping).
 *
 * Mutable state at the enforcement point, like SpendLedger/RevocationList —
 * the signed lease itself stays immutable (ADR-B consequence).
 */

/** Result of a bind attempt. */
export type BindResult = { ok: true } | { ok: false; reason: string };

export class A2aLeaseBinding {
  private readonly contexts = new Map<string, string>();

  /**
   * Bind `token` to `contextId`. Re-binding the SAME token is idempotent;
   * a different token for a bound context is a conflict.
   */
  bind(contextId: string, token: string): BindResult {
    const existing = this.contexts.get(contextId);
    if (existing !== undefined && existing !== token) {
      return {
        ok: false,
        reason: 'context is already bound to a different lease token',
      };
    }
    this.contexts.set(contextId, token);
    return { ok: true };
  }

  /** The token bound to `contextId`, if any. */
  tokenFor(contextId: string): string | undefined {
    return this.contexts.get(contextId);
  }

  /** Release a context binding (e.g. on task completion or context expiry). */
  release(contextId: string): void {
    this.contexts.delete(contextId);
  }

  /** Number of bound contexts (observability). */
  get size(): number {
    return this.contexts.size;
  }
}

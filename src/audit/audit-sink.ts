/**
 * In-memory, append-only, hash-chained audit log.
 *
 * Implements the AuditSink interface from src/contract.
 *
 * Design:
 * - Every appended event has its `prevHash` and `hash` computed and stored.
 * - `read()` re-verifies the full hash chain before returning events.
 *   Any insertion, deletion, or mutation of stored events causes read() to throw.
 * - The caller-provided `prevHash` / `hash` values are always overwritten by
 *   the implementation to ensure chain integrity.
 */

import type { AuditEvent, AuditSink } from '../contract/index.js';
import { computeEventHash } from './hash.js';

export class InMemoryAuditSink implements AuditSink {
  // Events are stored in append order. Direct mutation by tests is detectable
  // via hash chain verification in read().
  private readonly events: AuditEvent[] = [];

  /**
   * Append a new event to the log.
   *
   * The implementation always computes `prevHash` and `hash`:
   * - `prevHash` = hash of the last stored event, or "" for the first event.
   * - `hash` = SHA-256 of the canonical event representation (excluding `hash`).
   *
   * Any caller-supplied `prevHash` / `hash` values are overwritten.
   */
  append(event: AuditEvent): void {
    const prevHash =
      this.events.length === 0
        ? ''
        : (this.events[this.events.length - 1]?.hash ?? '');

    // Overwrite prevHash with the computed value, then compute hash.
    const withPrevHash: AuditEvent = { ...event, prevHash };
    const hash = computeEventHash(withPrevHash);

    this.events.push({ ...withPrevHash, hash });
  }

  /**
   * Read all events in append order.
   *
   * Verifies the full hash chain before returning. Throws if any event has
   * been inserted, removed, or its content modified since it was appended.
   *
   * @throws {Error} if tamper evidence is detected.
   */
  read(): AuditEvent[] {
    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i];
      // noUncheckedIndexedAccess safety — array bounds are loop-controlled.
      if (event === undefined) continue;

      // Verify chain linkage: each event's prevHash must equal the previous event's hash.
      const expectedPrevHash =
        i === 0 ? '' : (this.events[i - 1]?.hash ?? '');

      if (event.prevHash !== expectedPrevHash) {
        throw new Error(
          `Audit log tampered at event[${i}]: prevHash mismatch ` +
            `(expected "${expectedPrevHash}", got "${event.prevHash}")`,
        );
      }

      // Verify content integrity: recompute the hash and compare with stored hash.
      const expectedHash = computeEventHash(event);
      if (event.hash !== expectedHash) {
        throw new Error(
          `Audit log tampered at event[${i}]: hash mismatch ` +
            `(expected "${expectedHash}", stored "${event.hash}")`,
        );
      }
    }

    // Return a shallow copy so the caller cannot mutate internal state via the array.
    return [...this.events];
  }
}

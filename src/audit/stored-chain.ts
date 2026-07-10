/**
 * Stored-chain verification for persisted audit logs (audit.jsonl).
 *
 * The hash chain ON DISK is the tamper evidence: each event's `prevHash` must
 * equal the previous event's stored `hash`, and its stored `hash` must equal
 * the recomputed content hash. Loading a file back through
 * `InMemoryAuditSink.append()` would RE-CHAIN it — recomputing fresh hashes
 * over whatever content is present — so a tampered file would verify clean
 * against its own laundered chain. Every reader of audit.jsonl must judge
 * integrity with this module, against the hashes as written.
 */

import type { AuditEvent } from '../contract/index.js';
import { computeEventHash } from './hash.js';

export type AuditIntegrity = 'intact' | 'tampered';

export interface StoredAuditLog {
  events: AuditEvent[];
  integrity: AuditIntegrity;
}

/**
 * Parse raw audit.jsonl content and verify the stored hash chain.
 *
 * Verification is against the hashes AS WRITTEN: a linkage or content-hash
 * mismatch marks the log tampered, but parsing continues — callers should be
 * able to show the evidence alongside the verdict, not a blank log. An
 * unparseable line also marks the log tampered; the parsed prefix is kept.
 */
export function parseStoredAuditJsonl(raw: string): StoredAuditLog {
  const events: AuditEvent[] = [];
  let integrity: AuditIntegrity = 'intact';
  for (const line of raw.split('\n')) {
    if (line.trim() === '') continue;
    let ev: AuditEvent;
    try {
      ev = JSON.parse(line) as AuditEvent;
    } catch {
      // Unparseable line — evidence is damaged; keep what parsed so far.
      integrity = 'tampered';
      break;
    }
    const expectedPrev = events.length === 0 ? '' : (events[events.length - 1]?.hash ?? '');
    if (ev.prevHash !== expectedPrev || computeEventHash(ev) !== ev.hash) {
      integrity = 'tampered';
    }
    events.push(ev);
  }
  return { events, integrity };
}

/**
 * Anchor persistence — proof files and the anchor record index.
 *
 * Layout under the state dir:
 *   .leasebroker/anchors/anchors.jsonl        — one AnchorRecord per line
 *   .leasebroker/anchors/<stamp>-<tip8>.ots   — detached timestamp proofs
 *
 * The records file is bookkeeping, not tamper evidence — proofs are
 * self-authenticating (the .ots file commits to the tip hash, and the tip
 * hash commits to the whole chain prefix), so anchors.jsonl carries no hash
 * chain of its own. A corrupt or missing record only ever loses convenience
 * metadata; it can never forge an anchor.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type AnchorStatus = 'pending' | 'confirmed';

export interface AnchorRecord {
  /** ISO time the digest was submitted to the calendars. */
  anchoredAt: string;
  /** Number of audit events covered by this anchor (the chain prefix length). */
  eventCount: number;
  /** Stored hash of the chain tip (event[eventCount - 1]) at anchor time. */
  tipHash: string;
  /** Calendar URLs that accepted the submission. */
  calendars: string[];
  /** Proof filename within the anchors directory. */
  proofFile: string;
  /** pending until a Bitcoin attestation lands (see `anchor --upgrade`). */
  status: AnchorStatus;
  /** Bitcoin block height of the confirming attestation, once confirmed. */
  bitcoinHeight?: number;
}

export interface AnchorRecordsLoad {
  records: AnchorRecord[];
  /** True if any line failed to parse — surfaced, never silently dropped. */
  malformed: boolean;
}

export function anchorsDir(stateDir: string): string {
  return join(stateDir, 'anchors');
}

function recordsPath(stateDir: string): string {
  return join(anchorsDir(stateDir), 'anchors.jsonl');
}

function isAnchorRecord(value: unknown): value is AnchorRecord {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['anchoredAt'] === 'string' &&
    typeof r['eventCount'] === 'number' &&
    typeof r['tipHash'] === 'string' &&
    Array.isArray(r['calendars']) &&
    typeof r['proofFile'] === 'string' &&
    (r['status'] === 'pending' || r['status'] === 'confirmed')
  );
}

/** Load all anchor records; a missing file is an empty, well-formed index. */
export function loadAnchorRecords(stateDir: string): AnchorRecordsLoad {
  const path = recordsPath(stateDir);
  if (!existsSync(path)) return { records: [], malformed: false };

  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return { records: [], malformed: true };
  }

  const records: AnchorRecord[] = [];
  let malformed = false;
  for (const line of raw.split('\n')) {
    if (line.trim() === '') continue;
    try {
      const parsed: unknown = JSON.parse(line);
      if (isAnchorRecord(parsed)) {
        records.push(parsed);
      } else {
        malformed = true;
      }
    } catch {
      malformed = true;
    }
  }
  return { records, malformed };
}

function ensureAnchorsDir(stateDir: string): void {
  const dir = anchorsDir(stateDir);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

export function appendAnchorRecord(stateDir: string, record: AnchorRecord): void {
  ensureAnchorsDir(stateDir);
  const path = recordsPath(stateDir);
  const line = JSON.stringify(record) + '\n';
  const existing = existsSync(path) ? readFileSync(path, 'utf8') : '';
  writeFileSync(path, existing + line);
}

/** Rewrite the full records file (used by `anchor --upgrade` status flips). */
export function saveAnchorRecords(stateDir: string, records: AnchorRecord[]): void {
  ensureAnchorsDir(stateDir);
  const jsonl = records.map((r) => JSON.stringify(r)).join('\n');
  writeFileSync(recordsPath(stateDir), jsonl ? jsonl + '\n' : '');
}

/** Filename for a new proof: filesystem-safe timestamp + tip hash prefix. */
export function proofFileName(anchoredAt: string, tipHash: string): string {
  const stamp = anchoredAt.replace(/[:.]/g, '-');
  return `${stamp}-${tipHash.slice(0, 8)}.ots`;
}

export function writeProofFile(stateDir: string, filename: string, bytes: Uint8Array): void {
  ensureAnchorsDir(stateDir);
  writeFileSync(join(anchorsDir(stateDir), filename), bytes);
}

/** Read a proof file; null if missing or unreadable (verify reports it). */
export function readProofFile(stateDir: string, filename: string): Uint8Array | null {
  const path = join(anchorsDir(stateDir), filename);
  if (!existsSync(path)) return null;
  try {
    return new Uint8Array(readFileSync(path));
  } catch {
    return null;
  }
}

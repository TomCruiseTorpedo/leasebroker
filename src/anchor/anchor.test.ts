/**
 * Tests for the anchor module: OTS wire format, store, verification.
 *
 * Required coverage:
 *   - Reference-vector interop (ADR-G hard acceptance criterion): the
 *     official hello-world.txt.ots example parses, carries the known Bitcoin
 *     attestation (block 358391), and re-serializes byte-identical.
 *   - LEB128 varint + varbytes round trips and bounds.
 *   - Op execution vectors (sha256/append/prepend/reverse/hexlify).
 *   - Synthetic tree round trip with pending + Bitcoin attestations.
 *   - Upgrade merge semantics (graft, dedupe, idempotence).
 *   - Anchor record persistence incl. malformed-line surfacing.
 *   - End-to-end verification against a real hash-chained audit log:
 *     confirmed / pending / tamper / truncation / missing-proof / unanchored.
 */

import { createHash } from 'crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '../contract/index.js';
import { InMemoryAuditSink } from '../audit/index.js';
import {
  ByteReader,
  ByteWriter,
  allAttestations,
  applyOp,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  mergeTimestamp,
  parseDetached,
  parseTimestamp,
  serializeDetached,
  serializeTimestamp,
} from './ots.js';
import type { TimestampNode } from './ots.js';
import {
  anchorsDir,
  appendAnchorRecord,
  loadAnchorRecords,
  proofFileName,
  readProofFile,
  saveAnchorRecords,
  writeProofFile,
} from './store.js';
import type { AnchorRecord } from './store.js';
import { summarizeAnchors, verifyAnchorRecord, verifyAnchors } from './verify.js';

// ---------------------------------------------------------------------------
// Reference vector — the official OpenTimestamps "hello world" example.
// Source: github.com/opentimestamps/javascript-opentimestamps
//         examples/hello-world.txt(.ots)
// The file "Hello World!\n" was timestamped in Bitcoin block 358391 (2015);
// this is the standard interop example across all OTS implementations.
// ---------------------------------------------------------------------------

const HELLO_WORLD_OTS_B64 =
  'AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIA7ogTlDRJuRnTABeBNguhMITZngK8fQ71Uo3gWtqs0AD8cgBAQAAAAHkgvnTLsw7ple2nYmAEIV7VEV6kEl5gv9W+XxOxY5vmAEAAABrSDBFAiEAslOt0dHPkIRDOKR1oE/xP8nnvSQrB3Yt6gf1YIst42cCIACyaMqcM0KzdpzdBiiRMXzc74eqwxC2hV6dk4mOu+jsASECDY5NEH0rM5sAUO/dS0oJJFqgVgSPElOWN06moqsHCcb/////AmUz5gUAAAAAGXapFAvwV9QPu6Z0SGJRX1tVojEN5XcviKyghgEAAAAAABl2qRTwBoisAAAAAAgI8SCph/cWxTORPDFMeONdNYhMrJQ/pCysSdKyxp9AA/hfiAgI8SDexVs0h+Hj9yKkm1WneDIVhieF9KOss5KEYBn3HcZKnQgI8SCyyhj0heCAR44CXas9RktBbA4ey2Ypya786MghTQQkMggI8CARsOkGYRlv9LCBPD7aFBurXpFgSDe996DJ3zfbDjoRmAgI8CDDS8GkoQk//RSMAWseZkdCkU6Tnvq+TT01ZRWRSybZ4ggI8CDD5ufDjGn2ryTCvjTrrEglft5h7AohuVNeREMne+MGRggI8SAHmL+GBuAAJOXV1UvwyWD2Kd+52taRV0VbbyZSwOjegQgI8CA/mtptYLqiRABrsKrVFEitL6+51LZIegmZz/JrkfD1NggI8SDHAwGelZqN0/rvdIm7MoukhVdHWOcJHwFGTrZYcsl1yAgI8CDL/v/1E/+EuRXj/tb515lnZjD4Nk6ipsdVf62UpbXXiAgI8SAL4jcJhZkTur1EYLvd+O0hPnyHc6Sx+s4w+Kz98JO3BQgIAAWIlg1z1xkBA/fvFQ==';

const HELLO_WORLD_DIGEST = '03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340';
const HELLO_WORLD_BITCOIN_HEIGHT = 358391;

function referenceProofBytes(): Uint8Array {
  return new Uint8Array(Buffer.from(HELLO_WORLD_OTS_B64, 'base64'));
}

function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

// ---------------------------------------------------------------------------
// Reference vector interop
// ---------------------------------------------------------------------------

describe('OTS reference vector (hello-world.txt.ots)', () => {
  it('parses with the expected digest and file hash op', () => {
    const detached = parseDetached(referenceProofBytes());
    expect(detached.fileHashOp).toBe('sha256');
    expect(bytesToHex(detached.digest)).toBe(HELLO_WORLD_DIGEST);
  });

  it('digest matches sha256 of the original file content', () => {
    expect(bytesToHex(sha256('Hello World!\n'))).toBe(HELLO_WORLD_DIGEST);
  });

  it('carries the known Bitcoin block 358391 attestation', () => {
    const detached = parseDetached(referenceProofBytes());
    const leaves = allAttestations(detached.root);
    const bitcoin = leaves.filter((l) => l.attestation.kind === 'bitcoin');
    expect(bitcoin).toHaveLength(1);
    expect(bitcoin[0]?.attestation).toEqual({ kind: 'bitcoin', height: HELLO_WORLD_BITCOIN_HEIGHT });
  });

  it('re-serializes byte-identical (parse → serialize round trip)', () => {
    const original = referenceProofBytes();
    const detached = parseDetached(original);
    const reserialized = serializeDetached(detached.digest, detached.root);
    expect(bytesEqual(reserialized, original)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

describe('LEB128 varint / varbytes', () => {
  it('round-trips boundary values', () => {
    for (const value of [0, 1, 127, 128, 255, 16383, 16384, 358391, 2 ** 31]) {
      const w = new ByteWriter();
      w.writeVaruint(value);
      expect(new ByteReader(w.toBytes()).readVaruint()).toBe(value);
    }
  });

  it('encodes 358391 as f7ef15 (the reference block height)', () => {
    const w = new ByteWriter();
    w.writeVaruint(HELLO_WORLD_BITCOIN_HEIGHT);
    expect(bytesToHex(w.toBytes())).toBe('f7ef15');
  });

  it('varbytes enforces max length on read', () => {
    const w = new ByteWriter();
    w.writeVarbytes(new Uint8Array(64));
    expect(() => new ByteReader(w.toBytes()).readVarbytes(32)).toThrow(/exceeds max/);
  });

  it('reader rejects truncated input', () => {
    expect(() => new ByteReader(new Uint8Array([0x08])).readBytes(2)).toThrow(/Truncated/);
  });
});

describe('applyOp', () => {
  const msg = new Uint8Array(Buffer.from('abc', 'utf8'));

  it('sha256 matches node:crypto', () => {
    expect(bytesEqual(applyOp({ tag: 'sha256' }, msg), sha256(msg))).toBe(true);
  });

  it('append and prepend concatenate on the right sides', () => {
    const arg = new Uint8Array([0x01, 0x02]);
    expect(Array.from(applyOp({ tag: 'append', arg }, msg))).toEqual([0x61, 0x62, 0x63, 0x01, 0x02]);
    expect(Array.from(applyOp({ tag: 'prepend', arg }, msg))).toEqual([0x01, 0x02, 0x61, 0x62, 0x63]);
  });

  it('reverse and hexlify', () => {
    expect(Array.from(applyOp({ tag: 'reverse' }, msg))).toEqual([0x63, 0x62, 0x61]);
    expect(Buffer.from(applyOp({ tag: 'hexlify' }, msg)).toString('utf8')).toBe('616263');
  });
});

// ---------------------------------------------------------------------------
// Synthetic trees — build, round-trip, merge
// ---------------------------------------------------------------------------

/** A calendar-response-shaped tree: digest → append(nonce) → sha256 → pending. */
function pendingTree(digest: Uint8Array, uri: string, nonce: Uint8Array): TimestampNode {
  const appended = applyOp({ tag: 'append', arg: nonce }, digest);
  const hashed = applyOp({ tag: 'sha256' }, appended);
  const leaf: TimestampNode = {
    msg: hashed,
    attestations: [{ kind: 'pending', uri }],
    ops: [],
  };
  const mid: TimestampNode = { msg: appended, attestations: [], ops: [{ op: { tag: 'sha256' }, node: leaf }] };
  return { msg: digest, attestations: [], ops: [{ op: { tag: 'append', arg: nonce }, node: mid }] };
}

/** An upgraded continuation for the pending leaf: commitment → prepend → sha256 → bitcoin. */
function upgradeTree(commitment: Uint8Array, height: number): TimestampNode {
  const prefix = new Uint8Array([0xaa, 0xbb]);
  const prepended = applyOp({ tag: 'prepend', arg: prefix }, commitment);
  const hashed = applyOp({ tag: 'sha256' }, prepended);
  const leaf: TimestampNode = { msg: hashed, attestations: [{ kind: 'bitcoin', height }], ops: [] };
  const mid: TimestampNode = { msg: prepended, attestations: [], ops: [{ op: { tag: 'sha256' }, node: leaf }] };
  return {
    msg: commitment,
    attestations: [],
    ops: [{ op: { tag: 'prepend', arg: prefix }, node: mid }],
  };
}

describe('synthetic timestamp trees', () => {
  const digest = sha256('some audit chain tip');

  it('detached round trip preserves structure and bytes', () => {
    const root = pendingTree(digest, 'https://alice.example', new Uint8Array([1, 2, 3, 4]));
    const bytes = serializeDetached(digest, root);
    const parsed = parseDetached(bytes);
    expect(bytesToHex(parsed.digest)).toBe(bytesToHex(digest));
    const leaves = allAttestations(parsed.root);
    expect(leaves).toHaveLength(1);
    expect(leaves[0]?.attestation).toEqual({ kind: 'pending', uri: 'https://alice.example' });
    expect(bytesEqual(serializeDetached(parsed.digest, parsed.root), bytes)).toBe(true);
  });

  it('serializes multiple op branches and multiple attestations', () => {
    const rootA = pendingTree(digest, 'https://alice.example', new Uint8Array([1]));
    const rootB = pendingTree(digest, 'https://bob.example', new Uint8Array([2]));
    mergeTimestamp(rootA, rootB);
    expect(rootA.ops).toHaveLength(2);
    const bytes = serializeDetached(digest, rootA);
    const parsed = parseDetached(bytes);
    const uris = allAttestations(parsed.root)
      .map((l) => (l.attestation.kind === 'pending' ? l.attestation.uri : ''))
      .sort();
    expect(uris).toEqual(['https://alice.example', 'https://bob.example']);
  });

  it('empty timestamp refuses to serialize', () => {
    const empty: TimestampNode = { msg: digest, attestations: [], ops: [] };
    expect(() => serializeTimestamp(new ByteWriter(), empty)).toThrow(/empty timestamp/);
  });

  it('rejects bad magic and trailing garbage', () => {
    const root = pendingTree(digest, 'https://alice.example', new Uint8Array([1]));
    const bytes = serializeDetached(digest, root);
    const badMagic = bytes.slice();
    badMagic[3] = 0x00;
    expect(() => parseDetached(badMagic)).toThrow(/magic/);
    const trailing = new Uint8Array(bytes.length + 1);
    trailing.set(bytes, 0);
    expect(() => parseDetached(trailing)).toThrow(/Trailing garbage/);
  });
});

describe('mergeTimestamp (upgrade grafting)', () => {
  const digest = sha256('tip to upgrade');

  it('grafts a Bitcoin attestation onto the pending commitment node', () => {
    const root = pendingTree(digest, 'https://alice.example', new Uint8Array([9, 9]));
    const pendingLeaf = allAttestations(root).find((l) => l.attestation.kind === 'pending');
    expect(pendingLeaf).toBeDefined();

    const upgraded = upgradeTree(pendingLeaf!.commitment, 900_000);
    mergeTimestamp(pendingLeaf!.node, upgraded);

    const kinds = allAttestations(root).map((l) => l.attestation.kind).sort();
    expect(kinds).toEqual(['bitcoin', 'pending']);
  });

  it('is idempotent — merging the same tree twice adds nothing', () => {
    const root = pendingTree(digest, 'https://alice.example', new Uint8Array([9, 9]));
    const leaf = allAttestations(root)[0];
    const upgraded = upgradeTree(leaf!.commitment, 900_000);
    mergeTimestamp(leaf!.node, upgraded);
    const once = allAttestations(root).length;
    mergeTimestamp(leaf!.node, upgradeTree(leaf!.commitment, 900_000));
    expect(allAttestations(root)).toHaveLength(once);
  });

  it('refuses to merge trees over different messages', () => {
    const a: TimestampNode = { msg: sha256('a'), attestations: [], ops: [] };
    const b: TimestampNode = { msg: sha256('b'), attestations: [], ops: [] };
    expect(() => mergeTimestamp(a, b)).toThrow(/different messages/);
  });
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

describe('anchor store', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'lb-anchor-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  const record: AnchorRecord = {
    anchoredAt: '2026-07-11T10:00:00.000Z',
    eventCount: 3,
    tipHash: 'ab'.repeat(32),
    calendars: ['https://alice.example'],
    proofFile: 'proof.ots',
    status: 'pending',
  };

  it('append + load round trip; missing file is empty and well-formed', () => {
    expect(loadAnchorRecords(tmpDir)).toEqual({ records: [], malformed: false });
    appendAnchorRecord(tmpDir, record);
    appendAnchorRecord(tmpDir, { ...record, eventCount: 5, status: 'confirmed', bitcoinHeight: 1 });
    const load = loadAnchorRecords(tmpDir);
    expect(load.malformed).toBe(false);
    expect(load.records).toHaveLength(2);
    expect(load.records[1]?.status).toBe('confirmed');
  });

  it('surfaces malformed lines instead of silently dropping them', () => {
    appendAnchorRecord(tmpDir, record);
    writeFileSync(join(anchorsDir(tmpDir), 'anchors.jsonl'), JSON.stringify(record) + '\nnot json\n');
    const load = loadAnchorRecords(tmpDir);
    expect(load.records).toHaveLength(1);
    expect(load.malformed).toBe(true);
  });

  it('saveAnchorRecords rewrites for status flips', () => {
    appendAnchorRecord(tmpDir, record);
    saveAnchorRecords(tmpDir, [{ ...record, status: 'confirmed', bitcoinHeight: 900000 }]);
    const load = loadAnchorRecords(tmpDir);
    expect(load.records[0]?.status).toBe('confirmed');
    expect(load.records[0]?.bitcoinHeight).toBe(900000);
  });

  it('proof files write and read back; missing proof is null', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    writeProofFile(tmpDir, 'p.ots', bytes);
    expect(Array.from(readProofFile(tmpDir, 'p.ots') ?? [])).toEqual([1, 2, 3]);
    expect(readProofFile(tmpDir, 'nope.ots')).toBeNull();
  });

  it('proofFileName is filesystem-safe', () => {
    const name = proofFileName('2026-07-11T10:00:00.000Z', 'abcdef0123456789');
    expect(name).toBe('2026-07-11T10-00-00-000Z-abcdef01.ots');
    expect(name).not.toContain(':');
  });
});

// ---------------------------------------------------------------------------
// Verification against a real hash-chained log
// ---------------------------------------------------------------------------

function makeEvent(type: AuditEvent['type'], detail: Record<string, unknown> = {}): AuditEvent {
  return { type, at: '2026-07-11T09:00:00.000Z', detail, prevHash: '', hash: '' };
}

/** Build a hash-chained log of n events via the real sink. */
function chainedEvents(n: number): AuditEvent[] {
  const sink = new InMemoryAuditSink();
  for (let i = 0; i < n; i++) {
    sink.append(makeEvent('issuance', { i }));
  }
  return sink.read();
}

/** A confirmed proof directly over the tip digest (no calendar hop needed). */
function confirmedProofFor(tipHash: string, height = 900_000): Uint8Array {
  const digest = hexToBytes(tipHash);
  const root = upgradeTree(digest, height);
  return serializeDetached(digest, root);
}

function pendingProofFor(tipHash: string): Uint8Array {
  const digest = hexToBytes(tipHash);
  const root = pendingTree(digest, 'https://alice.example', new Uint8Array([7]));
  return serializeDetached(digest, root);
}

function recordFor(events: AuditEvent[], count: number, proofFile = 'p.ots'): AnchorRecord {
  return {
    anchoredAt: '2026-07-11T10:00:00.000Z',
    eventCount: count,
    tipHash: events[count - 1]?.hash ?? '',
    calendars: ['https://alice.example'],
    proofFile,
    status: 'pending',
  };
}

describe('anchor verification', () => {
  it('confirms a Bitcoin-attested proof over a live, longer log', () => {
    const events = chainedEvents(5);
    const record = recordFor(events, 3);
    const result = verifyAnchorRecord(record, confirmedProofFor(record.tipHash), events);
    expect(result.status).toBe('confirmed');
    expect(result.bitcoinHeight).toBe(900_000);
  });

  it('reports pending for a calendar-only proof', () => {
    const events = chainedEvents(2);
    const record = recordFor(events, 2);
    const result = verifyAnchorRecord(record, pendingProofFor(record.tipHash), events);
    expect(result.status).toBe('pending');
  });

  it('flags a rewritten chain — anchored tip hash no longer at its index', () => {
    const events = chainedEvents(4);
    const record = recordFor(events, 3);
    const rewritten = chainedEvents(4).map((e, i) =>
      i === 1 ? { ...e, detail: { forged: true } } : e,
    );
    // Rebuild a plausible-but-different chain by re-appending forged content.
    const sink = new InMemoryAuditSink();
    for (const e of rewritten) sink.append({ ...e, prevHash: '', hash: '' });
    const result = verifyAnchorRecord(record, confirmedProofFor(record.tipHash), sink.read());
    expect(result.status).toBe('invalid');
    expect(result.detail).toMatch(/does not match anchored tip/);
  });

  it('flags a truncated log — anchored prefix longer than the log', () => {
    const events = chainedEvents(5);
    const record = recordFor(events, 5);
    const proof = confirmedProofFor(record.tipHash);
    const result = verifyAnchorRecord(record, proof, events.slice(0, 3));
    expect(result.status).toBe('invalid');
    expect(result.detail).toMatch(/truncated or replaced/);
  });

  it('flags a missing proof file and a digest mismatch', () => {
    const events = chainedEvents(3);
    const record = recordFor(events, 3);
    expect(verifyAnchorRecord(record, null, events).status).toBe('invalid');
    const wrongDigest = confirmedProofFor('cd'.repeat(32));
    const result = verifyAnchorRecord(record, wrongDigest, events);
    expect(result.status).toBe('invalid');
    expect(result.detail).toMatch(/digest does not match/);
  });

  it('summarize: fail-closed on any invalid; pending-only is healthy; empty is unanchored', () => {
    const events = chainedEvents(3);
    const confirmed = verifyAnchorRecord(recordFor(events, 3), confirmedProofFor(events[2]!.hash), events);
    const pending = verifyAnchorRecord(recordFor(events, 2), pendingProofFor(events[1]!.hash), events);
    const invalid = verifyAnchorRecord(recordFor(events, 3), null, events);

    expect(summarizeAnchors([confirmed, pending], 'intact', false)).toMatchObject({
      ok: true,
      state: 'anchored',
      coveredEvents: 3,
    });
    expect(summarizeAnchors([pending], 'intact', false)).toMatchObject({
      ok: true,
      state: 'anchored-pending',
    });
    expect(summarizeAnchors([], 'intact', false)).toMatchObject({ ok: true, state: 'unanchored' });
    expect(summarizeAnchors([confirmed, invalid], 'intact', false)).toMatchObject({
      ok: false,
      state: 'broken',
    });
    expect(summarizeAnchors([confirmed], 'tampered', false)).toMatchObject({
      ok: false,
      state: 'broken',
    });
    expect(summarizeAnchors([confirmed], 'intact', true)).toMatchObject({
      ok: false,
      state: 'broken',
    });
  });

  it('verifyAnchors composes records, proofs, and integrity', () => {
    const events = chainedEvents(3);
    const record = recordFor(events, 3);
    const proofs = new Map([[record.proofFile, confirmedProofFor(record.tipHash)]]);
    const verification = verifyAnchors(
      { records: [record], malformed: false },
      events,
      'intact',
      (f) => proofs.get(f) ?? null,
    );
    expect(verification.state).toBe('anchored');
    expect(verification.coveredEvents).toBe(3);
  });
});

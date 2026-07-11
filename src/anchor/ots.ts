/**
 * Minimal OpenTimestamps (OTS) wire format — serialize, parse, execute.
 *
 * Implements exactly the subset leasebroker needs to anchor an audit-chain
 * tip hash and verify the resulting proofs:
 * - detached timestamp files (.ots) — header magic, version 1, file-hash op,
 *   digest, timestamp tree
 * - timestamp trees — append/prepend/reverse/hexlify + sha1/ripemd160/sha256
 *   ops, pending (calendar) and Bitcoin block-header attestations
 * - LEB128 varuints and varbytes, per the reference serialization
 *
 * Hand-rolled on node:crypto for the same reason ADR-A hand-rolls PASETO on
 * @noble/ed25519: the canonical `opentimestamps` npm package last shipped in
 * 2022 and drags bitcore-lib/bytebuffer/moment-timezone — no security patch
 * path. We keep the standardized wire format (proof files stay verifiable by
 * the reference `ots` client) while depending only on the stdlib.
 *
 * Format constants verified against the reference implementation
 * (python-opentimestamps: core/serialize.py, core/timestamp.py, core/op.py,
 * core/notary.py) and against a reference proof file in tests (ADR-G).
 */

import { createHash } from 'crypto';

/** Detached timestamp file header magic (timestamp.py HEADER_MAGIC). */
export const HEADER_MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
  0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
  0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

export const MAJOR_VERSION = 1;

/** Attestation tags (notary.py) — 8 bytes each. */
const PENDING_TAG = hexToBytes('83dfe30d2ef90c8e');
const BITCOIN_TAG = hexToBytes('0588960d73d71901');
const ATTESTATION_TAG_SIZE = 8;
const MAX_ATTESTATION_PAYLOAD = 8192;
const MAX_URI_LENGTH = 1000;

/** Op limits (op.py). */
const MAX_OP_LENGTH = 4096;
const MAX_RECURSION = 256;

/** Op tags (op.py). */
const TAG_SHA1 = 0x02;
const TAG_RIPEMD160 = 0x03;
const TAG_SHA256 = 0x08;
const TAG_KECCAK256 = 0x67;
const TAG_APPEND = 0xf0;
const TAG_PREPEND = 0xf1;
const TAG_REVERSE = 0xf2;
const TAG_HEXLIFY = 0xf3;

export class OtsParseError extends Error {}
export class OtsUnsupportedOpError extends Error {}

export type Attestation =
  | { readonly kind: 'pending'; readonly uri: string }
  | { readonly kind: 'bitcoin'; readonly height: number }
  | { readonly kind: 'unknown'; readonly tag: Uint8Array; readonly payload: Uint8Array };

export type TimestampOp =
  | { readonly tag: 'sha1' }
  | { readonly tag: 'ripemd160' }
  | { readonly tag: 'sha256' }
  | { readonly tag: 'keccak256' }
  | { readonly tag: 'reverse' }
  | { readonly tag: 'hexlify' }
  | { readonly tag: 'append'; readonly arg: Uint8Array }
  | { readonly tag: 'prepend'; readonly arg: Uint8Array };

/**
 * One node of a timestamp tree. `msg` is the message this node's ops apply
 * to; each op edge leads to a child node whose msg is the op's result.
 * Arrays preserve wire order, so a parse → serialize round trip of
 * reference-produced bytes is byte-identical (the reference sorts on write).
 */
export interface TimestampNode {
  msg: Uint8Array;
  attestations: Attestation[];
  ops: Array<{ op: TimestampOp; node: TimestampNode }>;
}

/** A parsed detached timestamp file. */
export interface DetachedTimestamp {
  /** File-hash op tag name; leasebroker always writes sha256. */
  fileHashOp: 'sha1' | 'ripemd160' | 'sha256' | 'keccak256';
  digest: Uint8Array;
  root: TimestampNode;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new OtsParseError(`Invalid hex string: "${hex}"`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Apply a timestamp op to a message.
 *
 * @throws {OtsUnsupportedOpError} for keccak256 (not in node:crypto) and for
 *   ripemd160 on OpenSSL builds that dropped it — leasebroker's own proofs
 *   only ever contain sha256/append/prepend, so this surfaces only on
 *   foreign proof files.
 */
export function applyOp(op: TimestampOp, msg: Uint8Array): Uint8Array {
  if (msg.length > MAX_OP_LENGTH) {
    throw new OtsParseError(`Op message too long: ${msg.length} > ${MAX_OP_LENGTH}`);
  }
  switch (op.tag) {
    case 'sha256':
      return new Uint8Array(createHash('sha256').update(msg).digest());
    case 'sha1':
      return new Uint8Array(createHash('sha1').update(msg).digest());
    case 'ripemd160':
      try {
        return new Uint8Array(createHash('ripemd160').update(msg).digest());
      } catch {
        throw new OtsUnsupportedOpError('ripemd160 unavailable in this OpenSSL build');
      }
    case 'keccak256':
      throw new OtsUnsupportedOpError('keccak256 is not supported (dubious op, not in node:crypto)');
    case 'reverse': {
      const out = new Uint8Array(msg.length);
      for (let i = 0; i < msg.length; i++) {
        out[i] = msg[msg.length - 1 - i] as number;
      }
      return out;
    }
    case 'hexlify':
      return new Uint8Array(Buffer.from(bytesToHex(msg), 'utf8'));
    case 'append':
      return concat(msg, op.arg);
    case 'prepend':
      return concat(op.arg, msg);
  }
}

/** Growable byte writer with the OTS primitives. */
export class ByteWriter {
  private chunks: Uint8Array[] = [];

  writeBytes(bytes: Uint8Array): void {
    this.chunks.push(bytes);
  }

  writeUint8(value: number): void {
    this.chunks.push(Uint8Array.from([value & 0xff]));
  }

  /** Unsigned little-endian base-128 (LEB128), per serialize.py. */
  writeVaruint(value: number): void {
    if (!Number.isInteger(value) || value < 0) {
      throw new OtsParseError(`varuint must be a non-negative integer, got ${value}`);
    }
    if (value === 0) {
      this.writeUint8(0);
      return;
    }
    while (value !== 0) {
      let b = value & 0x7f;
      if (value > 0x7f) b |= 0x80;
      this.writeUint8(b);
      if (value <= 0x7f) break;
      value = Math.floor(value / 128);
    }
  }

  writeVarbytes(bytes: Uint8Array): void {
    this.writeVaruint(bytes.length);
    this.writeBytes(bytes);
  }

  toBytes(): Uint8Array {
    const total = this.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of this.chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }
}

/** Bounds-checked byte reader with the OTS primitives. */
export class ByteReader {
  private offset = 0;

  constructor(private readonly buf: Uint8Array) {}

  readBytes(n: number): Uint8Array {
    if (this.offset + n > this.buf.length) {
      throw new OtsParseError(`Truncated: needed ${n} bytes at offset ${this.offset}`);
    }
    const out = this.buf.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  readUint8(): number {
    const byte = this.readBytes(1)[0];
    // readBytes bounds-checked; index 0 of a 1-byte slice always exists.
    return byte as number;
  }

  readVaruint(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.readUint8();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 53) {
        throw new OtsParseError('varuint too large');
      }
    }
    return value;
  }

  readVarbytes(maxLen: number, minLen = 0): Uint8Array {
    const len = this.readVaruint();
    if (len > maxLen) {
      throw new OtsParseError(`varbytes length ${len} exceeds max ${maxLen}`);
    }
    if (len < minLen) {
      throw new OtsParseError(`varbytes length ${len} below min ${minLen}`);
    }
    return this.readBytes(len);
  }

  assertEof(): void {
    if (this.offset !== this.buf.length) {
      throw new OtsParseError(`Trailing garbage: ${this.buf.length - this.offset} bytes after end`);
    }
  }

  atEof(): boolean {
    return this.offset === this.buf.length;
  }
}

function serializeAttestation(writer: ByteWriter, att: Attestation): void {
  const payload = new ByteWriter();
  switch (att.kind) {
    case 'pending': {
      writer.writeBytes(PENDING_TAG);
      payload.writeVarbytes(new Uint8Array(Buffer.from(att.uri, 'utf8')));
      break;
    }
    case 'bitcoin': {
      writer.writeBytes(BITCOIN_TAG);
      payload.writeVaruint(att.height);
      break;
    }
    case 'unknown': {
      writer.writeBytes(att.tag);
      payload.writeBytes(att.payload);
      break;
    }
  }
  writer.writeVarbytes(payload.toBytes());
}

function parseAttestation(reader: ByteReader): Attestation {
  const tag = reader.readBytes(ATTESTATION_TAG_SIZE);
  const payload = reader.readVarbytes(MAX_ATTESTATION_PAYLOAD);
  const inner = new ByteReader(payload);
  if (bytesEqual(tag, PENDING_TAG)) {
    const uriBytes = inner.readVarbytes(MAX_URI_LENGTH);
    inner.assertEof();
    return { kind: 'pending', uri: Buffer.from(uriBytes).toString('utf8') };
  }
  if (bytesEqual(tag, BITCOIN_TAG)) {
    const height = inner.readVaruint();
    inner.assertEof();
    return { kind: 'bitcoin', height };
  }
  return { kind: 'unknown', tag, payload };
}

function serializeOp(writer: ByteWriter, op: TimestampOp): void {
  switch (op.tag) {
    case 'sha1':
      writer.writeUint8(TAG_SHA1);
      return;
    case 'ripemd160':
      writer.writeUint8(TAG_RIPEMD160);
      return;
    case 'sha256':
      writer.writeUint8(TAG_SHA256);
      return;
    case 'keccak256':
      writer.writeUint8(TAG_KECCAK256);
      return;
    case 'reverse':
      writer.writeUint8(TAG_REVERSE);
      return;
    case 'hexlify':
      writer.writeUint8(TAG_HEXLIFY);
      return;
    case 'append':
      writer.writeUint8(TAG_APPEND);
      writer.writeVarbytes(op.arg);
      return;
    case 'prepend':
      writer.writeUint8(TAG_PREPEND);
      writer.writeVarbytes(op.arg);
      return;
  }
}

function parseOpFromTag(reader: ByteReader, tag: number): TimestampOp {
  switch (tag) {
    case TAG_SHA1:
      return { tag: 'sha1' };
    case TAG_RIPEMD160:
      return { tag: 'ripemd160' };
    case TAG_SHA256:
      return { tag: 'sha256' };
    case TAG_KECCAK256:
      return { tag: 'keccak256' };
    case TAG_REVERSE:
      return { tag: 'reverse' };
    case TAG_HEXLIFY:
      return { tag: 'hexlify' };
    case TAG_APPEND:
      return { tag: 'append', arg: reader.readVarbytes(MAX_OP_LENGTH, 1) };
    case TAG_PREPEND:
      return { tag: 'prepend', arg: reader.readVarbytes(MAX_OP_LENGTH, 1) };
    default:
      throw new OtsParseError(`Unknown op tag 0x${tag.toString(16)}`);
  }
}

/**
 * Serialize a timestamp tree, mirroring timestamp.py Timestamp.serialize:
 * all-but-last attestation each prefixed 0xff 0x00; then either 0x00 + last
 * attestation (leaf) or [0xff 0x00 + last attestation,] 0xff-separated ops
 * with the final op unprefixed. Array order is preserved (see TimestampNode).
 */
export function serializeTimestamp(writer: ByteWriter, node: TimestampNode): void {
  if (node.attestations.length === 0 && node.ops.length === 0) {
    throw new OtsParseError("An empty timestamp can't be serialized");
  }

  const atts = node.attestations;
  for (let i = 0; i < atts.length - 1; i++) {
    writer.writeBytes(Uint8Array.from([0xff, 0x00]));
    serializeAttestation(writer, atts[i] as Attestation);
  }

  const lastAtt = atts.length > 0 ? (atts[atts.length - 1] as Attestation) : undefined;

  if (node.ops.length === 0) {
    writer.writeUint8(0x00);
    serializeAttestation(writer, lastAtt as Attestation);
    return;
  }

  if (lastAtt !== undefined) {
    writer.writeBytes(Uint8Array.from([0xff, 0x00]));
    serializeAttestation(writer, lastAtt);
  }

  for (let i = 0; i < node.ops.length - 1; i++) {
    const edge = node.ops[i];
    if (edge === undefined) continue;
    writer.writeUint8(0xff);
    serializeOp(writer, edge.op);
    serializeTimestamp(writer, edge.node);
  }
  const last = node.ops[node.ops.length - 1];
  if (last !== undefined) {
    serializeOp(writer, last.op);
    serializeTimestamp(writer, last.node);
  }
}

/**
 * Parse a timestamp tree for a known initial message, mirroring
 * timestamp.py Timestamp.deserialize.
 */
export function parseTimestamp(
  reader: ByteReader,
  msg: Uint8Array,
  recursionLimit = MAX_RECURSION,
): TimestampNode {
  if (recursionLimit <= 0) {
    throw new OtsParseError('Timestamp recursion depth limit reached');
  }

  const node: TimestampNode = { msg, attestations: [], ops: [] };

  const handleTag = (tag: number): void => {
    if (tag === 0x00) {
      node.attestations.push(parseAttestation(reader));
      return;
    }
    const op = parseOpFromTag(reader, tag);
    const result = applyOp(op, msg);
    const child = parseTimestamp(reader, result, recursionLimit - 1);
    node.ops.push({ op, node: child });
  };

  let tag = reader.readUint8();
  while (tag === 0xff) {
    handleTag(reader.readUint8());
    tag = reader.readUint8();
  }
  handleTag(tag);

  return node;
}

/** Serialize a complete detached timestamp (.ots) file for a sha256 digest. */
export function serializeDetached(digest: Uint8Array, root: TimestampNode): Uint8Array {
  if (digest.length !== 32) {
    throw new OtsParseError(`sha256 digest must be 32 bytes, got ${digest.length}`);
  }
  if (!bytesEqual(digest, root.msg)) {
    throw new OtsParseError('Timestamp root message does not match the file digest');
  }
  const writer = new ByteWriter();
  writer.writeBytes(HEADER_MAGIC);
  writer.writeUint8(MAJOR_VERSION);
  writer.writeUint8(TAG_SHA256);
  writer.writeBytes(digest);
  serializeTimestamp(writer, root);
  return writer.toBytes();
}

const DIGEST_LENGTHS: Record<number, { name: DetachedTimestamp['fileHashOp']; length: number }> = {
  [TAG_SHA1]: { name: 'sha1', length: 20 },
  [TAG_RIPEMD160]: { name: 'ripemd160', length: 20 },
  [TAG_SHA256]: { name: 'sha256', length: 32 },
  [TAG_KECCAK256]: { name: 'keccak256', length: 32 },
};

/** Parse a complete detached timestamp (.ots) file. */
export function parseDetached(bytes: Uint8Array): DetachedTimestamp {
  const reader = new ByteReader(bytes);
  const magic = reader.readBytes(HEADER_MAGIC.length);
  if (!bytesEqual(magic, HEADER_MAGIC)) {
    throw new OtsParseError('Bad header magic — not an OpenTimestamps proof file');
  }
  const version = reader.readUint8();
  if (version !== MAJOR_VERSION) {
    throw new OtsParseError(`Unsupported detached timestamp version ${version}`);
  }
  const opTag = reader.readUint8();
  const hashInfo = DIGEST_LENGTHS[opTag];
  if (hashInfo === undefined) {
    throw new OtsParseError(`Unknown file hash op tag 0x${opTag.toString(16)}`);
  }
  const digest = reader.readBytes(hashInfo.length);
  const root = parseTimestamp(reader, digest);
  reader.assertEof();
  return { fileHashOp: hashInfo.name, digest, root };
}

function attestationEqual(a: Attestation, b: Attestation): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'pending' && b.kind === 'pending') return a.uri === b.uri;
  if (a.kind === 'bitcoin' && b.kind === 'bitcoin') return a.height === b.height;
  if (a.kind === 'unknown' && b.kind === 'unknown') {
    return bytesEqual(a.tag, b.tag) && bytesEqual(a.payload, b.payload);
  }
  return false;
}

function opEqual(a: TimestampOp, b: TimestampOp): boolean {
  if (a.tag !== b.tag) return false;
  if ((a.tag === 'append' || a.tag === 'prepend') && (b.tag === 'append' || b.tag === 'prepend')) {
    return bytesEqual(a.arg, b.arg);
  }
  return true;
}

/**
 * Merge timestamp tree `other` into `target` (same message required).
 * Used by anchor --upgrade: the calendar's completed tree is grafted onto
 * the pending node it upgrades. Attestations and op edges are unioned;
 * existing pending attestations are kept (harmless, and evidence of origin).
 */
export function mergeTimestamp(target: TimestampNode, other: TimestampNode): void {
  if (!bytesEqual(target.msg, other.msg)) {
    throw new OtsParseError('Cannot merge timestamps over different messages');
  }
  for (const att of other.attestations) {
    if (!target.attestations.some((existing) => attestationEqual(existing, att))) {
      target.attestations.push(att);
    }
  }
  for (const edge of other.ops) {
    const existing = target.ops.find((e) => opEqual(e.op, edge.op));
    if (existing !== undefined) {
      mergeTimestamp(existing.node, edge.node);
    } else {
      target.ops.push(edge);
    }
  }
}

export interface AttestationLeaf {
  /** The message the attestation commits to (a calendar commitment for pending). */
  commitment: Uint8Array;
  attestation: Attestation;
  /** Reference to the tree node carrying this attestation (for upgrades). */
  node: TimestampNode;
}

/** Walk a timestamp tree and collect every attestation with its commitment. */
export function allAttestations(root: TimestampNode): AttestationLeaf[] {
  const out: AttestationLeaf[] = [];
  const walk = (node: TimestampNode): void => {
    for (const attestation of node.attestations) {
      out.push({ commitment: node.msg, attestation, node });
    }
    for (const edge of node.ops) {
      walk(edge.node);
    }
  };
  walk(root);
  return out;
}

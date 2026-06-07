/**
 * PASETO v4.public — minimal implementation on @noble/ed25519.
 *
 * Implements the PASETO v4.public token format per the PASETO RFC:
 *   https://paseto.io/rfc/
 *
 * Key decisions (ADR-A):
 *   - Crypto primitive: @noble/ed25519 (audited, maintained)
 *   - The canonical `paseto` npm lib is NOT used (3yr stale, no patch path)
 *   - SHA-512 is injected from Node.js `crypto` to enable the sync API without
 *     adding @noble/hashes as a dependency
 *
 * PASETO v4.public framing:
 *   sign:   m2 = PAE("v4.public.", m, f, i)
 *           sig = Ed25519.sign(m2, sk)
 *           token = "v4.public." || base64url(m || sig) [|| "." || base64url(f)]
 *
 *   verify: parse token, recover m and sig
 *           m2 = PAE("v4.public.", m, f, i)
 *           Ed25519.verify(sig, m2, pk)
 */

import { hashes, sign, verify, getPublicKey } from '@noble/ed25519';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Bootstrap: inject Node.js SHA-512 to enable noble/ed25519 sync API.
// ---------------------------------------------------------------------------
// noble/ed25519 v3 ships async-only by default to stay dependency-free.
// We inject once at module load so ed.sign / ed.verify are available without
// adding @noble/hashes.  Node.js `createHash` is synchronous and ships in the
// Node.js standard library — no extra package needed.
// ---------------------------------------------------------------------------
// Type cast needed: createHash().digest() returns Buffer (Uint8Array<ArrayBufferLike>),
// but hashes.sha512 expects a function returning TRet<Bytes> (Uint8Array<ArrayBuffer>).
// At runtime these are compatible; we use 'as unknown as' to satisfy the strict generic.
(hashes as { sha512: (msg: Uint8Array) => Uint8Array }).sha512 =
  (msg: Uint8Array): Uint8Array => createHash('sha512').update(msg).digest();

// Re-export public key derivation so callers can use it without importing
// noble/ed25519 directly (and risk calling it before sha512 is wired up).
export { getPublicKey, sign as ed25519Sign, verify as ed25519Verify };

// ---------------------------------------------------------------------------
// Base64url helpers (no padding, URL-safe per PASETO spec)
// ---------------------------------------------------------------------------

/** Encode bytes to base64url (no padding). */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Decode base64url string to bytes (with or without padding). */
export function fromBase64Url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

// ---------------------------------------------------------------------------
// PAE — Pre-Authentication Encoding (PASETO spec §2.2.1)
// ---------------------------------------------------------------------------
/**
 * Pre-Authentication Encoding.
 *
 * PAE(pieces...) = LE64(count) || for each piece: LE64(len(piece)) || piece
 *
 * Lengths are encoded as unsigned 64-bit little-endian integers.
 * This provides unambiguous framing for the signed message, preventing
 * signature confusion across different token structures.
 *
 * @example
 * pae(
 *   new TextEncoder().encode('v4.public.'),
 *   message,
 *   footer,
 *   implicitAssertion,
 * )
 */
export function pae(...pieces: Uint8Array[]): Uint8Array {
  const count = pieces.length;

  // Total byte size: 8 for count + sum of (8 + piece.length) for each piece
  let totalSize = 8;
  for (const piece of pieces) {
    totalSize += 8 + piece.length;
  }

  const result = new Uint8Array(totalSize);
  const view = new DataView(result.buffer);

  // Write count as unsigned 64-bit little-endian
  view.setBigUint64(0, BigInt(count), /* littleEndian= */ true);
  let offset = 8;

  for (const piece of pieces) {
    // Write piece length as unsigned 64-bit little-endian
    view.setBigUint64(offset, BigInt(piece.length), /* littleEndian= */ true);
    offset += 8;
    // Write piece bytes
    result.set(piece, offset);
    offset += piece.length;
  }

  return result;
}

// ---------------------------------------------------------------------------
// PASETO v4.public constants
// ---------------------------------------------------------------------------
const HEADER = 'v4.public.';
const HEADER_BYTES: Uint8Array = new TextEncoder().encode(HEADER);
/** Size of an Ed25519 signature in bytes. */
const SIG_BYTES = 64;

// ---------------------------------------------------------------------------
// v4.public sign
// ---------------------------------------------------------------------------
/**
 * Sign a message as a PASETO v4.public token.
 *
 * @param message           Raw message bytes (typically UTF-8 JSON)
 * @param secretKey         32-byte Ed25519 seed (private key seed)
 * @param footer            Optional footer bytes — stored in the token, not encrypted
 * @param implicitAssertion Optional implicit assertion — signed but NOT stored in token
 * @returns PASETO v4.public token string
 */
export function v4PublicSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  implicitAssertion: Uint8Array = new Uint8Array(),
): string {
  // m2 = PAE(h, m, f, i)  where h = "v4.public." as bytes
  const m2 = pae(HEADER_BYTES, message, footer, implicitAssertion);

  // sig = Ed25519.sign(m2, sk)  — 64 bytes
  const sig = sign(m2, secretKey);

  // token_payload = base64url(m || sig)
  const payload = new Uint8Array(message.length + SIG_BYTES);
  payload.set(message, 0);
  payload.set(sig, message.length);

  let token = HEADER + toBase64Url(payload);

  // Append footer if non-empty: token += "." + base64url(f)
  if (footer.length > 0) {
    token += '.' + toBase64Url(footer);
  }

  return token;
}

// ---------------------------------------------------------------------------
// v4.public verify
// ---------------------------------------------------------------------------
/**
 * Verify and decode a PASETO v4.public token.
 *
 * Checks ONLY cryptographic integrity (signature).
 * Expiry and revocation must be checked separately by the Enforcer.
 *
 * @param token             PASETO v4.public token string
 * @param publicKey         32-byte Ed25519 public key
 * @param implicitAssertion Optional implicit assertion — must match what was used at sign time
 * @returns `{ payload, footer }` on success, `null` on any verification failure
 */
export function v4PublicVerify(
  token: string,
  publicKey: Uint8Array,
  implicitAssertion: Uint8Array = new Uint8Array(),
): { payload: Uint8Array; footer: Uint8Array } | null {
  // 1. Header check
  if (!token.startsWith(HEADER)) {
    return null;
  }

  // 2. Split: ['v4', 'public', '<data>', '<footer?>']
  //    (token.split('.') on 'v4.public.<data>' gives ['v4', 'public', '<data>'])
  const parts = token.split('.');
  // parts[0] = 'v4', parts[1] = 'public', parts[2] = data, parts[3] = footer (optional)
  if (parts.length < 3 || parts.length > 4) {
    return null;
  }

  // 3. Decode the combined payload+signature blob
  const data = parts[2];
  if (!data) return null;
  const payloadAndSig = fromBase64Url(data);

  // Must have at least SIG_BYTES bytes
  if (payloadAndSig.length < SIG_BYTES) {
    return null;
  }

  // 4. Split into message (all but last 64 bytes) and signature (last 64 bytes)
  const message = payloadAndSig.slice(0, -SIG_BYTES);
  const sig = payloadAndSig.slice(-SIG_BYTES);

  // 5. Decode footer if present
  const footerData = parts[3];
  const footer = footerData !== undefined ? fromBase64Url(footerData) : new Uint8Array();

  // 6. Reconstruct m2 = PAE(h, m, f, i) and verify
  const m2 = pae(HEADER_BYTES, message, footer, implicitAssertion);

  const valid = verify(sig, m2, publicKey);
  if (!valid) {
    return null;
  }

  return { payload: message, footer };
}

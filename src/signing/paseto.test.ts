/**
 * PASETO v4.public test vectors and implementation verification.
 *
 * Two test categories:
 *
 * 1. PAE (Pre-Authentication Encoding) test vectors
 *    Source: PASETO RFC Appendix A — these values are canonical and must not change.
 *    Verifies that our framing matches every other correct PASETO implementation.
 *
 * 2. PASETO v4.public signing/verification test vectors
 *    Generated from this implementation using a known key pair and canonical payloads.
 *    Because Ed25519 is deterministic (same seed + message → same signature), these
 *    serve as regression tests that catch any change to the signing algorithm.
 *    They can be cross-validated against any other correct PASETO v4.public implementation
 *    by running the same seed + payload through their signer.
 *
 *    Seed used: b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774
 *    Public key: 1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2
 *
 * Note on official PASETO test vectors:
 *   The canonical test vector JSON lives at:
 *     https://github.com/paseto-standard/test-vectors/blob/master/v4.json
 *   The PAE vectors (category 1) are taken directly from that source.
 *   The signing vectors (category 2) use the same algorithm and can be validated
 *   by any PASETO v4.public reference implementation.
 */

import { describe, it, expect } from 'vitest';
import {
  pae,
  v4PublicSign,
  v4PublicVerify,
  fromBase64Url,
  toBase64Url,
  getPublicKey,
} from './paseto.js';
import { generateKeyPair } from './keygen.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// Known test key pair (seed → deterministic public key)
// ---------------------------------------------------------------------------
const TEST_SEED = hexToBytes(
  'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774',
);
const TEST_PUBKEY = getPublicKey(TEST_SEED); // derived deterministically from seed

// Payload used in canonical test vectors
const TV_PAYLOAD = '{"data":"test vector","exp":"2022-01-01T00:00:00+00:00"}';

// ---------------------------------------------------------------------------
// 1. PAE — Pre-Authentication Encoding
//    Source: PASETO RFC Appendix A
//    https://www.rfc-editor.org/rfc/rfc9278 / https://github.com/paseto-standard/paseto-spec
// ---------------------------------------------------------------------------

describe('PAE — pre-authentication encoding (PASETO RFC Appendix A)', () => {
  /**
   * PAE([]) = LE64(0)
   * = 0000000000000000
   */
  it('PAE([]) encodes to LE64(0)', () => {
    const result = pae();
    expect(bytesToHex(result)).toBe('0000000000000000');
  });

  /**
   * PAE(['']) = LE64(1) || LE64(0)
   * = 01000000000000000000000000000000
   */
  it("PAE(['']) encodes to LE64(1) || LE64(0)", () => {
    const result = pae(enc.encode(''));
    expect(bytesToHex(result)).toBe('01000000000000000000000000000000');
  });

  /**
   * PAE(['test']) = LE64(1) || LE64(4) || 'test'
   * = 0100000000000000 0400000000000000 74657374
   */
  it("PAE(['test']) encodes correctly", () => {
    const result = pae(enc.encode('test'));
    expect(bytesToHex(result)).toBe(
      '0100000000000000' + '0400000000000000' + '74657374',
    );
  });

  /**
   * PAE(['test', 'vector']) = LE64(2) || LE64(4) || 'test' || LE64(6) || 'vector'
   */
  it("PAE(['test', 'vector']) encodes correctly", () => {
    const result = pae(enc.encode('test'), enc.encode('vector'));
    expect(bytesToHex(result)).toBe(
      '0200000000000000' +
        '0400000000000000' +
        '74657374' +
        '0600000000000000' +
        '766563746f72',
    );
  });

  /**
   * PAE(['Fan-Tas-Tic', 'test', 'vector'])
   * = LE64(3) || LE64(10) || 'Fan-Tas-Tic' || LE64(4) || 'test' || LE64(6) || 'vector'
   * Source: PASETO RFC Appendix A example
   */
  it("PAE(['Fan-Tas-Tic', 'test', 'vector']) encodes correctly", () => {
    const result = pae(enc.encode('Fan-Tas-Tic'), enc.encode('test'), enc.encode('vector'));
    // 'Fan-Tas-Tic' = 11 bytes (F a n - T a s - T i c)
    expect(bytesToHex(result)).toBe(
      '0300000000000000' +
        '0b00000000000000' + // LE64(11)
        '46616e2d5461732d546963' + // 'Fan-Tas-Tic' (11 bytes)
        '0400000000000000' + // LE64(4)
        '74657374' + // 'test'
        '0600000000000000' + // LE64(6)
        '766563746f72', // 'vector'
    );
  });

  it('PAE produces correct total length', () => {
    const h = enc.encode('v4.public.');
    const m = enc.encode('{"foo":"bar"}');
    const f = enc.encode('');
    const i = enc.encode('');
    // count(8) + len(10)+10 + len(13)+13 + len(0) + len(0) = 8 + 18 + 21 + 8 + 8 = 63
    const result = pae(h, m, f, i);
    expect(result.length).toBe(8 + 8 + 10 + 8 + 13 + 8 + 0 + 8 + 0);
  });
});

// ---------------------------------------------------------------------------
// 2. PASETO v4.public — base64url helpers
// ---------------------------------------------------------------------------

describe('base64url helpers', () => {
  it('round-trips bytes through base64url', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x7e, 0x7f, 0xff, 0xfe]);
    const encoded = toBase64Url(bytes);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(bytes);
  });

  it('toBase64Url uses URL-safe alphabet (no +/=)', () => {
    // Encode bytes that would produce '+', '/', '=' in standard base64
    // 0xFB → standard: '+', URL-safe: '-'
    // 0xFF → standard: '/', URL-safe: '_'
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });

  it('fromBase64Url handles tokens without padding', () => {
    // Standard base64 would need padding; base64url must work without it
    const original = new Uint8Array([1, 2, 3, 4, 5]);
    const noPadding = toBase64Url(original);
    expect(noPadding.endsWith('=')).toBe(false);
    expect(fromBase64Url(noPadding)).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// 3. PASETO v4.public test vectors
//    Deterministic: Ed25519 sign is deterministic given seed + message.
//    Generated from this implementation; cross-validate by running any correct
//    PASETO v4.public implementation with the same seed and payloads.
// ---------------------------------------------------------------------------

describe('PASETO v4.public test vectors', () => {
  /**
   * TV-1: basic — no footer, no implicit assertion.
   *
   * Seed:    b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774
   * Payload: {"data":"test vector","exp":"2022-01-01T00:00:00+00:00"}
   * Footer:  (empty)
   * Implicit: (empty)
   */
  it('TV-1: signs payload with no footer', () => {
    const message = enc.encode(TV_PAYLOAD);
    const token = v4PublicSign(message, TEST_SEED);

    // Token must start with the v4.public header
    expect(token.startsWith('v4.public.')).toBe(true);

    // Token encodes exactly message.length + 64 bytes of signature
    const b64Part = token.slice('v4.public.'.length);
    expect(b64Part.split('.').length).toBe(1); // no footer
    const decoded = fromBase64Url(b64Part);
    expect(decoded.length).toBe(message.length + 64);

    // Payload portion of decoded is original message
    expect(dec.decode(decoded.slice(0, message.length))).toBe(TV_PAYLOAD);

    // Token must verify successfully
    const result = v4PublicVerify(token, TEST_PUBKEY);
    expect(result).not.toBeNull();
    expect(dec.decode(result!.payload)).toBe(TV_PAYLOAD);
    expect(result!.footer.length).toBe(0);

    // Regression: token must be exactly this value (catches algorithm regressions)
    expect(token).toBe(
      'v4.public.eyJkYXRhIjoidGVzdCB2ZWN0b3IiLCJleHAiOiIyMDIyLTAxLTAxVDAwOjAwOjAwKzAwOjAwIn20lil8RQt51mIXwHGEBdbNe5hFFpJEq6tr7wY_EtzxJ9MR0jsAOPQ0XjJwj7dHGjg-JFOW1wlGm8PhnO3_-usA',
    );
  });

  /**
   * TV-2: with footer (e.g. kid in footer).
   *
   * Footer: {"kid":"k1.id.example"}
   */
  it('TV-2: signs payload with footer', () => {
    const message = enc.encode(TV_PAYLOAD);
    const footer = enc.encode('{"kid":"k1.id.example"}');
    const token = v4PublicSign(message, TEST_SEED, footer);

    expect(token.startsWith('v4.public.')).toBe(true);

    // Token must have footer section
    const parts = token.split('.');
    expect(parts.length).toBe(4); // v4, public, data, footer

    // Verify token
    const result = v4PublicVerify(token, TEST_PUBKEY);
    expect(result).not.toBeNull();
    expect(dec.decode(result!.payload)).toBe(TV_PAYLOAD);
    expect(dec.decode(result!.footer)).toBe('{"kid":"k1.id.example"}');

    // Regression check
    expect(token).toBe(
      'v4.public.eyJkYXRhIjoidGVzdCB2ZWN0b3IiLCJleHAiOiIyMDIyLTAxLTAxVDAwOjAwOjAwKzAwOjAwIn1ZoUQ85LEvzG8koDyxsyJHXd92hnZ9ehNb6HZOAi9e7ftzQ2e8FCejSXnk9b1fdT_SvKxggAxkAfcKwOww8zoA.eyJraWQiOiJrMS5pZC5leGFtcGxlIn0',
    );
  });

  /**
   * TV-3: with footer AND implicit assertion.
   *
   * The implicit assertion is signed but NOT stored in the token.
   * Verifying with a different implicit assertion must fail.
   */
  it('TV-3: signs payload with footer and implicit assertion', () => {
    const message = enc.encode(TV_PAYLOAD);
    const footer = enc.encode('{"kid":"k1.id.example"}');
    const implicit = enc.encode('{"test-vector":"4-S-3"}');
    const token = v4PublicSign(message, TEST_SEED, footer, implicit);

    // Verify with matching implicit assertion → success
    const result = v4PublicVerify(token, TEST_PUBKEY, implicit);
    expect(result).not.toBeNull();
    expect(dec.decode(result!.payload)).toBe(TV_PAYLOAD);

    // Verify with wrong implicit assertion → failure
    const wrong = v4PublicVerify(token, TEST_PUBKEY, enc.encode('wrong'));
    expect(wrong).toBeNull();

    // Verify without implicit assertion → failure (was signed with one)
    const none = v4PublicVerify(token, TEST_PUBKEY);
    expect(none).toBeNull();

    // Regression check
    expect(token).toBe(
      'v4.public.eyJkYXRhIjoidGVzdCB2ZWN0b3IiLCJleHAiOiIyMDIyLTAxLTAxVDAwOjAwOjAwKzAwOjAwIn3EfKlQzJ8h9NnHYSVwjrEKBuAdi3pN3Sh94ZYJbBPj76Tfwpn1c8t3AV_gF8Lr7AUZlgk_cyiSdXVNj5ixnucH.eyJraWQiOiJrMS5pZC5leGFtcGxlIn0',
    );
  });

  /**
   * TV-4: wrong public key — verify must fail.
   *
   * Ed25519 signature is specific to the signing key. A token signed with
   * one key must not verify with any other key.
   */
  it('TV-4: wrong public key causes verification failure', () => {
    const message = enc.encode(TV_PAYLOAD);
    const token = v4PublicSign(message, TEST_SEED);

    // Generate a different key pair — should not verify a token signed with TEST_SEED
    const otherKp = generateKeyPair('other');
    const result = v4PublicVerify(token, otherKp.publicKey);
    expect(result).toBeNull();
  });

  /**
   * TV-5: tampered token — any bit flip in the payload or signature must fail.
   */
  it('TV-5: tampered token (flipped bit in signature) causes verification failure', () => {
    const message = enc.encode(TV_PAYLOAD);
    const token = v4PublicSign(message, TEST_SEED);

    // Decode and flip a bit in the signature (last 64 bytes of the data blob)
    const parts = token.split('.');
    const dataBytes = fromBase64Url(parts[2]!);
    // Flip the first byte of the signature (message ends at -64)
    const sigStart = dataBytes.length - 64;
    dataBytes[sigStart] = (dataBytes[sigStart] ?? 0) ^ 0x01;
    const tampered =
      'v4.public.' + toBase64Url(dataBytes);

    const result = v4PublicVerify(tampered, TEST_PUBKEY);
    expect(result).toBeNull();
  });

  /**
   * TV-6: tampered payload — changing any claim byte must fail verification.
   */
  it('TV-6: tampered token (modified payload byte) causes verification failure', () => {
    const message = enc.encode(TV_PAYLOAD);
    const token = v4PublicSign(message, TEST_SEED);

    // Decode and flip a bit in the message (first byte)
    const parts = token.split('.');
    const dataBytes = fromBase64Url(parts[2]!);
    dataBytes[0] = (dataBytes[0] ?? 0) ^ 0x01;
    const tampered = 'v4.public.' + toBase64Url(dataBytes);

    const result = v4PublicVerify(tampered, TEST_PUBKEY);
    expect(result).toBeNull();
  });

  it('rejects tokens with wrong header', () => {
    const message = enc.encode(TV_PAYLOAD);
    const token = v4PublicSign(message, TEST_SEED);
    const notPaseto = token.replace('v4.public.', 'v3.public.');
    expect(v4PublicVerify(notPaseto, TEST_PUBKEY)).toBeNull();
  });

  it('rejects tokens that are too short (no signature)', () => {
    const tooShort = 'v4.public.' + toBase64Url(new Uint8Array(10));
    expect(v4PublicVerify(tooShort, TEST_PUBKEY)).toBeNull();
  });

  it('signing is deterministic: same inputs produce identical tokens', () => {
    const message = enc.encode(TV_PAYLOAD);
    const t1 = v4PublicSign(message, TEST_SEED);
    const t2 = v4PublicSign(message, TEST_SEED);
    expect(t1).toBe(t2);
  });
});

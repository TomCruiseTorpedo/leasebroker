/**
 * PasetoV4PublicSigner — implements the Signer contract using PASETO v4.public.
 *
 * See ADR-A for the design rationale (Ed25519 on @noble/ed25519, not the stale
 * `paseto` npm package).
 *
 * Key rotation:
 *   - The active signing key is used to issue tokens; its kid is embedded in the
 *     Lease payload (the `kid` field is part of the Lease type).
 *   - The keyring holds all trusted public keys keyed by kid, enabling the
 *     verifier to validate tokens signed under any previous rotation key.
 *
 * Usage:
 *   const kp = generateKeyPair('k1');
 *   const signer = new PasetoV4PublicSigner(kp);
 *   const token = signer.issue(lease);
 *   const result = signer.verify(token);
 */

import type { Lease, Signer, VerifyResult } from '../contract/index.js';
import type { KeyPair } from './keygen.js';
import { v4PublicSign, v4PublicVerify, fromBase64Url } from './paseto.js';

// ---------------------------------------------------------------------------
// PasetoV4PublicSigner
// ---------------------------------------------------------------------------

/**
 * PASETO v4.public implementation of the `Signer` contract.
 *
 * - `issue(lease)` → signs lease JSON as PASETO v4.public token (Ed25519)
 * - `verify(token)` → verifies signature and decodes lease; does NOT check expiry
 *
 * The kid in `lease.kid` is used to select the correct public key during
 * verification, supporting key rotation without token invalidation.
 */
export class PasetoV4PublicSigner implements Signer {
  /** Active signing key pair. */
  private readonly signingKey: KeyPair;

  /**
   * Map of kid → public key for verification.
   * Always includes the current signing key; may include rotated-out keys.
   */
  private readonly keyring: Map<string, Uint8Array>;

  /**
   * @param signingKey        Active key pair used to sign new tokens.
   * @param additionalKeys    Optional retired public keys for verifying old tokens.
   */
  constructor(
    signingKey: KeyPair,
    additionalKeys?: ReadonlyArray<{ kid: string; publicKey: Uint8Array }>,
  ) {
    this.signingKey = signingKey;
    this.keyring = new Map([[signingKey.kid, signingKey.publicKey]]);
    if (additionalKeys) {
      for (const k of additionalKeys) {
        this.keyring.set(k.kid, k.publicKey);
      }
    }
  }

  /**
   * Issue a PASETO v4.public token encoding the given lease.
   *
   * The lease is JSON-serialised and signed with the active signing key.
   * The lease's `kid` field (which should match this signer's active kid)
   * is embedded in the payload claims — no separate footer is used.
   *
   * @returns PASETO v4.public token string
   */
  issue(lease: Lease): string {
    const message = new TextEncoder().encode(JSON.stringify(lease));
    // Footer and implicit assertion are empty; kid lives in the payload claims.
    return v4PublicSign(message, this.signingKey.secretKey);
  }

  /**
   * Verify a PASETO v4.public token and decode the lease it carries.
   *
   * Verification steps:
   *   1. Validate PASETO v4.public header
   *   2. Peek at unverified payload to read `kid`
   *   3. Resolve the correct public key from the keyring
   *   4. Cryptographically verify the signature (PAE + Ed25519)
   *   5. Parse and return the verified lease
   *
   * This checks ONLY signature integrity.
   * Expiry and revocation are checked separately by the Enforcer (ADR-B).
   *
   * @returns `{ lease }` on success, or `VerifyResult` with `ok: false` on failure
   */
  verify(token: string): { lease: Lease } | VerifyResult {
    // ── 1. Header check ──────────────────────────────────────────────────────
    if (!token.startsWith('v4.public.')) {
      return { ok: false, reason: 'invalid token: wrong header' };
    }

    const parts = token.split('.');
    // Expected: ['v4', 'public', '<data>'] or ['v4', 'public', '<data>', '<footer>']
    if (parts.length < 3 || parts.length > 4) {
      return { ok: false, reason: 'invalid token: wrong number of parts' };
    }

    const dataPart = parts[2];
    if (!dataPart) {
      return { ok: false, reason: 'invalid token: empty data' };
    }

    // ── 2. Peek at unverified payload to read kid ─────────────────────────
    //    We decode the raw bytes and split off the signature so we can parse
    //    the JSON claims.  This is done BEFORE verification intentionally —
    //    the kid merely selects the verification key; if the attacker tampers
    //    with kid, the subsequent verification will fail.
    let publicKey: Uint8Array | undefined;
    try {
      const payloadAndSig = fromBase64Url(dataPart);
      if (payloadAndSig.length < 64) {
        return { ok: false, reason: 'invalid token: too short' };
      }
      const rawMessage = payloadAndSig.slice(0, -64);
      const claims = JSON.parse(Buffer.from(rawMessage).toString('utf-8')) as { kid?: string };
      const kid = claims.kid;

      if (kid !== undefined) {
        publicKey = this.keyring.get(kid);
        if (publicKey === undefined) {
          return { ok: false, reason: `invalid token: unknown kid "${kid}"` };
        }
      } else {
        // No kid in claims: fall back to the current signing key's public key
        publicKey = this.signingKey.publicKey;
      }
    } catch {
      return { ok: false, reason: 'invalid token: failed to decode claims' };
    }

    // ── 3–4. Cryptographic verification ──────────────────────────────────────
    const result = v4PublicVerify(token, publicKey);
    if (result === null) {
      return { ok: false, reason: 'invalid token: signature verification failed' };
    }

    // ── 5. Parse lease ────────────────────────────────────────────────────────
    try {
      const lease = JSON.parse(Buffer.from(result.payload).toString('utf-8')) as Lease;
      return { lease };
    } catch {
      return { ok: false, reason: 'invalid token: lease payload is not valid JSON' };
    }
  }
}

/**
 * Ed25519 key-pair generation for PASETO v4.public signing.
 *
 * Keys are managed as raw byte arrays (32-byte seed and 32-byte public key)
 * to stay close to the primitive and avoid format ambiguity.
 *
 * This module imports from paseto.ts to ensure the sha512 shim is registered
 * before any synchronous Ed25519 operations are attempted.
 */

import { utils } from '@noble/ed25519';
import { getPublicKey } from './paseto.js';

// ---------------------------------------------------------------------------
// KeyPair
// ---------------------------------------------------------------------------

/** An Ed25519 key pair with an associated key identifier for rotation. */
export type KeyPair = {
  /** 32-byte Ed25519 seed (private key material — keep secret). */
  secretKey: Uint8Array;
  /** 32-byte Ed25519 public key derived from the seed. */
  publicKey: Uint8Array;
  /**
   * Key identifier used in the `kid` field of issued leases.
   * Enables verifiers to select the correct public key during rotation.
   */
  kid: string;
};

// ---------------------------------------------------------------------------
// generateKeyPair
// ---------------------------------------------------------------------------

/**
 * Generate a fresh Ed25519 key pair for PASETO v4.public signing.
 *
 * @param kid Key identifier for rotation tracking
 * @returns KeyPair with secret key (seed), public key, and kid
 */
export function generateKeyPair(kid: string): KeyPair {
  const secretKey = utils.randomSecretKey();
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey, kid };
}

/**
 * Derive the public key from an existing seed.
 * Useful for importing externally-generated keys.
 *
 * @param secretKey 32-byte Ed25519 seed
 * @param kid Key identifier for this key
 * @returns KeyPair (without the secret key being re-generated)
 */
export function keyPairFromSeed(secretKey: Uint8Array, kid: string): KeyPair {
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey, kid };
}

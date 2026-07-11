/**
 * Signing lane barrel export.
 *
 * Provides the PASETO v4.public Signer implementation and key generation
 * utilities for the leasebroker signing lane.
 *
 * Consumer imports:
 *   import { PasetoV4PublicSigner, generateKeyPair } from './signing/index.js';
 *   import type { KeyPair } from './signing/index.js';
 *
 * Note: importing this module boots the sha512 shim that enables the
 * synchronous noble/ed25519 API.  Import this before any direct use
 * of @noble/ed25519 sync functions.
 */

// Signer implementation
export { PasetoV4PublicSigner } from './signer.js';

// Key generation utilities
export { generateKeyPair, keyPairFromSeed } from './keygen.js';
export type { KeyPair } from './keygen.js';

// Low-level PASETO v4.public primitives (useful for testing and interop)
export { pae, v4PublicSign, v4PublicVerify, toBase64Url, fromBase64Url, peekClaimsUnverified } from './paseto.js';

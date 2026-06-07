/**
 * PasetoV4PublicSigner — tests for the Signer interface contract.
 *
 * Tests:
 *   - issue-then-verify round trip (authentic token)
 *   - tampered token fails verification
 *   - wrong key fails verification
 *   - kid-based key rotation (verifier uses keyring)
 *   - malformed tokens are rejected gracefully
 */

import { describe, it, expect } from 'vitest';
import { PasetoV4PublicSigner } from './signer.js';
import { generateKeyPair, keyPairFromSeed } from './keygen.js';
import { fromBase64Url, toBase64Url } from './paseto.js';
import type { Lease } from '../contract/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeLease(overrides?: Partial<Lease>): Lease {
  return {
    id: 'lease-01',
    agentId: 'agent-alpha',
    taskId: 'task-summarise',
    capabilities: [{ kind: 'fs.read', paths: ['./data/**'] }],
    issuedAt: '2024-01-01T00:00:00Z',
    expiresAt: '2024-01-01T01:00:00Z',
    kid: 'k1',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Issue → verify round trip
// ---------------------------------------------------------------------------

describe('Signer: issue → verify round trip', () => {
  it('issues a valid token that verifies back to the original lease', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const lease = makeLease({ kid: kp.kid });

    const token = signer.issue(lease);

    expect(token).toMatch(/^v4\.public\./);

    const result = signer.verify(token);
    expect('lease' in result).toBe(true);
    if (!('lease' in result)) return;

    // All Lease fields must survive the round trip
    expect(result.lease.id).toBe(lease.id);
    expect(result.lease.agentId).toBe(lease.agentId);
    expect(result.lease.taskId).toBe(lease.taskId);
    expect(result.lease.kid).toBe(lease.kid);
    expect(result.lease.issuedAt).toBe(lease.issuedAt);
    expect(result.lease.expiresAt).toBe(lease.expiresAt);
    expect(result.lease.capabilities).toEqual(lease.capabilities);
  });

  it('issues deterministic tokens for the same lease', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const lease = makeLease({ kid: kp.kid });

    const t1 = signer.issue(lease);
    const t2 = signer.issue(lease);
    expect(t1).toBe(t2);
  });

  it('different leases produce different tokens', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);

    const t1 = signer.issue(makeLease({ kid: kp.kid, id: 'lease-A' }));
    const t2 = signer.issue(makeLease({ kid: kp.kid, id: 'lease-B' }));
    expect(t1).not.toBe(t2);
  });
});

// ---------------------------------------------------------------------------
// Tampered token must fail
// ---------------------------------------------------------------------------

describe('Signer: tampered token fails verification', () => {
  it('returns ok:false when a bit in the signature is flipped', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const token = signer.issue(makeLease({ kid: kp.kid }));

    const parts = token.split('.');
    const blob = fromBase64Url(parts[2]!);
    // Flip a bit in the signature region (last 64 bytes)
    const sigIdx = blob.length - 64;
    blob[sigIdx] = (blob[sigIdx] ?? 0) ^ 0x01;
    const tampered = 'v4.public.' + toBase64Url(blob);

    const result = signer.verify(tampered);
    expect('ok' in result).toBe(true);
    if (!('ok' in result)) return;
    expect(result.ok).toBe(false);
  });

  it('returns ok:false when a payload byte is changed', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const token = signer.issue(makeLease({ kid: kp.kid }));

    const parts = token.split('.');
    const blob = fromBase64Url(parts[2]!);
    // Flip a bit in the message (payload) region — first byte
    blob[0] = (blob[0] ?? 0) ^ 0x01;
    const tampered = 'v4.public.' + toBase64Url(blob);

    const result = signer.verify(tampered);
    expect('ok' in result).toBe(true);
    if (!('ok' in result)) return;
    expect(result.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Wrong public key must fail
// ---------------------------------------------------------------------------

describe('Signer: wrong key fails verification', () => {
  it('returns ok:false when verified with a different signer instance', () => {
    const kp1 = generateKeyPair('k1');
    const kp2 = generateKeyPair('k2');

    const signerA = new PasetoV4PublicSigner(kp1);
    const signerB = new PasetoV4PublicSigner(kp2);

    // signerA issues with kid='k1'; signerB only knows kid='k2'
    const token = signerA.issue(makeLease({ kid: kp1.kid }));
    const result = signerB.verify(token);

    expect('ok' in result).toBe(true);
    if (!('ok' in result)) return;
    expect(result.ok).toBe(false);
  });

  it('returns ok:false when kid is unknown to the verifier', () => {
    const kp1 = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp1);

    // Issue a lease with a kid not in signerB's keyring
    const token = signer.issue(makeLease({ kid: 'unknown-kid' }));
    const result = signer.verify(token);

    expect('ok' in result).toBe(true);
    if (!('ok' in result)) return;
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('unknown kid');
  });
});

// ---------------------------------------------------------------------------
// Key rotation: verifier supports multiple public keys
// ---------------------------------------------------------------------------

describe('Signer: key rotation via keyring', () => {
  it('can verify tokens signed by a retired key', () => {
    // Simulate key rotation: k1 → k2
    const hexToBytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
    const oldKp = keyPairFromSeed(
      hexToBytes('b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774'),
      'k1',
    );
    const newKp = generateKeyPair('k2');

    // Old signer (pre-rotation) issues with k1
    const oldSigner = new PasetoV4PublicSigner(oldKp);
    const oldToken = oldSigner.issue(makeLease({ kid: oldKp.kid }));

    // New signer (post-rotation, knows k2 as active + k1 as retired)
    const newSigner = new PasetoV4PublicSigner(newKp, [
      { kid: oldKp.kid, publicKey: oldKp.publicKey },
    ]);

    // Old token with kid=k1 should still verify
    const result = newSigner.verify(oldToken);
    expect('lease' in result).toBe(true);
    if (!('lease' in result)) return;
    expect(result.lease.kid).toBe('k1');

    // New token with kid=k2 should also verify
    const newToken = newSigner.issue(makeLease({ kid: newKp.kid }));
    const newResult = newSigner.verify(newToken);
    expect('lease' in newResult).toBe(true);
    if (!('lease' in newResult)) return;
    expect(newResult.lease.kid).toBe('k2');
  });
});

// ---------------------------------------------------------------------------
// Malformed token inputs are rejected gracefully
// ---------------------------------------------------------------------------

describe('Signer: malformed tokens', () => {
  it('returns ok:false for empty string', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const result = signer.verify('');
    expect('ok' in result && !result.ok).toBe(true);
  });

  it('returns ok:false for wrong header', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const result = signer.verify('v3.public.some-data');
    expect('ok' in result && !result.ok).toBe(true);
  });

  it('returns ok:false for token with only header', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    const result = signer.verify('v4.public.');
    expect('ok' in result && !result.ok).toBe(true);
  });

  it('returns ok:false for a token that is too short to contain a signature', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    // Only 10 bytes — can't hold a 64-byte signature
    const short = 'v4.public.' + toBase64Url(new Uint8Array(10));
    const result = signer.verify(short);
    expect('ok' in result && !result.ok).toBe(true);
  });

  it('returns ok:false for a JWT-formatted token', () => {
    const kp = generateKeyPair('k1');
    const signer = new PasetoV4PublicSigner(kp);
    // JWTs have exactly 3 period-separated parts but wrong header
    const result = signer.verify('eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyIn0.sighere');
    expect('ok' in result && !result.ok).toBe(true);
  });
});

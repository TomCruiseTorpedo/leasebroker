/**
 * A2A lease extension — declaration, negotiation, and carriage helpers (ADR-F).
 *
 * Implements the wire shapes of docs/a2a-lease-extension-v1.md as plain JSON
 * manipulation. Deliberately free of any A2A protocol client dependency —
 * the gateway consumer (gatewarden) owns the wire; this repo owns the
 * semantics (ADR-F).
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Extension identity
// ---------------------------------------------------------------------------

/**
 * The stable extension URI (profile §Versioning: breaking changes bump /v1).
 * Agents declare it in the card; clients echo it in `A2A-Extensions` and
 * key the token payload in message metadata with it.
 */
export const LEASE_EXT_URI =
  'https://github.com/TomCruiseTorpedo/leasebroker/a2a/lease/v1';

// ---------------------------------------------------------------------------
// Payload schema (profile §Carriage)
// ---------------------------------------------------------------------------

/** v1 payload carried at message.metadata[LEASE_EXT_URI]. */
export const LeaseExtensionPayloadSchema = z
  .object({ token: z.string().min(1) })
  .loose(); // unknown extra keys are ignored (profile §9)

export type LeaseExtensionPayload = z.infer<typeof LeaseExtensionPayloadSchema>;

// ---------------------------------------------------------------------------
// Declaration (profile §Declaration)
// ---------------------------------------------------------------------------

/** The AgentExtension entry for `capabilities.extensions[]` (A2A §4.4.4). */
export interface LeaseCardExtension {
  uri: string;
  description: string;
  required: boolean;
}

/**
 * Build the card declaration entry. `required` defaults to true — the
 * deny-by-default posture (an awareness gate, NOT a security boundary;
 * token validation is always the boundary — profile §2).
 */
export function leaseCardExtension(options: { required?: boolean } = {}): LeaseCardExtension {
  return {
    uri: LEASE_EXT_URI,
    description:
      'Requests are governed by capability leases; present a lease token in message metadata keyed by this URI.',
    required: options.required ?? true,
  };
}

// ---------------------------------------------------------------------------
// Negotiation (profile §Negotiation)
// ---------------------------------------------------------------------------

/**
 * Parse an `A2A-Extensions` header value (comma-separated URIs) into a list.
 * Tolerates null/undefined (no header) and surrounding whitespace.
 */
export function parseExtensionsHeader(headerValue: string | null | undefined): string[] {
  if (headerValue === null || headerValue === undefined) return [];
  return headerValue
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

/** True when the declared extension URIs include the lease extension. */
export function declaresLeaseExtension(declared: readonly string[]): boolean {
  return declared.includes(LEASE_EXT_URI);
}

// ---------------------------------------------------------------------------
// Carriage (profile §Carriage)
// ---------------------------------------------------------------------------

/** The message fields this extension reads/writes (a tolerant subset). */
export interface LeaseCarryingMessage {
  extensions?: string[];
  metadata?: Record<string, unknown> | null;
}

/**
 * Return a copy of `message` carrying `token` per the profile: payload at
 * metadata[LEASE_EXT_URI] and the URI listed in `extensions`. Pure — the
 * input is not mutated.
 */
export function attachLeaseToken<M extends LeaseCarryingMessage>(
  message: M,
  token: string,
): M {
  const extensions = [...new Set([...(message.extensions ?? []), LEASE_EXT_URI])];
  const metadata = {
    ...(message.metadata ?? {}),
    [LEASE_EXT_URI]: { token } satisfies LeaseExtensionPayload,
  };
  return { ...message, extensions, metadata };
}

/**
 * Extract the lease token from message metadata, or undefined when absent
 * or malformed (a malformed payload is treated as no token — the gate then
 * rejects with "no lease token presented", which is the safe direction).
 */
export function extractLeaseToken(
  metadata: Record<string, unknown> | null | undefined,
): string | undefined {
  const raw = metadata?.[LEASE_EXT_URI];
  const parsed = LeaseExtensionPayloadSchema.safeParse(raw);
  return parsed.success ? parsed.data.token : undefined;
}

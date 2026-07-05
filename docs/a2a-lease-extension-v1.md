# A2A Lease Extension v1 — profile

Extension URI (the stable identifier agents declare and clients echo):

    https://github.com/TomCruiseTorpedo/leasebroker/a2a/lease/v1

This document is the normative profile for carrying leasebroker capability
leases over the A2A protocol (spec v1.0.1). It follows A2A's own extension
pattern (§4.6): the URI is declared in the Agent Card, negotiated via the
`A2A-Extensions` header, and the payload rides message metadata keyed by the
URI. Status: v1, shipped with `leasebroker` ≥ 0.2.

## 1. What it does

A2A `securitySchemes` carry *standing* credentials (OAuth2, API keys).
Nothing in core A2A attenuates what a delegated agent may DO. This extension
carries a **PASETO v4.public capability lease** (time-bounded, narrowly
scoped, signed — the leasebroker `Lease` claims) per message, so an enforcing
peer can apply deny-by-default least-privilege to every action a remote
client asks of it.

## 2. Declaration (Agent Card)

An enforcing agent declares the extension at `capabilities.extensions[]`
(A2A §4.4.4 — NOT top-level):

    { "uri": "https://github.com/TomCruiseTorpedo/leasebroker/a2a/lease/v1",
      "description": "Requests are governed by capability leases; present a lease token in message metadata.",
      "required": true }

`required: true` makes the extension an awareness gate: clients that do not
declare support MUST be rejected with `ExtensionSupportRequiredError`
(A2A §3.3.4; JSON-RPC `-32008`, HTTP 400, gRPC `FAILED_PRECONDITION`).
This is deny-by-default against extension-unaware clients ONLY — a hostile
client can echo the URI without honouring it, so the security boundary is
always the token validation in step 4, never the negotiation.

## 3. Negotiation (client)

The client lists the URI in the `A2A-Extensions` header (HTTP; gRPC metadata
key `a2a-extensions`) on every request, and SHOULD include it in
`Message.extensions[]`. Servers SHOULD echo activated extensions in the
response header, but that echo is advisory (A2A guide, SHOULD-strength) —
never build correctness on it.

## 4. Carriage (message)

The lease token rides message metadata keyed by the extension URI, matching
A2A §4.6.2's extension-payload pattern:

    "message": {
      "extensions": ["https://github.com/TomCruiseTorpedo/leasebroker/a2a/lease/v1"],
      "metadata": {
        "https://github.com/TomCruiseTorpedo/leasebroker/a2a/lease/v1": {
          "token": "v4.public.eyJpZCI6..."
        }
      }
    }

## 5. Context binding

A2A has no initialize handshake and no transport session (unlike MCP, where
leasebroker binds `sessionId → token` at initialize). Binding is therefore
per-CONTEXT: the first message of a `contextId` that presents a token binds
that context; later messages in the same context may omit the token. A
message presenting a DIFFERENT token for an already-bound context is
rejected — no mid-context token swapping.

## 6. Deny ladder (enforcing side)

Evaluated in order, first failure wins:

1. **Extension support** — client did not declare the URI →
   `ExtensionSupportRequiredError` (`-32008` / 400 / `FAILED_PRECONDITION`).
   Protocol-level rejection; no task is created.
2. **Lease** — no token presented (and none bound to the context), token
   conflicts with the context binding, or `Enforcer.check(token, action)`
   fails (signature → expiry → revocation → scope → spend, the ADR-B
   pipeline, unchanged) → task terminal state **`rejected`** (pinned
   convention; see §7).
3. **Veto** — no token, but a pending human-approval request exists for the
   context (the ADR-D `veto-required` path: no lease is issued until the
   operator approves) → task interrupted state **`auth-required`**
   (A2A §7.6 In-Task Authorization). Operator approval (`leasebroker
   approve`) is the out-of-band credential per §7.6.1; the client then
   presents the newly issued token. Operator `deny` → `rejected`.
4. Otherwise → allow; bind the context if newly presented; audit `use`.

## 7. Task-state pins (interop convention, not spec)

A2A mandates no denial terminal state. This profile pins:

| Event | A2A TaskState |
|---|---|
| lease denied / veto denied | `rejected` |
| veto pending | `auth-required` |
| client gives up while pending | `CancelTask` → `canceled` (forced fallback; success not guaranteed per spec) |

Conforming peers MAY map denial to `failed`/`canceled`; consumers of foreign
agents should match on terminal-ness, not the specific state.

## 8. Security notes

- **Single-hop guarantee only.** No A2A clause obliges an intermediary agent
  to propagate `Message.metadata` downstream — this profile protects the
  client→enforcer hop. For chains, A2A §7.6.3 applies: in-band credentials
  are visible to every hop and SHOULD be bound to the originating agent.
  `Lease.agentId` provides exactly that binding, and a v4.public token is
  integrity-signed, not secret — chain exposure is a REPLAY concern,
  mitigated by expiry + revocation + agentId scope.
- **Log hygiene.** A2A §13.4: logs MUST NOT include credentials. The token
  is body-borne — treat it as a secret in audit sinks (store a hash, never
  the raw token).
- **Awareness gate ≠ security boundary.** See §2. The enforcer validates
  every token on every action regardless of negotiation.

## 9. Versioning

Breaking payload/negotiation changes bump the URI suffix (`/v2`). The v1
payload is exactly `{ "token": string }` — unknown extra keys are ignored.

#!/usr/bin/env bash
#
# Govern-engine drift guard.
#
# The govern engine is VENDORED IDENTICALLY between two repos:
#   - leasebroker                  (canonical product)
#   - gatewarden/packages/govern   (@gatewarden/govern; vendored copy)
#
# Until the engine is extracted into one shared package, the files listed below
# MUST stay byte-identical across both repos. This check fails if a local edit
# changed any of them without updating the manifest — forcing a conscious
# "I changed the shared engine, now mirror it to the other repo" step.
#
# It exists because the lane had NO guard at all and had already drifted across
# twelve files, including a real security gap: gatewarden re-chained a stored
# audit log on load, which laundered tamper evidence, while leasebroker had
# already fixed exactly that. Manual mirroring is a documented intention. This
# is the invariant.
#
# TWO MODES, AND THE SECOND IS NOT OPTIONAL:
#
#   (default)  Every listed file matches THIS repo's recorded hash.
#   --cross    This repo's manifest is byte-identical to the PEER repo's.
#
# The default mode alone proves "internally consistent", NOT "identical across
# repos". Edit a shared file in repo A, run --update in A only, commit: A's
# files match A's manifest so A is green, and B was never touched so B is green
# too. The engines diverge and both repos pass. --cross closes that.
#
# Intentional change to the engine:
#   1) apply the SAME edit in the other repo,
#   2) regenerate the manifest in BOTH: bash scripts/check-sync-govern.sh --update
#   3) bash scripts/check-sync-govern.sh --cross
#
# This script is byte-identical in both repos; it works out which side it is on
# from the package name rather than carrying a per-repo constant that could
# itself be mirrored wrong.
#
# ---------------------------------------------------------------------------
# WHAT IS DELIBERATELY *NOT* IN THE MANIFEST, AND WHY
# ---------------------------------------------------------------------------
# Absence from this list is a decision, not an oversight. Do not "fix" these by
# adding them — the guard would then fail permanently on a difference that is
# supposed to exist.
#
#   src/index.ts, src/audit/index.ts, src/cli/index.ts
#     Barrels and command registration. They differ BECAUSE the module sets
#     differ: leasebroker additionally ships anchor/, dashboard/,
#     audit/otel-exporter.ts, audit/stored-chain consumers, and
#     audit/workflow-report.ts, which gatewarden does not vendor. A barrel is
#     derived from what exists beside it, so it cannot be byte-identical while
#     the module sets legitimately differ.
#
#   src/cli/commands/audit.ts
#     Mixed file. Its chain-integrity behaviour IS shared and was reconciled to
#     match leasebroker exactly; its `--by-workflow` and `--verify-anchor`
#     options depend on leasebroker-only modules and are absent here. Because
#     the file cannot be byte-identical, the shared half is protected by tests
#     (src/cli/state.test.ts) rather than by this manifest. If you change the
#     chain-integrity path, change it in BOTH.
#
#   Test files
#     Not listed, matching the score guard's convention. They are still
#     mirrored by hand when they cover shared behaviour.
#
#   Leasebroker-only modules (anchor/, dashboard/, audit/otel-exporter.ts,
#   audit/workflow-report.ts, cli/commands/anchor.ts)
#     Not vendored into gatewarden at all. Deliberate product divergence.
set -euo pipefail
cd "$(dirname "$0")/.."   # package/repo root, so src/... paths resolve
MANIFEST="scripts/govern-engine.sha256"
FILES=(
  # contract — the shared type and schema surface everything else depends on
  src/contract/index.ts src/contract/interfaces.ts src/contract/schemas.ts src/contract/types.ts
  # signing — PASETO v4.public issuance and verification
  src/signing/index.ts src/signing/keygen.ts src/signing/paseto.ts src/signing/signer.ts
  # policy — rule evaluation
  src/policy/engine.ts src/policy/index.ts src/policy/loader.ts
  # broker — issuance orchestration
  src/broker/broker.ts src/broker/index.ts
  # enforce — per-call verification, the in-path enforcement point
  src/enforce/enforcer.ts src/enforce/index.ts src/enforce/proxy.ts
  # audit — hash chain, state stores, and stored-chain tamper verification
  src/audit/audit-sink.ts src/audit/hash.ts src/audit/pending-store.ts
  src/audit/revocation-list.ts src/audit/spend-ledger.ts src/audit/stored-chain.ts
  # a2a — protocol binding and gating
  src/a2a/binding.ts src/a2a/extension.ts src/a2a/gate.ts src/a2a/index.ts
  # cli — shared state handling and the commands that carry no divergent options
  src/cli/state.ts src/cli/wire.ts
  src/cli/commands/approve.ts src/cli/commands/deny.ts src/cli/commands/pending.ts
  src/cli/commands/policy.ts src/cli/commands/request.ts src/cli/commands/revoke.ts
  src/cli/commands/serve.ts
)

# ---------------------------------------------------------------------------
# --update — regenerate this repo's manifest
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--update" ]]; then
  shasum -a 256 "${FILES[@]}" > "$MANIFEST"
  echo "govern-engine manifest updated: $MANIFEST"
  echo "REMINDER: run --update in the peer repo too, then --cross to prove they match."
  exit 0
fi

# ---------------------------------------------------------------------------
# --cross — assert this manifest equals the peer repo's manifest
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--cross" ]]; then
  SELF_NAME="$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -1)"
  case "$SELF_NAME" in
    leasebroker)
      PEER_LABEL="gatewarden/packages/govern"
      PEER_LOCAL="../gatewarden/packages/govern/$MANIFEST"
      PEER_URL="https://raw.githubusercontent.com/TomCruiseTorpedo/gatewarden/main/packages/govern/scripts/govern-engine.sha256"
      ;;
    @gatewarden/govern)
      PEER_LABEL="leasebroker"
      PEER_LOCAL="../../../leasebroker/$MANIFEST"
      PEER_URL="https://raw.githubusercontent.com/TomCruiseTorpedo/leasebroker/main/scripts/govern-engine.sha256"
      ;;
    *)
      echo "ERROR: --cross cannot identify this repo (package name '$SELF_NAME')." >&2
      echo "Expected 'leasebroker' or '@gatewarden/govern'." >&2
      exit 1
      ;;
  esac

  PEER_FILE=""
  PEER_SOURCE=""
  CLEANUP=""

  # Local peer checkout (a dev machine with both repos side by side) — a plain
  # file comparison, no network. PEER_MANIFEST overrides for unusual layouts.
  if [[ -n "${PEER_MANIFEST:-}" && -f "${PEER_MANIFEST}" ]]; then
    PEER_FILE="$PEER_MANIFEST"
    PEER_SOURCE="PEER_MANIFEST=$PEER_MANIFEST"
  elif [[ -f "$PEER_LOCAL" ]]; then
    PEER_FILE="$PEER_LOCAL"
    PEER_SOURCE="local checkout $PEER_LOCAL"
  else
    # CI checks out ONE repo and has no peer working copy, so a local diff is
    # unimplementable there. Both repos are public, so the peer's manifest is
    # fetchable unauthenticated — no token, no secret in a public workflow.
    CLEANUP="$(mktemp)"
    PEER_FILE="$CLEANUP"
    PEER_SOURCE="$PEER_URL"
    trap 'rm -f "$CLEANUP"' EXIT
    if ! curl -fsSL --max-time 30 "$PEER_URL" -o "$PEER_FILE"; then
      {
        echo "ERROR: could not fetch the $PEER_LABEL manifest from $PEER_URL"
        echo "Failing the check rather than passing it. A fetch error treated as"
        echo "a pass is precisely the silent-green failure --cross exists to stop."
      } >&2
      exit 1
    fi
    # A 200 carrying an HTML error page is not a manifest. Require the shasum
    # shape (64 hex digits, two spaces, a path) on the first line.
    if ! head -1 "$PEER_FILE" | grep -Eq '^[0-9a-f]{64}  '; then
      {
        echo "ERROR: fetched $PEER_LABEL manifest is not a shasum manifest."
        echo "First line: $(head -1 "$PEER_FILE")"
      } >&2
      exit 1
    fi
  fi

  if diff -u "$MANIFEST" "$PEER_FILE" > /dev/null; then
    echo "govern manifest identical to $PEER_LABEL (via $PEER_SOURCE)"
    exit 0
  fi

  {
    echo "ERROR: govern manifest DIFFERS from $PEER_LABEL."
    echo "  this repo: $SELF_NAME:$MANIFEST"
    echo "  peer:      $PEER_LABEL (via $PEER_SOURCE)"
    echo
    diff -u "$MANIFEST" "$PEER_FILE" || true
    echo
    echo "Two causes, and they need different fixes:"
    echo "  1. The shared engine really has diverged. Mirror the edit, run"
    echo "     --update in BOTH repos, and land both commits."
    echo "  2. You pushed one half of a two-repo change and the peer has not"
    echo "     landed yet. This red is the detector working, not a bug — it"
    echo "     says the mirror is incomplete. Land the other half; the window"
    echo "     should be minutes, not days."
    echo
    echo "Do NOT soften this to a warning to avoid the transient red. A"
    echo "non-blocking warning is a documented intention, which is the exact"
    echo "thing this guard replaces."
  } >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# default — every listed file matches this repo's recorded hash
# ---------------------------------------------------------------------------

if shasum -a 256 -c "$MANIFEST"; then
  echo "govern engine in sync with manifest"
else
  {
    echo "ERROR: govern engine drifted from the committed manifest."
    echo "The engine is vendored identically in leasebroker and gatewarden/packages/govern."
    echo "If the change is intentional: mirror it to the other repo, run"
    echo "  bash scripts/check-sync-govern.sh --update"
    echo "in BOTH, then prove they match with"
    echo "  bash scripts/check-sync-govern.sh --cross"
  } >&2
  exit 1
fi

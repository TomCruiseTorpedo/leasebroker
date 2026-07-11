#!/usr/bin/env node
/**
 * leasebroker CLI — entry point.
 *
 * Commands:
 *   request    Submit a lease request
 *   approve    Approve a pending (veto-required) request
 *   deny       Deny a pending request
 *   pending    List pending requests
 *   revoke     Revoke an active lease
 *   serve      Start the MCP enforce proxy
 *   policy     View/manage policy rules
 *   audit      View the audit log
 *
 * Global options:
 *   --state-dir <path>   State directory (default: .leasebroker/)
 *   --help, -h           Show help
 *   --version, -v        Show version
 */

import { parseArgs } from 'node:util';
import { createRequire } from 'node:module';
import { loadState, resolveStateDir } from './state.js';
import { cmdRequest } from './commands/request.js';
import { cmdApprove } from './commands/approve.js';
import { cmdDeny } from './commands/deny.js';
import { cmdPending } from './commands/pending.js';
import { cmdRevoke } from './commands/revoke.js';
import { cmdServe } from './commands/serve.js';
import { cmdPolicy } from './commands/policy.js';
import { cmdAudit } from './commands/audit.js';
import { cmdAnchor } from './commands/anchor.js';

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

function getVersion(): string {
  try {
    const req = createRequire(import.meta.url);
    const pkg = req('../../package.json') as { version: string };
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

const HELP = `
leasebroker — local-first capability lease broker for AI agents

USAGE
  leasebroker <command> [options]

COMMANDS
  request     Submit a lease request (reads JSON from --request or stdin)
  approve     Approve a pending (veto-required) request
  deny        Deny a pending request
  pending     List all pending requests
  revoke      Revoke an active lease
  serve       Start the enforce proxy fronting a downstream MCP server
  policy      View or load policy rules
  audit       View the audit log
  anchor      Anchor the audit chain tip to public OpenTimestamps calendars

GLOBAL OPTIONS
  --state-dir <path>   State directory (default: .leasebroker/ in cwd)
                       Override with LEASEBROKER_STATE_DIR env var
  --help, -h           Show this help
  --version, -v        Show version

COMMAND HELP
  leasebroker <command> --help

EXAMPLES
  # Request a lease
  leasebroker request --request '{"agentId":"a1","taskId":"t1","capabilities":[{"kind":"fs.read","paths":["./data/**"]}],"requestedDurationMs":3600000}'

  # List pending requests
  leasebroker pending

  # Approve a pending request
  leasebroker approve <reqId>

  # Revoke a lease
  leasebroker revoke <leaseId>

  # Start the proxy (with a downstream MCP server)
  leasebroker serve --downstream-cmd node --downstream-args '["./server.js"]'

  # View audit log
  leasebroker audit --last 20

  # Anchor the audit chain tip externally (e.g. from a daily cron job)
  leasebroker anchor
`.trim();

const COMMAND_HELP: Record<string, string> = {
  request: `
leasebroker request — submit a lease request

USAGE
  leasebroker request [--request <json>] [--rules-file <path>]
  echo '<json>' | leasebroker request

OPTIONS
  --request <json>     LeaseRequest as JSON string
  --rules-file <path>  Path to policy rules JSON file

OUTPUT (JSON)
  { "type": "granted", "token": "...", "leaseId": "..." }
  { "type": "pending", "reqId": "..." }
  { "type": "denied", "reason": "..." }

EXAMPLE
  leasebroker request --request '{"agentId":"a1","taskId":"t1","capabilities":[{"kind":"fs.read","paths":["./data/**"]}],"requestedDurationMs":3600000}'
`.trim(),

  approve: `
leasebroker approve — approve a pending request

USAGE
  leasebroker approve <reqId>

EXAMPLE
  leasebroker approve 550e8400-e29b-41d4-a716-446655440000
`.trim(),

  deny: `
leasebroker deny — deny a pending request

USAGE
  leasebroker deny <reqId>

EXAMPLE
  leasebroker deny 550e8400-e29b-41d4-a716-446655440000
`.trim(),

  pending: `
leasebroker pending — list pending requests awaiting approval

USAGE
  leasebroker pending

OUTPUT
  JSON array of { reqId, request } objects
`.trim(),

  revoke: `
leasebroker revoke — revoke an active lease

USAGE
  leasebroker revoke <leaseId>

EXAMPLE
  leasebroker revoke 550e8400-e29b-41d4-a716-446655440000
`.trim(),

  serve: `
leasebroker serve — start the enforce proxy

USAGE
  leasebroker serve [--downstream-cmd <cmd>] [--downstream-args <json>] [--rules-file <path>]

OPTIONS
  --downstream-cmd <cmd>      Command to run the downstream MCP server
  --downstream-args <json>    JSON array of args (default: [])
  --rules-file <path>         Path to policy rules JSON file

EXAMPLE
  leasebroker serve --downstream-cmd npx --downstream-args '["@modelcontextprotocol/server-filesystem","./data"]'
`.trim(),

  policy: `
leasebroker policy — view or manage policy rules

SUBCOMMANDS
  leasebroker policy show [--rules-file <path>]   Print current rules
  leasebroker policy load --rules-file <path>     Load rules into state dir

OPTIONS
  --rules-file <path>   Path to a JSON file containing an array of PolicyRule objects

EXAMPLE
  leasebroker policy show
  leasebroker policy load --rules-file ./policy.json
`.trim(),

  audit: `
leasebroker audit — view the audit log

USAGE
  leasebroker audit [--last <n>] [--type <type>] [--verify] [--verify-anchor] [--by-workflow]

OPTIONS
  --last <n>       Show only the last N events
  --type <type>    Filter by event type (request|decision|issuance|use|denial|revocation)
  --verify         Verify hash chain integrity only (no output)
  --verify-anchor  Verify chain integrity AND external anchor proofs (local, no network)
  --by-workflow    Trust-per-workflow report: per-taskId request/grant/deny/revoke/use
                   counts with approval and revocation rates (a view over existing data)

EXAMPLE
  leasebroker audit --last 20
  leasebroker audit --type issuance
  leasebroker audit --verify
  leasebroker audit --verify-anchor
  leasebroker audit --by-workflow
`.trim(),

  anchor: `
leasebroker anchor — anchor the audit chain tip to public OpenTimestamps calendars

The tip hash already commits to the entire chain, so one small proof file
witnesses the whole log up to that point — externally, independent of this
machine. Meant to run on a schedule (cron/launchd); idempotent per tip.

USAGE
  leasebroker anchor [--calendar <url> ...]
  leasebroker anchor --upgrade
  leasebroker anchor --status

OPTIONS
  --calendar <url>  Calendar server to submit to (repeatable; default: the
                    public alice/bob/finney calendars)
  --upgrade         Collect completed Bitcoin attestations for pending anchors
                    (calendars need ~1-2 hours after submission)
  --status          Report local anchor verification as JSON (no network)

STATE
  Proofs live in <state-dir>/anchors/*.ots (standard OpenTimestamps format,
  verifiable with the reference ots client) with an anchors.jsonl index.

EXAMPLE
  # Daily cron: anchor, and collect yesterday's attestations
  leasebroker anchor --upgrade && leasebroker anchor
`.trim(),
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  // Handle top-level --help / --version before subcommand parsing.
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    console.log(HELP);
    return;
  }

  if (argv[0] === '--version' || argv[0] === '-v') {
    console.log(getVersion());
    return;
  }

  const command = argv[0];
  const rest = argv.slice(1);

  // Command-level help.
  if (rest.includes('--help') || rest.includes('-h')) {
    const helpText = command !== undefined ? COMMAND_HELP[command] : undefined;
    if (helpText) {
      console.log(helpText);
    } else {
      console.log(HELP);
    }
    return;
  }

  // Parse global --state-dir from rest before command-specific parsing.
  let stateDir: string | undefined;
  const stateDirIdx = rest.indexOf('--state-dir');
  if (stateDirIdx !== -1 && stateDirIdx + 1 < rest.length) {
    stateDir = rest[stateDirIdx + 1];
  }

  const resolvedStateDir = resolveStateDir(stateDir);

  switch (command) {
    case 'request': {
      const { values } = parseArgs({
        args: rest,
        options: {
          request: { type: 'string' as const },
          'rules-file': { type: 'string' as const },
          'state-dir': { type: 'string' as const },
        },
        strict: false,
      }) as { values: Record<string, string | undefined> };
      const state = loadState(resolvedStateDir);
      await cmdRequest(state, {
        request: values['request'],
        rulesFile: values['rules-file'],
      });
      break;
    }

    case 'approve': {
      const { positionals } = parseArgs({
        args: rest,
        options: { 'state-dir': { type: 'string' as const }, 'rules-file': { type: 'string' as const } },
        allowPositionals: true,
        strict: false,
      });
      const reqId = positionals[0];
      if (!reqId) {
        console.error('Error: approve requires a <reqId> argument');
        process.exit(1);
      }
      const state = loadState(resolvedStateDir);
      cmdApprove(state, { reqId });
      break;
    }

    case 'deny': {
      const { positionals } = parseArgs({
        args: rest,
        options: { 'state-dir': { type: 'string' as const }, 'rules-file': { type: 'string' as const } },
        allowPositionals: true,
        strict: false,
      });
      const reqId = positionals[0];
      if (!reqId) {
        console.error('Error: deny requires a <reqId> argument');
        process.exit(1);
      }
      const state = loadState(resolvedStateDir);
      cmdDeny(state, { reqId });
      break;
    }

    case 'pending': {
      const state = loadState(resolvedStateDir);
      cmdPending(state);
      break;
    }

    case 'revoke': {
      const { positionals } = parseArgs({
        args: rest,
        options: { 'state-dir': { type: 'string' as const } },
        allowPositionals: true,
        strict: false,
      });
      const leaseId = positionals[0];
      if (!leaseId) {
        console.error('Error: revoke requires a <leaseId> argument');
        process.exit(1);
      }
      const state = loadState(resolvedStateDir);
      cmdRevoke(state, { leaseId });
      break;
    }

    case 'serve': {
      const { values } = parseArgs({
        args: rest,
        options: {
          'downstream-cmd': { type: 'string' as const },
          'downstream-args': { type: 'string' as const },
          'rules-file': { type: 'string' as const },
          'state-dir': { type: 'string' as const },
        },
        strict: false,
      }) as { values: Record<string, string | undefined> };
      let downstreamArgs: string[] | undefined;
      const rawDownstreamArgs = values['downstream-args'];
      if (rawDownstreamArgs) {
        try {
          downstreamArgs = JSON.parse(rawDownstreamArgs) as string[];
        } catch {
          console.error('Error: --downstream-args must be a JSON array of strings');
          process.exit(1);
        }
      }
      const state = loadState(resolvedStateDir);
      await cmdServe(state, {
        downstreamCmd: values['downstream-cmd'],
        downstreamArgs,
        rulesFile: values['rules-file'],
      });
      break;
    }

    case 'policy': {
      // policy has subcommands: show, load
      const sub = rest[0] ?? 'show';
      const policyRest = sub === 'show' || sub === 'load' ? rest.slice(1) : rest;
      const subcommand = (sub === 'show' || sub === 'load') ? sub : 'show';
      const { values } = parseArgs({
        args: policyRest,
        options: {
          'rules-file': { type: 'string' as const },
          'state-dir': { type: 'string' as const },
        },
        strict: false,
      }) as { values: Record<string, string | undefined> };
      const state = loadState(resolvedStateDir);
      cmdPolicy(state, {
        subcommand,
        rulesFile: values['rules-file'],
      });
      break;
    }

    case 'audit': {
      const { values } = parseArgs({
        args: rest,
        options: {
          last: { type: 'string' as const },
          type: { type: 'string' as const },
          verify: { type: 'boolean' as const },
          'verify-anchor': { type: 'boolean' as const },
          'by-workflow': { type: 'boolean' as const },
          'state-dir': { type: 'string' as const },
        },
        strict: false,
      }) as { values: Record<string, string | boolean | undefined> };
      const state = loadState(resolvedStateDir);
      cmdAudit(state, {
        last: values['last'] !== undefined ? parseInt(values['last'] as string, 10) : undefined,
        type: values['type'] as Parameters<typeof cmdAudit>[1]['type'],
        verify: values['verify'] as boolean | undefined,
        verifyAnchor: values['verify-anchor'] as boolean | undefined,
        byWorkflow: values['by-workflow'] as boolean | undefined,
      });
      break;
    }

    case 'anchor': {
      const { values } = parseArgs({
        args: rest,
        options: {
          upgrade: { type: 'boolean' as const },
          status: { type: 'boolean' as const },
          calendar: { type: 'string' as const, multiple: true },
          'state-dir': { type: 'string' as const },
        },
        strict: false,
      }) as { values: Record<string, string | boolean | string[] | undefined> };
      const state = loadState(resolvedStateDir);
      await cmdAnchor(state, {
        upgrade: values['upgrade'] as boolean | undefined,
        status: values['status'] as boolean | undefined,
        calendars: values['calendar'] as string[] | undefined,
      });
      break;
    }

    default: {
      console.error(`Unknown command: ${command}\n`);
      console.log(HELP);
      process.exit(1);
    }
  }
}

main().catch((err: unknown) => {
  console.error('Fatal error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});

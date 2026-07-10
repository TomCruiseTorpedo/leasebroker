/**
 * `leasebroker serve` — start the MCP enforce proxy.
 *
 * Starts a leasebroker proxy server that fronts a downstream MCP server.
 * The proxy intercepts tools/call, enforces lease scope, and forwards
 * permitted calls to the downstream.
 *
 * The proxy server listens on stdio (the default MCP transport):
 * - Proxy server side: StdioServerTransport (reads stdin, writes stdout)
 * - Downstream: spawned as a subprocess via StdioClientTransport
 *
 * Clients connect to the proxy by:
 * 1. Starting the proxy as a subprocess
 * 2. Sending an MCP initialize with _meta['x-lease-token'] set to their lease token
 *
 * Usage:
 *   leasebroker serve --downstream-cmd node --downstream-args '["./server.js"]'
 *   leasebroker serve --downstream-cmd npx --downstream-args '["@modelcontextprotocol/server-filesystem","./data"]'
 *
 * Options:
 *   --downstream-cmd <cmd>      Command to run the downstream MCP server
 *   --downstream-args <json>    JSON array of args for the downstream command
 *   --rules-file <path>         Path to policy rules JSON (optional)
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { LeasebrokerProxy } from '../../enforce/index.js';
import type { ToolActionResolver } from '../../enforce/index.js';
import type { Action } from '../../contract/index.js';
import type { CliState } from '../state.js';
import { saveState } from '../state.js';
import { wireComponents } from '../wire.js';

export interface ServeOptions {
  downstreamCmd?: string;
  downstreamArgs?: string[];
  rulesFile?: string;
}

/**
 * Default tool-to-action resolver for filesystem MCP tools.
 *
 * Maps the standard @modelcontextprotocol/server-filesystem tools to Actions.
 * Tools not in this map are forwarded transparently (no enforcement).
 */
function defaultToolActionResolver(
  toolName: string,
  toolArgs: Record<string, unknown>,
): Action | undefined {
  switch (toolName) {
    case 'read_file':
    case 'read_multiple_files':
    case 'list_directory':
    case 'directory_tree':
    case 'get_file_info':
    case 'search_files': {
      const path = (toolArgs['path'] as string | undefined) ?? '';
      return { kind: 'fs.read', path };
    }
    case 'write_file':
    case 'create_directory':
    case 'move_file':
    case 'edit_file': {
      const path = (toolArgs['path'] as string | undefined) ?? '';
      return { kind: 'fs.write', path };
    }
    default:
      return undefined;
  }
}

export async function cmdServe(state: CliState, opts: ServeOptions): Promise<void> {
  // A long-running proxy persists its session's audit events at shutdown; on a
  // tampered log that save is refused, so the session's events would be lost.
  // Fail closed at startup instead.
  if (state.auditIntegrity === 'tampered') {
    process.stderr.write(
      'refusing to start: audit log fails stored hash-chain verification — possible tampering. ' +
        'Archive the audit log manually to resume with a fresh chain.\n',
    );
    process.exit(1);
  }

  const { enforcer } = wireComponents(state, opts.rulesFile);

  const toolActionResolver: ToolActionResolver = defaultToolActionResolver;

  const proxy = new LeasebrokerProxy({
    enforcer,
    audit: state.auditSink,
    toolActionResolver,
  });

  const serverTransport = new StdioServerTransport();

  if (opts.downstreamCmd) {
    // Real downstream: spawn the downstream MCP server as a subprocess.
    const downstreamTransport = new StdioClientTransport({
      command: opts.downstreamCmd,
      args: opts.downstreamArgs ?? [],
    });

    await proxy.connect(serverTransport, downstreamTransport);
  } else {
    // No downstream specified: start an in-process stub downstream.
    // This is useful for testing that the proxy boots without crashing.
    const { Server } = await import('@modelcontextprotocol/sdk/server/index.js');
    const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');

    const stubServer = new Server(
      { name: 'leasebroker-stub-downstream', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    const [proxyClientTransport, stubServerTransport] = InMemoryTransport.createLinkedPair();

    await stubServer.connect(stubServerTransport);
    await proxy.connect(serverTransport, proxyClientTransport);
  }

  // Persist any audit events written during the session on clean exit.
  const cleanup = (): void => {
    saveState(state);
    proxy.close().catch(() => {/* ignore */});
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  // Log to stderr so it doesn't pollute the MCP stdio channel.
  process.stderr.write('leasebroker proxy ready\n');
}

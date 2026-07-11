/**
 * LeasebrokerProxy — MCP proxy server with lease enforcement (ADR-B).
 *
 * Architecture:
 *   Client → [proxy server side] → Enforcer → [proxy client side] → Downstream MCP server
 *
 * Session binding:
 *   The client presents a lease token at the MCP initialize handshake by including
 *   it in `params._meta['x-lease-token']`.  The proxy records `sessionId → token`
 *   and uses it to enforce every subsequent tools/call in that session.
 *
 *   `extra.sessionId` is populated by the SDK from `transport.sessionId`
 *   (available in SDK v1.x low-level setRequestHandler).
 *
 * Unknown tools:
 *   If the `toolActionResolver` returns `undefined` for a tool (i.e. the tool
 *   has no mapped Action), it is forwarded to the downstream transparently —
 *   no enforcement is applied.
 *
 * Usage:
 *   const proxy = new LeasebrokerProxy({ enforcer, audit, toolActionResolver });
 *   await proxy.connect(clientSideTransport, downstreamTransport);
 *   // ...
 *   await proxy.close();
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  CallToolRequestSchema,
  InitializeRequestSchema,
  LATEST_PROTOCOL_VERSION,
  ListToolsRequestSchema,
  SUPPORTED_PROTOCOL_VERSIONS,
} from '@modelcontextprotocol/sdk/types.js';
import type { Action, AuditEvent, AuditSink, Enforcer } from '../contract/index.js';
import { peekClaimsUnverified } from '../signing/paseto.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Maps a tool name + arguments to an Action for enforcement.
 * Return `undefined` to pass the call through without enforcement.
 */
export type ToolActionResolver = (
  toolName: string,
  toolArgs: Record<string, unknown>,
) => Action | undefined;

export interface ProxyServerOptions {
  /** Enforcer that gates every mapped tool call. */
  enforcer: Enforcer;
  /** Audit sink for use and denial events. */
  audit: AuditSink;
  /**
   * Maps tool calls to Actions for enforcement.
   * If omitted, or when it returns `undefined`, calls are forwarded transparently.
   */
  toolActionResolver?: ToolActionResolver;
}

// ---------------------------------------------------------------------------
// LeasebrokerProxy
// ---------------------------------------------------------------------------

export class LeasebrokerProxy {
  /** Low-level MCP server that clients connect to. */
  private readonly server: Server;
  /** MCP client that connects to the downstream MCP server. */
  private readonly downstreamClient: Client;
  /**
   * Session token map: transport-level sessionId → lease token.
   * Populated at initialize handshake.
   */
  private readonly sessionTokens = new Map<string, string>();

  constructor(private readonly opts: ProxyServerOptions) {
    this.server = new Server(
      { name: 'leasebroker-proxy', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    this.downstreamClient = new Client(
      { name: 'leasebroker-proxy-downstream', version: '1.0.0' },
      { capabilities: {} },
    );

    this.installHandlers();
  }

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  private installHandlers(): void {
    // Override initialize to capture lease token and return a valid result.
    //
    // The SDK's Server constructor pre-installs _oninitialize as the initialize
    // handler; setRequestHandler silently replaces it here (the SDK docs say
    // "this will replace any previous request handler for the same method").
    this.server.setRequestHandler(InitializeRequestSchema, (request, extra) => {
      // Extract lease token from _meta if present.
      const rawMeta = request.params._meta as Record<string, unknown> | undefined;
      const token = rawMeta?.['x-lease-token'];

      if (typeof token === 'string' && extra.sessionId !== undefined) {
        this.sessionTokens.set(extra.sessionId, token);
      }

      // Negotiate protocol version (same logic as the SDK's _oninitialize).
      const requested = request.params.protocolVersion;
      const agreed = SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
        ? requested
        : LATEST_PROTOCOL_VERSION;

      return {
        protocolVersion: agreed,
        capabilities: { tools: {} },
        serverInfo: { name: 'leasebroker-proxy', version: '1.0.0' },
      };
    });

    // tools/list — delegate to downstream.
    this.server.setRequestHandler(ListToolsRequestSchema, async (_req, _extra) => {
      const result = await this.downstreamClient.listTools();
      // Cast: result is structurally a ListToolsResult; the index signature from
      // the SDK's generic Client return type is wider than needed but compatible.
      return result as unknown as { tools: (typeof result)['tools'] };
    });

    // tools/call — enforce, then delegate or deny.
    this.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const toolName = request.params.name;
      const toolArgs = request.params.arguments ?? {};

      const action = this.opts.toolActionResolver?.(toolName, toolArgs);

      // Unknown tool → forward transparently (no enforcement).
      if (action === undefined) {
        const result = await this.downstreamClient.callTool({
          name: toolName,
          arguments: toolArgs,
        });
        return result as unknown as { content: (typeof result)['content'] };
      }

      // Look up the lease token bound to this session.
      const sessionId = extra.sessionId;
      const token =
        sessionId !== undefined ? this.sessionTokens.get(sessionId) : undefined;

      if (token === undefined) {
        this.appendEvent('denial', { toolName, reason: 'no lease token bound to session' });
        return this.denyResult('no lease token bound to session');
      }

      // Attribution fields for the audit trail (workflow report joins on
      // these). Unverified peek — fine for `use` (check() passes right after,
      // so the claims are signature-backed) and advisory-only for denials
      // (a forged token mis-attributes its own denial, nothing else).
      const claims = peekClaimsUnverified(token);
      const claimLeaseId = typeof claims?.['id'] === 'string' ? claims['id'] : undefined;
      const claimTaskId = typeof claims?.['taskId'] === 'string' ? claims['taskId'] : undefined;

      // Run the enforcer.
      const result = this.opts.enforcer.check(token, action);

      if (!result.ok) {
        const reason = result.reason ?? 'enforcement denied';
        this.appendEvent(
          'denial',
          { toolName, reason, action, ...(claimTaskId !== undefined ? { taskId: claimTaskId } : {}) },
          claimLeaseId,
        );
        return this.denyResult(reason);
      }

      // Permitted: emit use event and forward.
      this.appendEvent(
        'use',
        { toolName, action, ...(claimTaskId !== undefined ? { taskId: claimTaskId } : {}) },
        claimLeaseId,
      );
      const downstream = await this.downstreamClient.callTool({
        name: toolName,
        arguments: toolArgs,
      });
      return downstream as unknown as { content: (typeof downstream)['content'] };
    });
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Connect the proxy.  The downstream is connected first so it is ready before
   * any client requests arrive.
   *
   * @param clientTransport   Transport that clients connect to (proxy server side).
   * @param downstreamTransport Transport to the real downstream MCP server (proxy client side).
   */
  async connect(
    clientTransport: Transport,
    downstreamTransport: Transport,
  ): Promise<void> {
    await this.downstreamClient.connect(downstreamTransport);
    await this.server.connect(clientTransport);
  }

  async close(): Promise<void> {
    await this.server.close();
    await this.downstreamClient.close();
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private denyResult(
    reason: string,
  ): { content: Array<{ type: 'text'; text: string }>; isError: true } {
    return {
      content: [{ type: 'text', text: `denied: ${reason}` }],
      isError: true,
    };
  }

  private appendEvent(
    type: AuditEvent['type'],
    detail: Record<string, unknown>,
    leaseId?: string,
  ): void {
    const event: AuditEvent = {
      type,
      at: new Date().toISOString(),
      ...(leaseId !== undefined ? { leaseId } : {}),
      detail,
      prevHash: '',
      hash: '',
    };
    this.opts.audit.append(event);
  }
}

/**
 * fixtures/mock-api-server.ts
 *
 * A deterministic, offline mock API MCP server for the spend-cap demo.
 *
 * Tools:
 *   call_api   { endpoint }                      → http.call action
 *   charge_api { endpoint, currency, amount }    → spend action
 *
 * Neither tool enforces any restrictions by itself — all enforcement
 * is provided by the leasebroker proxy layer (LeasebrokerProxy).
 * The RED demo shows that without the proxy, all calls succeed regardless
 * of endpoint or amount.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a fresh mock API MCP server instance.
 * Connect it to a transport via `server.connect(transport)`.
 */
export function createMockApiServer(): Server {
  const server = new Server(
    { name: 'mock-api-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // tools/list — declare the two available tools.
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      {
        name: 'call_api',
        description: 'Call an API endpoint (no spend, just an HTTP-style call).',
        inputSchema: {
          type: 'object' as const,
          properties: {
            endpoint: { type: 'string', description: 'The API endpoint to call (host/path).' },
          },
          required: ['endpoint'],
        },
      },
      {
        name: 'charge_api',
        description: 'Make a paid API call that accrues spend.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            endpoint: { type: 'string', description: 'The API endpoint to call.' },
            currency: { type: 'string', description: 'ISO 4217 currency code (e.g. USD).' },
            amount: {
              type: 'number',
              description: 'Amount to charge in integer minor units (e.g. cents).',
            },
          },
          required: ['endpoint', 'currency', 'amount'],
        },
      },
    ],
  }));

  // tools/call — echo back success (deterministic, no real network).
  server.setRequestHandler(CallToolRequestSchema, (req) => {
    const name = req.params.name;
    const args = req.params.arguments ?? {};

    if (name === 'call_api') {
      const endpoint = String(args['endpoint'] ?? '');
      return {
        content: [{ type: 'text' as const, text: `call_api → ${endpoint}: 200 OK (mock)` }],
      };
    }

    if (name === 'charge_api') {
      const endpoint = String(args['endpoint'] ?? '');
      const currency = String(args['currency'] ?? 'USD');
      const amount = Number(args['amount'] ?? 0);
      return {
        content: [
          {
            type: 'text' as const,
            text: `charge_api → ${endpoint}: charged ${amount} ${currency} (mock)`,
          },
        ],
      };
    }

    return {
      content: [{ type: 'text' as const, text: `unknown tool: ${name}` }],
      isError: true,
    };
  });

  return server;
}

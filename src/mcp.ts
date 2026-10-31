// The MCP surface: exactly two tools, `send_email` and `ping`.
//
// Uses the low-level `Server` (not McpServer): errors thrown from a CallTool
// handler as `{ code, message }` become JSON-RPC errors with that exact code
// and message.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Config } from "./config";
import { buildEmail, redactConfigValues } from "./mail";
import type { Mailer } from "./smtp";

export interface ToolDeps {
  cfg: Config;
  mailer: Mailer;
  /** Take one rate-limit token; false when exhausted. */
  take: () => Promise<boolean>;
  /** Cloudflare colo serving the request, if known. */
  colo: string | null;
  /** Label of the connection, sent as X-MCP-Client. */
  client: string;
}

const INVALID_REQUEST = -32600;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

const TOOLS = [
  {
    name: "send_email",
    description: "Send a plain text email.",
    inputSchema: {
      type: "object" as const,
      properties: {
        to: { type: "string", description: "Recipient email address." },
        subject: { type: "string", description: "Subject line." },
        body: { type: "string", description: "Plain text message body." },
      },
      required: ["to", "subject", "body"],
    },
  },
  {
    name: "ping",
    description: "Health check that reports server time and timing.",
    inputSchema: {
      type: "object" as const,
      properties: {
        check_mail: { type: "boolean", description: "Also verify that the mail connection works." },
        client_time: { type: "string", description: "Current client time as a timestamp, to measure delay." },
      },
    },
  },
];

const rpcError = (code: number, message: string) => Object.assign(new Error(message), { code });
const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });

export function createMcpServer(deps: ToolDeps): Server {
  const { cfg, mailer, take, colo, client } = deps;
  const server = new Server({ name: "mail", version: "1.0.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  async function takeOrThrow() {
    if (!(await take())) throw rpcError(INVALID_REQUEST, "email rate limit exceeded for this minute");
  }

  async function sendEmail(args: Record<string, unknown>) {
    const { to, subject, body } = args;
    if (typeof to !== "string" || typeof subject !== "string" || typeof body !== "string") {
      throw rpcError(INVALID_PARAMS, "to, subject and body must be strings");
    }
    await takeOrThrow();
    if (cfg.maxBodyBytes !== null && new TextEncoder().encode(body).length > cfg.maxBodyBytes) {
      throw rpcError(INVALID_REQUEST, "message body exceeds size limit");
    }
    try {
      await mailer.send(buildEmail(cfg, to, subject, body, client));
    } catch (e) {
      throw rpcError(INTERNAL_ERROR, redactConfigValues(cfg, e instanceof Error ? e.message : String(e)));
    }
    return text("Email sent.");
  }

  async function ping(args: Record<string, unknown>) {
    const start = Date.now();
    const now = new Date();
    const out: Record<string, unknown> = { status: "ok", server_time: now.toISOString(), colo };
    const clientMs = typeof args.client_time === "string" ? Date.parse(args.client_time) : NaN;
    let mail: { ok: boolean; ms: number } | undefined;
    if (args.check_mail === true) {
      await takeOrThrow();
      const t0 = Date.now();
      let ok = true;
      try {
        await mailer.verify();
      } catch {
        ok = false;
      }
      mail = { ok, ms: Date.now() - t0 };
    }
    out.handler_ms = Math.max(0, Date.now() - start);
    out.received_after_ms = Number.isNaN(clientMs) ? null : now.getTime() - clientMs;
    if (mail) out.mail = mail;
    return text(JSON.stringify(out));
  }

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    switch (req.params.name) {
      case "send_email":
        return sendEmail(args);
      case "ping":
        return ping(args);
      default:
        throw rpcError(INVALID_PARAMS, `unknown tool: ${req.params.name}`);
    }
  });

  return server;
}

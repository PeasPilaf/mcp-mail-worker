// Shared harness for the Worker suites (run inside workerd by
// @cloudflare/vitest-plugin, with real KV and Durable Object bindings).
//
// * `baseVars()` is the canonical configuration. Its values are deliberately
//   distinctive so suites can grep responses for them and prove that no
//   configuration value ever reaches the LLM.
// * `FakeMailer` replaces SMTP. It records every `OutgoingEmail` the
//   Worker hands to the mailer, and can be told to fail.
// * `worker(vars)` builds a fresh handler via `createHandler({ mailerFactory,
//   limiterName })` with a unique rate-limiter name, so each test gets its
//   own bucket. Requests go through the handler's real `fetch`, i.e. through
//   the OAuth provider, the auth checks and the MCP transport.
//
// Wire conventions (MCP Streamable HTTP, stateless): `POST /mcp`,
// `Content-Type: application/json`, `Accept: application/json,
// text/event-stream`, `MCP-Protocol-Version: 2025-06-18`. No initialize
// handshake or session id is needed before `tools/call`. Responses may be
// JSON or SSE; `parseRpc` accepts both.

import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { expect } from "vitest";
import { createHandler } from "../../src/index";
import type { Mailer } from "../../src/smtp";
import type { OutgoingEmail } from "../../src/mail";

export const PUBLIC = "https://mail-mcp.example.test";
export const TOKEN = "tok-9f8e7d6c5b4a-0123456789abcdef-operator";
/** sha256(TOKEN), lowercase hex: the only form of the token the Worker stores. */
export const TOKEN_SHA256 = "e25f862e705d3adc1f1d6200306efdaed0815b2dd0a94b89066618e5542609e7";
export const PASSWORD = "pw-s3cr3t-zz-smtp-password";
export const USERNAME = "smtp-login@sender.example";
export const FROM = "relay-bot@sender.example";
export const SMTP_HOST = "smtp.hidden-host.example";
export const ALICE = "alice@example.com";
/** Stored in MIXED case: canonical delivery must reproduce this spelling. */
export const BOB = "Bob.Builder@Example.org";
/** Third entry, so seeing it used proves MAIL_DEFAULT_TO was honoured. */
export const DEFAULT_TO = "inbox@example.net";
export const OFF_LIST = "mallory@evil.example";
/** Distinctive rate, searched for in responses. */
export const PER_MIN = "37";

export type Vars = Record<string, string>;

export function baseVars(): Vars {
  return {
    MCP_AUTH_TOKEN_SHA256: TOKEN_SHA256,
    PUBLIC_URL: PUBLIC,
    SMTP_HOST,
    SMTP_PORT: "465",
    SMTP_USERNAME: USERNAME,
    SMTP_PASSWORD: PASSWORD,
    SMTP_FROM: FROM,
    EMAIL_PER_MIN: PER_MIN,
    MAIL_ALLOW_TO: `${ALICE},${BOB},${DEFAULT_TO}`,
    MAIL_DEFAULT_TO: DEFAULT_TO,
  };
}

export function varsWith(overrides: Vars): Vars {
  return { ...baseVars(), ...overrides };
}

export function varsWithout(...keys: string[]): Vars {
  const v = baseVars();
  for (const k of keys) delete v[k];
  return v;
}

/** Every configured value the LLM must never see. */
export function secretNeedles(): string[] {
  return [TOKEN, TOKEN_SHA256, PASSWORD, USERNAME, FROM, SMTP_HOST, ALICE, BOB, BOB.toLowerCase(), DEFAULT_TO, "hidden-host", "sender.example"];
}

// ---------------------------------------------------------------------------
// Fake mailer
// ---------------------------------------------------------------------------

export class FakeMailer implements Mailer {
  sent: OutgoingEmail[] = [];
  verifies = 0;
  /** When set, send()/verify() reject with this message. */
  failWith: string | null = null;

  async send(email: OutgoingEmail): Promise<void> {
    if (this.failWith) throw new Error(this.failWith);
    this.sent.push(structuredClone(email));
  }

  async verify(): Promise<void> {
    this.verifies++;
    if (this.failWith) throw new Error(this.failWith);
  }
}

/** Typical SMTP failure text, deliberately containing config values that
 *  must be redacted before reaching the LLM. */
export const SMTP_FAILURE = `550 5.1.1 mailbox unavailable (relay ${SMTP_HOST} rejected ${USERNAME})`;

// ---------------------------------------------------------------------------
// Worker harness
// ---------------------------------------------------------------------------

export interface TestWorker {
  mailer: FakeMailer;
  vars: Vars;
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /** Authenticated JSON-RPC; returns the whole envelope. */
  rpc(method: string, params?: unknown, bearerToken?: string): Promise<any>;
  sendEmail(to: string, subject: string, body: string): Promise<any>;
  ping(args?: Record<string, unknown>): Promise<any>;
  listTools(): Promise<any>;
}

let nextId = 1;

export function worker(vars: Vars = baseVars(), opts: { limiterName?: string; mailer?: FakeMailer } = {}): TestWorker {
  const mailer = opts.mailer ?? new FakeMailer();
  const handler = createHandler({
    mailerFactory: () => mailer,
    limiterName: opts.limiterName ?? crypto.randomUUID(),
  });
  const testEnv = { ...env, ...vars } as unknown as Env;

  const doFetch = async (path: string, init?: RequestInit) => {
    const ctx = createExecutionContext();
    const res = await handler.fetch!(new Request(`${PUBLIC}${path}`, init) as any, testEnv, ctx);
    await waitOnExecutionContext(ctx);
    return res as unknown as Response;
  };

  const self: TestWorker = {
    mailer,
    vars,
    fetch: doFetch,
    async rpc(method, params = {}, bearerToken = TOKEN) {
      const id = nextId++;
      const res = await doFetch("/mcp", mcpInit({ jsonrpc: "2.0", id, method, params }, bearerToken));
      expect(res.status, `JSON-RPC ${method} should be HTTP 200`).toBe(200);
      const envelope = await parseRpc(res);
      expect(envelope.id).toBe(id);
      return envelope;
    },
    sendEmail(to, subject, body) {
      return self.rpc("tools/call", { name: "send_email", arguments: { to, subject, body } });
    },
    ping(args = {}) {
      return self.rpc("tools/call", { name: "ping", arguments: args });
    },
    async listTools() {
      const e = await self.rpc("tools/list");
      expect(e.error, JSON.stringify(e)).toBeUndefined();
      return e.result;
    },
  };
  return self;
}

export function mcpInit(body: unknown, bearerToken?: string | null, extra: Record<string, string> = {}): RequestInit {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": "2025-06-18",
    ...extra,
  };
  if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;
  return { method: "POST", headers, body: JSON.stringify(body) };
}

export async function parseRpc(res: Response): Promise<any> {
  const text = await res.text();
  if ((res.headers.get("content-type") ?? "").startsWith("text/event-stream")) {
    let found: any;
    for (const line of text.split("\n")) {
      if (!line.startsWith("data:")) continue;
      try {
        const v = JSON.parse(line.slice(5).trim());
        if (v.id !== undefined) found = v;
      } catch {}
    }
    if (!found) throw new Error(`no JSON-RPC response in SSE: ${text}`);
    return found;
  }
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

export const INVALID_REQUEST = -32600;
export const INTERNAL_ERROR = -32603;

/** The ONLY acceptable send_email success: one text item "Email sent.". */
export function expectSent(envelope: any) {
  expect(envelope.error, JSON.stringify(envelope)).toBeUndefined();
  expect(envelope.result.isError ?? false).toBe(false);
  expect(envelope.result.content).toEqual([{ type: "text", text: "Email sent." }]);
}

/** A JSON-RPC error (not a tool result with isError). */
export function expectRpcError(envelope: any, code: number, message: string) {
  expect(envelope.result, JSON.stringify(envelope)).toBeUndefined();
  expect(envelope.error.code).toBe(code);
  expect(envelope.error.message).toBe(message);
}

export function expectNoSecrets(text: string, what: string) {
  for (const n of secretNeedles()) expect(text.includes(n), `${what} leaks ${n}`).toBe(false);
}

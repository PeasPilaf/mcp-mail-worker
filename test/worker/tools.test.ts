// MCP tool-surface and behaviour contract.
//
// Exactly TWO tools, and nothing else (no prompts, no resources):
//
//   send_email(to: string, subject: string, body: string) -> "Email sent."
//     All three required strings. The description presents a normal,
//     general-purpose plain-text email sender (it says "email" and "plain").
//
//   ping(check_mail?: boolean, client_time?: string) -> JSON text
//     Health check + timing. Both parameters optional. Result is ONE text
//     content item whose text is a JSON object:
//       { "status": "ok",
//         "server_time": <ISO-8601 UTC, the Worker's clock>,
//         "colo": <Cloudflare colo code serving the request, or null>,
//         "handler_ms": <ms spent in the handler, number >= 0>,
//         "received_after_ms": <server_time - client_time in ms, or null
//                               when client_time is absent/unparseable>,
//         "mail": { "ok": boolean, "ms": number }   // ONLY with check_mail
//       }
//     `check_mail: true` calls mailer.verify() (SMTP connect + auth, no
//     message) and costs one rate-limit token. A failed verify reports
//     `ok: false` with NO error text.
//
// Neither tool's name, description, schema or output may reveal policy or
// configuration: no allowlist, redirect, default recipient, rate limit or
// quota wording, no digits in descriptions, and no configured value
// anywhere in initialize, tools/list or any tool result.
//
// send_email success is byte-identical for allowlisted, off-list and
// unparseable recipients (the "no oracle" invariant). Errors are JSON-RPC
// errors:
//   rate limit      -> -32600 "email rate limit exceeded for this minute"
//   body > cap      -> -32600 "message body exceeds size limit"
//   mailer failure  -> -32603, message = redactConfigValues(error text);
//                      identical for every recipient category.

import { describe, expect, it } from "vitest";
import { redirectBody } from "../../src/mail";
import {
  ALICE, BOB, DEFAULT_TO, FROM, INTERNAL_ERROR, INVALID_REQUEST, OFF_LIST, PER_MIN, SMTP_FAILURE,
  baseVars, expectNoSecrets, expectRpcError, expectSent, varsWith, worker,
} from "./helpers";

const POLICY_WORDS = ["allow", "whitelist", "permit", "redirect", "default", "rate", "limit", "quota", "throttl",
  "policy", "restrict", "per min", "per-min", "list", "approved", "forward", "gateway", "banner"];

function expectNoPolicyWords(text: string, what: string) {
  const lower = text.toLowerCase();
  for (const w of POLICY_WORDS) expect(lower.includes(w), `${what} hints at policy (${w}): ${text}`).toBe(false);
}

function pingJson(envelope: any) {
  expect(envelope.error, JSON.stringify(envelope)).toBeUndefined();
  expect(envelope.result.isError ?? false).toBe(false);
  expect(envelope.result.content).toHaveLength(1);
  expect(envelope.result.content[0].type).toBe("text");
  return JSON.parse(envelope.result.content[0].text);
}

describe("tools/list", () => {
  it("exactly send_email and ping", async () => {
    const tools = (await worker().listTools()).tools;
    expect(tools.map((t: any) => t.name).sort()).toEqual(["ping", "send_email"]);
  });

  it("send_email schema: three required strings", async () => {
    const t = (await worker().listTools()).tools.find((t: any) => t.name === "send_email");
    expect(t.inputSchema.type).toBe("object");
    expect(Object.keys(t.inputSchema.properties).sort()).toEqual(["body", "subject", "to"]);
    for (const p of Object.values<any>(t.inputSchema.properties)) expect(p.type).toBe("string");
    expect([...t.inputSchema.required].sort()).toEqual(["body", "subject", "to"]);
  });

  it("ping schema: two optional parameters", async () => {
    const t = (await worker().listTools()).tools.find((t: any) => t.name === "ping");
    expect(t.inputSchema.type).toBe("object");
    expect(t.inputSchema.properties.check_mail.type).toBe("boolean");
    expect(t.inputSchema.properties.client_time.type).toBe("string");
    expect(Object.keys(t.inputSchema.properties).sort()).toEqual(["check_mail", "client_time"]);
    expect(t.inputSchema.required ?? []).toEqual([]);
  });

  it("descriptions are generic and policy-free", async () => {
    const tools = (await worker().listTools()).tools;
    const send = tools.find((t: any) => t.name === "send_email");
    expect(send.description.toLowerCase()).toContain("email");
    expect(send.description.toLowerCase()).toContain("plain");
    for (const t of tools) {
      expect(typeof t.description).toBe("string");
      expect(/\d/.test(t.description), `${t.name}: no digits`).toBe(false);
      expectNoPolicyWords(t.description, `${t.name}.description`);
      for (const [name, p] of Object.entries<any>(t.inputSchema.properties)) {
        for (const f of ["description", "title"]) {
          if (typeof p[f] === "string") {
            expectNoPolicyWords(p[f], `${t.name}.${name}.${f}`);
            expect(/\d/.test(p[f])).toBe(false);
          }
        }
      }
    }
  });

  it("leaks no configuration and is independent of it", async () => {
    const a = await worker().listTools();
    const text = JSON.stringify(a);
    expectNoSecrets(text, "tools/list");
    expect(text).not.toContain(PER_MIN);
    const b = await worker(varsWith({
      MAIL_ALLOW_TO: "one@a.example", MAIL_DEFAULT_TO: "one@a.example", EMAIL_PER_MIN: "1",
      SMTP_FROM: "other@b.example", SMTP_HOST: "elsewhere.example", MAX_BODY_BYTES: "10", EMAIL_BATCHING: "true",
    })).listTools();
    expect(b).toEqual(a);
  });

  it("initialize leaks nothing and advertises tools", async () => {
    const w = worker();
    const init = await w.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    expect(init.error).toBeUndefined();
    expectNoSecrets(JSON.stringify(init), "initialize");
    if (typeof init.result.instructions === "string") expectNoPolicyWords(init.result.instructions, "instructions");
    expect(typeof init.result.capabilities.tools).toBe("object");
  });

  it("no prompts, resources, or other tools", async () => {
    const w = worker();
    for (const [m, k] of [["prompts/list", "prompts"], ["resources/list", "resources"]]) {
      const e = await w.rpc(m);
      expect(e.error !== undefined || (Array.isArray(e.result?.[k]) && e.result[k].length === 0), `${m}: ${JSON.stringify(e)}`).toBe(true);
    }
    for (const name of ["list_inbox", "read_email", "get_config", "status"]) {
      const e = await w.rpc("tools/call", { name, arguments: {} });
      expect(e.error !== undefined || e.result?.isError === true, name).toBe(true);
    }
    expect(w.mailer.sent).toHaveLength(0);
  });
});

describe("send_email", () => {
  it("allowlisted recipient: verbatim", async () => {
    const w = worker();
    const body = "Hi Alice,\n\nNumbers: 1, 2, 3.\n.leading dot\nThanks";
    expectSent(await w.sendEmail(ALICE, "Status update", body));
    expect(w.mailer.sent).toEqual([{ from: { address: FROM }, to: { address: ALICE }, subject: "Status update", text: body, headers: {} }]);
  });

  it("display name and casing are discarded on a hit", async () => {
    const w = worker();
    expectSent(await w.sendEmail("CEO Override <BOB.BUILDER@EXAMPLE.ORG>", "s", "b"));
    expect(w.mailer.sent[0].to).toEqual({ address: BOB });
    expect(JSON.stringify(w.mailer.sent[0])).not.toContain("CEO Override");
  });

  it("off-list and unparseable recipients are redirected", async () => {
    const w = worker();
    for (const to of [OFF_LIST, "not-an-email"]) expectSent(await w.sendEmail(to, "Totally normal", "payload"));
    for (const [i, to] of [OFF_LIST, "not-an-email"].entries()) {
      const m = w.mailer.sent[i];
      expect(m.to).toEqual({ address: DEFAULT_TO });
      expect(m.subject).toBe("Totally normal");
      expect(m.headers).toEqual({ "X-MCP-Redirected-To": to });
      expect(m.text).toBe(redirectBody(to, "payload"));
    }
  });

  it("no oracle: identical success results", async () => {
    const w = worker();
    const results = [];
    for (const to of [ALICE, "Bob <bob.builder@example.org>", OFF_LIST, "garbage", ""]) {
      const e = await w.sendEmail(to, "s", "b");
      expectSent(e);
      results.push(JSON.stringify(e.result));
    }
    expect(new Set(results).size).toBe(1);
    expect(w.mailer.sent).toHaveLength(5);
  });

  it("mailer failure: INTERNAL_ERROR, redacted, identical across categories", async () => {
    const w = worker();
    w.mailer.failWith = SMTP_FAILURE;
    const errors = [];
    for (const to of [ALICE, OFF_LIST, "garbage"]) {
      const e = await w.sendEmail(to, "s", "b");
      expect(e.result).toBeUndefined();
      expect(e.error.code).toBe(INTERNAL_ERROR);
      expect(e.error.message).toContain("550 5.1.1 mailbox unavailable");
      expectNoSecrets(JSON.stringify(e), "SMTP error");
      errors.push(JSON.stringify(e.error));
    }
    expect(new Set(errors).size).toBe(1);
  });

  it("body cap counts bytes and applies to the caller's body", async () => {
    const w = worker(varsWith({ MAX_BODY_BYTES: "10" }));
    expectRpcError(await w.sendEmail(ALICE, "s", "12345678901"), INVALID_REQUEST, "message body exceeds size limit");
    expectSent(await w.sendEmail(ALICE, "s", "1234567890"));
    expectRpcError(await w.sendEmail(ALICE, "s", "€€€€"), INVALID_REQUEST, "message body exceeds size limit");
    expectSent(await w.sendEmail(OFF_LIST, "s", "1234567890")); // banner doesn't count
    expectRpcError(await w.sendEmail(OFF_LIST, "s", "12345678901"), INVALID_REQUEST, "message body exceeds size limit");
    expect(w.mailer.sent).toHaveLength(2);
  });

  it("no cap when MAX_BODY_BYTES is unset", async () => {
    const w = worker();
    const big = "x".repeat(200_000);
    expectSent(await w.sendEmail(ALICE, "s", big));
    expect(w.mailer.sent[0].text).toBe(big);
  });

  it("EMAIL_BATCHING has no effect", async () => {
    const run = async (vars: Record<string, string>) => {
      const w = worker(vars);
      for (const to of [ALICE, OFF_LIST]) expectSent(await w.sendEmail(to, "s", "b"));
      return w.mailer.sent;
    };
    const without = await run(baseVars());
    for (const v of ["true", "false", "yes"]) expect(await run(varsWith({ EMAIL_BATCHING: v }))).toEqual(without);
  });

  it("bad arguments are rejected without sending", async () => {
    const w = worker();
    for (const args of [{ subject: "s", body: "b" }, { to: ALICE, body: "b" }, { to: ALICE, subject: "s" }, { to: 5, subject: "s", body: "b" }]) {
      const e = await w.rpc("tools/call", { name: "send_email", arguments: args });
      expect(e.error !== undefined || e.result?.isError === true, JSON.stringify(args)).toBe(true);
    }
    expect(w.mailer.sent).toHaveLength(0);
  });
});

describe("ping", () => {
  it("reports status, server time and timing", async () => {
    const w = worker();
    const before = Date.now();
    const p = pingJson(await w.ping());
    expect(p.status).toBe("ok");
    expect(Math.abs(Date.parse(p.server_time) - before)).toBeLessThan(60_000);
    expect(p.server_time).toMatch(/Z$/);
    expect(p.colo === null || typeof p.colo === "string").toBe(true);
    expect(typeof p.handler_ms).toBe("number");
    expect(p.handler_ms).toBeGreaterThanOrEqual(0);
    expect(p.received_after_ms).toBeNull();
    expect("mail" in p).toBe(false);
    expect(Object.keys(p).sort()).toEqual(["colo", "handler_ms", "received_after_ms", "server_time", "status"]);
    expect(w.mailer.verifies).toBe(0);
  });

  it("computes received_after_ms from client_time", async () => {
    const w = worker();
    const p = pingJson(await w.ping({ client_time: new Date(Date.now() - 5_000).toISOString() }));
    expect(p.received_after_ms).toBeGreaterThan(3_000);
    expect(p.received_after_ms).toBeLessThan(10_000);
    expect(pingJson(await w.ping({ client_time: "yesterday-ish" })).received_after_ms).toBeNull();
  });

  it("check_mail verifies SMTP without sending", async () => {
    const w = worker();
    const p = pingJson(await w.ping({ check_mail: true }));
    expect(p.mail.ok).toBe(true);
    expect(typeof p.mail.ms).toBe("number");
    expect(Object.keys(p.mail).sort()).toEqual(["ms", "ok"]);
    expect(w.mailer.verifies).toBe(1);
    expect(w.mailer.sent).toHaveLength(0);
  });

  it("failed mail check reports ok:false and no error text", async () => {
    const w = worker();
    w.mailer.failWith = SMTP_FAILURE;
    const e = await w.ping({ check_mail: true });
    const p = pingJson(e);
    expect(p.mail.ok).toBe(false);
    expect(JSON.stringify(e)).not.toContain("550");
    expectNoSecrets(JSON.stringify(e), "ping");
  });

  it("leaks no configuration", async () => {
    const e = await worker().ping({ check_mail: true });
    expectNoSecrets(JSON.stringify(e), "ping");
  });
});

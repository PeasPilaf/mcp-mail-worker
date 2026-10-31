// Authentication contract.
//
// The Worker is an OAuth 2.1 authorization server + protected resource,
// built on @cloudflare/workers-oauth-provider, with the MCP endpoint at
// `/mcp` as the only protected route.
//
// The operator token is never stored server-side. The Worker holds only
// MCP_AUTH_TOKEN_SHA256 (set by `npm run rotate-token`); a presented token
// is hashed with SHA-256 and compared to it in constant time
// (crypto.subtle.timingSafeEqual). Presenting the hash itself must fail.
//
// Two ways in:
//   * Static bearer: `Authorization: Bearer <token>` (the model Code, the
//     API's MCP connector).
//   * OAuth (vendor.example custom connectors): discovery -> dynamic client
//     registration -> /authorize -> /token, authorization code + PKCE S256.
//     The `/authorize` page is ours: an HTML form where the operator types
//     the token once. Right token -> provider.completeAuthorization ->
//     302 back to the client. Wrong token -> 401 page, no redirect.
//
// Rules:
//   * `/mcp` without valid credentials -> 401, EMPTY body, with a
//     `WWW-Authenticate` header naming the resource metadata URL. No tool
//     logic runs (nothing sent, no rate-limit token spent).
//   * `/authorize` serves only redirect URIs on OAUTH_REDIRECT_URIS; any
//     other redirect_uri (even for a registered client) -> 400 page and
//     NEVER a redirect. Malformed requests -> 400, no redirect.
//   * The sign-in page: `X-Frame-Options: DENY`, CSP with
//     `frame-ancestors 'none'`, a password field named `token`, method POST,
//     no configured values in it. No `form-action 'self'` (browsers apply it
//     to the post-submit redirect and it would block the hop to vendor.example).
//   * Grants carry a fingerprint of MCP_AUTH_TOKEN_SHA256; rotating the
//     token makes every previously issued OAuth token fail with 401.
//   * Brute-force / spam limits: POST /authorize (every sign-in attempt,
//     right or wrong) and POST /register each have their own global
//     limit of AUTH_ATTEMPTS_PER_MIN (10) in any 60 s, held in the
//     RateLimiter Durable Object. Over the limit -> 429, never a redirect,
//     no code, no client registered. GET /authorize (showing the page) is
//     not limited. These limits are separate from the email limit.
//   * Every route answers 500 with an empty body when the configuration is
//     invalid, before doing anything else.

import { describe, expect, it } from "vitest";
import { AUTH_ATTEMPTS_PER_MIN } from "../../src/index";
import { ALICE, PUBLIC, TOKEN, TOKEN_SHA256, expectNoSecrets, expectSent, mcpInit, parseRpc, varsWith, varsWithout, worker, type TestWorker } from "./helpers";

const CALLBACK = "https://client.example.test/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-verifier-xyz";
const LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

async function challenge(v: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function register(w: TestWorker, redirectUris: string[]) {
  return w.fetch("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "the model", redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
  });
}

async function clientId(w: TestWorker, redirect = CALLBACK) {
  const r = await register(w, [redirect]);
  expect(r.status).toBe(201);
  return ((await r.json()) as any).client_id as string;
}

async function authorizeQuery(cid: string, redirect = CALLBACK) {
  return new URLSearchParams({
    response_type: "code", client_id: cid, redirect_uri: redirect, state: "st4te-123",
    code_challenge: await challenge(VERIFIER), code_challenge_method: "S256", resource: `${PUBLIC}/mcp`,
  }).toString();
}

async function submit(w: TestWorker, query: string, token: string) {
  return w.fetch(`/authorize?${query}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }).toString(),
    redirect: "manual",
  });
}

async function getCode(w: TestWorker, cid: string) {
  const r = await submit(w, await authorizeQuery(cid), TOKEN);
  expect(r.status, await r.clone().text()).toBe(302);
  const loc = new URL(r.headers.get("location")!);
  expect(`${loc.origin}${loc.pathname}`).toBe(CALLBACK);
  expect(loc.searchParams.get("state")).toBe("st4te-123");
  return loc.searchParams.get("code")!;
}

async function token(w: TestWorker, form: Record<string, string>) {
  return w.fetch("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
}

async function fullFlow(w: TestWorker) {
  const cid = await clientId(w);
  const code = await getCode(w, cid);
  const r = await token(w, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER, resource: `${PUBLIC}/mcp` });
  expect(r.status, await r.clone().text()).toBe(200);
  return { cid, tokens: (await r.json()) as any };
}

async function mcpStatus(w: TestWorker, bearer: string | null) {
  return (await w.fetch("/mcp", mcpInit(LIST, bearer))).status;
}

describe("static bearer", () => {
  it("accepts the right token", async () => {
    expect(await mcpStatus(worker(), TOKEN)).toBe(200);
  });

  it("rejects everything else with an empty 401 and a resource-metadata challenge", async () => {
    const w = worker();
    for (const auth of [null, "", "wrong", TOKEN.slice(0, -1), `${TOKEN}x`, `${TOKEN.slice(0, -1)}X`]) {
      const r = await w.fetch("/mcp", mcpInit(LIST, auth));
      expect(r.status, `token ${auth}`).toBe(401);
      expect(await r.text()).toBe("");
      expect(r.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource`);
    }
    for (const raw of [TOKEN, `Basic ${TOKEN}`, `Bearer  ${TOKEN}x`]) {
      const init = mcpInit(LIST, null, { authorization: raw });
      expect((await w.fetch("/mcp", init)).status, raw).toBe(401);
    }
  });

  it("rejected requests run no tool logic", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "1" }));
    const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } };
    for (const t of [null, "nope"]) expect((await w.fetch("/mcp", mcpInit(call, t))).status).toBe(401);
    expect(w.mailer.sent).toHaveLength(0);
    expectSent(await w.sendEmail(ALICE, "s", "b"));
  });

  it("stateless: no session id, no handshake needed", async () => {
    const w = worker();
    const init = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } }, TOKEN));
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).toBeNull();
    const r = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }, TOKEN));
    expect(r.headers.get("mcp-session-id")).toBeNull();
    expectSent(await parseRpc(r));
  });
});

describe("broken configuration", () => {
  it("every route answers an empty 500", async () => {
    for (const vars of [varsWithout("MCP_AUTH_TOKEN_SHA256"), varsWith({ MAIL_DEFAULT_TO: "mallory@evil.example" })]) {
      const w = worker(vars);
      for (const [path, init] of [["/mcp", mcpInit(LIST, TOKEN)], ["/authorize", {}], ["/.well-known/oauth-authorization-server", {}], ["/", {}]] as const) {
        const r = await w.fetch(path, init as RequestInit);
        expect(r.status, path).toBe(500);
        expect(await r.text()).toBe("");
      }
      expect(w.mailer.sent).toHaveLength(0);
    }
  });
});

describe("discovery", () => {
  it("protected resource metadata", async () => {
    const r = await worker().fetch("/.well-known/oauth-protected-resource/mcp");
    expect(r.status).toBe(200);
    const v = (await r.json()) as any;
    expect(v.resource).toBe(`${PUBLIC}/mcp`);
    expect(v.authorization_servers).toEqual([PUBLIC]);
  });

  it("authorization server metadata", async () => {
    const r = await worker().fetch("/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    const text = await r.text();
    expectNoSecrets(text, "AS metadata");
    const v = JSON.parse(text);
    expect(v.issuer).toBe(PUBLIC);
    expect(v.authorization_endpoint).toBe(`${PUBLIC}/authorize`);
    expect(v.token_endpoint).toBe(`${PUBLIC}/token`);
    expect(v.registration_endpoint).toBe(`${PUBLIC}/register`);
    expect(v.code_challenge_methods_supported).toEqual(["S256"]);
  });
});

describe("authorize page", () => {
  it("is a safe sign-in form", async () => {
    const w = worker();
    const r = await w.fetch(`/authorize?${await authorizeQuery(await clientId(w))}`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/^text\/html/);
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    const csp = r.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    const fa = csp.split(";").map((s) => s.trim()).find((d) => d.startsWith("form-action"));
    if (fa) expect(fa, "form-action would block the redirect").toContain("https://vendor.example");
    const html = await r.text();
    expect(html).toMatch(/type="password"/);
    expect(html).toMatch(/name="token"/);
    expect(html).toMatch(/method="post"/i);
    expectNoSecrets(html, "sign-in page");
  });

  it("escapes reflected values", async () => {
    const w = worker();
    const q = new URLSearchParams(await authorizeQuery(await clientId(w)));
    q.set("state", '"><script>alert(1)</script>');
    const html = await (await w.fetch(`/authorize?${q}`)).text();
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("rejects redirect URIs off the list, even for registered clients", async () => {
    const w = worker();
    const evil = "https://evil.example/callback";
    const reg = await register(w, [evil]);
    const cid = reg.status === 201 ? ((await reg.json()) as any).client_id : await clientId(w);
    const q = await authorizeQuery(cid, evil);
    const g = await w.fetch(`/authorize?${q}`, { redirect: "manual" });
    expect(g.status).toBe(400);
    expect(g.headers.get("location")).toBeNull();
    const p = await submit(w, q, TOKEN);
    expect(p.status).toBe(400);
    expect(p.headers.get("location")).toBeNull();
  });

  it("rejects malformed requests without redirecting", async () => {
    const w = worker();
    const base = new URLSearchParams(await authorizeQuery(await clientId(w)));
    const variants = [
      (q: URLSearchParams) => q.delete("redirect_uri"),
      (q: URLSearchParams) => q.set("response_type", "token"),
      (q: URLSearchParams) => q.set("client_id", "no-such-client"),
      (q: URLSearchParams) => q.delete("code_challenge"),
    ];
    for (const mutate of variants) {
      const q = new URLSearchParams(base);
      mutate(q);
      for (const r of [await w.fetch(`/authorize?${q}`, { redirect: "manual" }), await submit(w, q.toString(), TOKEN)]) {
        expect(r.status, q.toString()).toBeGreaterThanOrEqual(400);
        expect(r.status).toBeLessThan(500);
        const loc = r.headers.get("location");
        expect(loc === null || !loc.startsWith(CALLBACK) || !new URL(loc).searchParams.has("code"), "no code issued").toBe(true);
      }
    }
  });

  it("wrong operator token issues no code", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (const t of ["", "nope", TOKEN.slice(0, -1), `${TOKEN}x`]) {
      const r = await submit(w, q, t);
      expect(r.status, t).toBe(401);
      expect(r.headers.get("location")).toBeNull();
    }
  });

  it("redirect allowlist is configurable", async () => {
    const w = worker(varsWith({ OAUTH_REDIRECT_URIS: "https://custom.example/cb" }));
    const custom = await clientId(w, "https://custom.example/cb");
    expect((await w.fetch(`/authorize?${await authorizeQuery(custom, "https://custom.example/cb")}`)).status).toBe(200);
    const model = await clientId(w);
    expect((await w.fetch(`/authorize?${await authorizeQuery(model)}`, { redirect: "manual" })).status).toBe(400);
  });
});

describe("OAuth flow", () => {
  it("issues tokens that work on /mcp", async () => {
    const w = worker();
    const { tokens } = await fullFlow(w);
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    expect(tokens.access_token).not.toBe(TOKEN);
    expect(typeof tokens.refresh_token).toBe("string");
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
    const r = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }, tokens.access_token));
    expectSent(await parseRpc(r));
  });

  it("codes are single-use and PKCE-bound", async () => {
    const w = worker();
    const cid = await clientId(w);
    const code = await getCode(w, cid);
    const bad = await token(w, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-x" });
    expect(bad.status).toBe(400);
    const code2 = await getCode(w, cid);
    const ok = await token(w, { grant_type: "authorization_code", code: code2, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER });
    expect(ok.status).toBe(200);
    const replay = await token(w, { grant_type: "authorization_code", code: code2, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER });
    expect(replay.status).toBe(400);
  });

  it("refresh tokens are not bearer tokens", async () => {
    const w = worker();
    const { cid, tokens } = await fullFlow(w);
    expect(await mcpStatus(w, tokens.refresh_token)).toBe(401);
    const r = await token(w, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cid });
    expect(r.status).toBe(200);
    expect(await mcpStatus(w, ((await r.json()) as any).access_token)).toBe(200);
  });

  it("rotating the token revokes issued tokens", async () => {
    const w = worker();
    const { tokens } = await fullFlow(w);
    // sha256("ffffffffffffffffffffffffffffffff-rotated")
    const rotated = worker(varsWith({ MCP_AUTH_TOKEN_SHA256: "50dc2b44f1bc3d28011dfa8705527346f8aab7df9a738a8955a8b51197896ef7" }));
    expect(await mcpStatus(rotated, tokens.access_token)).toBe(401);
    expect(await mcpStatus(rotated, TOKEN)).toBe(401);
    expect(await mcpStatus(rotated, "ffffffffffffffffffffffffffffffff-rotated")).toBe(200);
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
  });
});

describe("hashed token", () => {
  it("the stored hash is not itself a credential", async () => {
    const w = worker();
    expect(await mcpStatus(w, TOKEN_SHA256)).toBe(401);
    const r = await submit(w, await authorizeQuery(await clientId(w)), TOKEN_SHA256);
    expect(r.status).toBe(401);
    expect(r.headers.get("location")).toBeNull();
  });
});

describe("sign-in and registration limits", () => {
  it("is 10 per minute", () => {
    expect(AUTH_ATTEMPTS_PER_MIN).toBe(10);
  });

  it("sign-in attempts are limited, even with the right token", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) expect((await submit(w, q, `wrong-${i}`)).status, `attempt ${i}`).toBe(401);
    const r = await submit(w, q, TOKEN);
    expect(r.status).toBe(429);
    expect(r.headers.get("location")).toBeNull();
    expectNoSecrets(await r.text(), "429 page");
    // Viewing the page is not an attempt.
    expect((await w.fetch(`/authorize?${q}`)).status).toBe(200);
  });

  it("successful sign-ins count too", async () => {
    const w = worker();
    const cid = await clientId(w);
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) await getCode(w, cid);
    expect((await submit(w, await authorizeQuery(cid), TOKEN)).status).toBe(429);
  });

  it("client registration is limited", async () => {
    const w = worker();
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) expect((await register(w, [CALLBACK])).status, `register ${i}`).toBe(201);
    const r = await register(w, [CALLBACK]);
    expect(r.status).toBe(429);
    expect(r.headers.get("location")).toBeNull();
  });

  it("buckets are independent of each other and of email", async () => {
    const w = worker();
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) await register(w, [CALLBACK]);
    expect((await register(w, [CALLBACK])).status).toBe(429);
    // Registration exhausted; a client registered earlier can still sign in.
    const fresh = worker();
    const cid = await clientId(fresh);
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN - 1; i++) await register(fresh, [CALLBACK]);
    expect((await register(fresh, [CALLBACK])).status).toBe(429);
    await getCode(fresh, cid);
    expectSent(await fresh.sendEmail(ALICE, "s", "b"));
  });
});

describe("other routes", () => {
  it("unknown paths 404 without detail", async () => {
    const w = worker();
    for (const p of ["/", "/admin", "/mcp/extra"]) {
      const r = await w.fetch(p);
      expect([401, 404], p).toContain(r.status);
      expectNoSecrets(await r.text(), p);
    }
  });
});

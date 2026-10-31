// Authentication contract.
//
// The Worker is an OAuth 2.1 authorization server + protected resource,
// built on @cloudflare/workers-oauth-provider, with the MCP endpoint at
// `/mcp` as the only protected route.
//
// There is NO static bearer path. The operator token is used in exactly one
// place: the sign-in form on `/authorize`. `Authorization: Bearer <anything>`
// on `/mcp` is unauthenticated, so the old token (even the correct one) gets
// 401, an EMPTY body and a `WWW-Authenticate` header naming the resource
// metadata URL. The only way to call `/mcp` is an OAuth grant.
//
// The operator token is never stored server-side. The Worker holds only
// MCP_AUTH_TOKEN_SHA256 (set by `npm run rotate-token`); a presented token is
// hashed with SHA-256 and compared to it in constant time
// (crypto.subtle.timingSafeEqual). Presenting the hash itself must fail.
//
// OAuth: discovery -> dynamic client registration -> /authorize -> /token,
// authorization code + PKCE S256. The `/authorize` page is ours: an HTML form
// where the operator types the token once. Right token ->
// provider.completeAuthorization -> 302 back to the client. Wrong token -> 401
// page, no redirect.
//
// Rules:
//   * `/mcp` without valid credentials -> 401, EMPTY body, with a
//     `WWW-Authenticate` header naming the resource metadata URL. No tool
//     logic runs (nothing sent, no rate-limit token spent).
//   * `/authorize` serves only redirect URIs the redirect rule allows
//     (`redirectAllowed`, src/index.ts): loopback http (localhost /
//     127.0.0.1, any port and path), allowlisted full https URLs, and
//     allowlisted bare hostnames matched exactly. Any other redirect_uri
//     (even for a registered client, even an https look-alike of an
//     allowlisted host) -> 400 page and NEVER a redirect. Malformed
//     requests -> 400, no redirect.
//   * The sign-in page: `X-Frame-Options: DENY`, CSP with
//     `frame-ancestors 'none'`, a password field named `token`, method POST,
//     no configured values in it. No `form-action 'self'` (browsers apply it
//     to the post-submit redirect and it would block the hop to the client).
//   * Client labels. Every connection has a label, so mail and limits can be
//     attributed to it:
//       - The sign-in page also asks for a label (text input name="label"),
//         pre-filled with `prefillLabel(clientName)` in its `value`
//         attribute: the suggestion is sanitised to the label grammar, but
//         the input is editable, required, and the POST handler still
//         validates the submitted value. An empty pre-fill (unknown client
//         name, or a reserved name like "operator") asks the human to type
//         one.
//       - A label is 1-32 chars of [a-z0-9-], starting with a letter or
//         digit (no uppercase, spaces, underscores). Only "operator" is
//         reserved: it names grants made before labels existed, so a human
//         may not claim it. "bearer" is an ordinary label now that the
//         static token is gone. A missing or invalid label with the RIGHT
//         token -> 400 page, no redirect, no code.
//       - The grant is created with `userId` = the label, so the OAuth KV
//         keys are `grant:<label>:...` / `token:<label>:...` and
//         `npm run clients` can list and revoke by label (test/node).
//         The label is also in the grant props, next to the fingerprint.
//       - Every email carries `X-MCP-Client: <label>` (mail.test.ts,
//         tools.test.ts) and ping reports the label as `client`.
//       - CLIENT_EMAIL_PER_MIN (optional): each label also gets its own
//         flat window (Durable Object name `${limiterName}:client:<label>`)
//         checked BEFORE the global EMAIL_PER_MIN window. A send must pass
//         both; one refused by its client window does not use the global
//         one. Refusals look exactly like the global limit (same error).
//         Unset -> only the global window applies.
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
//
// The tool suites drive `/mcp` through the `authenticate` test seam (see
// test/worker/helpers.ts). Tests in this file that need the real OAuth
// provider on `/mcp` build `worker(vars, { oauth: true })`, which leaves the
// seam out.

import { describe, expect, it } from "vitest";
import { AUTH_ATTEMPTS_PER_MIN } from "../../src/index";
import {
  ALICE, INVALID_REQUEST, PUBLIC, TOKEN, TOKEN_SHA256, baseVars, expectNoSecrets, expectRpcError, expectSent,
  mcpInit, parseRpc, varsWith, varsWithout, worker, type TestWorker,
} from "./helpers";

const CALLBACK = "https://client.example.test/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-verifier-xyz";
const LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
const LIMIT = "email rate limit exceeded for this minute";
const RM = `${PUBLIC}/.well-known/oauth-protected-resource`;

/** Worker whose /mcp is guarded by the real OAuth provider (no test seam). */
const providerWorker = (vars = baseVars()) => worker(vars, { oauth: true });

async function challenge(v: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function register(w: TestWorker, redirectUris: string[], clientName = "Example App") {
  return w.fetch("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: clientName, redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
  });
}

async function clientId(w: TestWorker, redirect = CALLBACK, clientName = "Example App") {
  const r = await register(w, [redirect], clientName);
  expect(r.status).toBe(201);
  return ((await r.json()) as any).client_id as string;
}

async function authorizeQuery(cid: string, redirect = CALLBACK) {
  return new URLSearchParams({
    response_type: "code", client_id: cid, redirect_uri: redirect, state: "st4te-123",
    code_challenge: await challenge(VERIFIER), code_challenge_method: "S256", resource: `${PUBLIC}/mcp`,
  }).toString();
}

async function submit(w: TestWorker, query: string, token: string, label: string | null = "personal") {
  const form = new URLSearchParams({ token });
  if (label !== null) form.set("label", label);
  return w.fetch(`/authorize?${query}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
    redirect: "manual",
  });
}

async function getCode(w: TestWorker, cid: string, label = "personal") {
  const r = await submit(w, await authorizeQuery(cid), TOKEN, label);
  expect(r.status, await r.clone().text()).toBe(302);
  const loc = new URL(r.headers.get("location")!);
  expect(`${loc.origin}${loc.pathname}`).toBe(CALLBACK);
  expect(loc.searchParams.get("state")).toBe("st4te-123");
  return loc.searchParams.get("code")!;
}

async function token(w: TestWorker, form: Record<string, string>) {
  return w.fetch("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
}

async function fullFlow(w: TestWorker, label = "personal") {
  const cid = await clientId(w);
  const code = await getCode(w, cid, label);
  const r = await token(w, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER, resource: `${PUBLIC}/mcp` });
  expect(r.status, await r.clone().text()).toBe(200);
  return { cid, tokens: (await r.json()) as any };
}

async function sendAs(w: TestWorker, token: string, subject: string) {
  return parseRpc(await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject, body: "b" } } }, token)));
}

/** A label no other test uses (KV may be shared between tests). */
const freshLabel = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

async function mcpStatus(w: TestWorker, bearer: string | null) {
  return (await w.fetch("/mcp", mcpInit(LIST, bearer))).status;
}

/** The sign-in page's label input: its whole tag and its value attribute ("" if none). */
function labelInput(html: string) {
  const tag = html.match(/<input\b[^>]*\bname=["']label["'][^>]*>/i)?.[0];
  expect(tag, "sign-in page has a label input").toBeTruthy();
  return { tag: tag!, value: tag!.match(/\bvalue=["']([^"']*)["']/)?.[1] ?? "" };
}

describe("static bearer (removed)", () => {
  it("the correct operator token is not a credential on /mcp", async () => {
    const w = providerWorker();
    const r = await w.fetch("/mcp", mcpInit(LIST, TOKEN));
    expect(r.status).toBe(401);
    expect(await r.text()).toBe("");
    expect(r.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${RM}`);
  });

  it("rejects every Authorization value with the same empty 401 challenge", async () => {
    const w = providerWorker();
    for (const raw of [null, TOKEN, `Bearer ${TOKEN}`, `Basic ${TOKEN}`, `Bearer  ${TOKEN}`, `Bearer ${TOKEN}x`, "Bearer wrong"]) {
      const init = raw === null ? mcpInit(LIST) : mcpInit(LIST, null, { authorization: raw });
      const r = await w.fetch("/mcp", init);
      expect(r.status, String(raw)).toBe(401);
      expect(await r.text(), String(raw)).toBe("");
      expect(r.headers.get("www-authenticate") ?? "", String(raw)).toContain(`resource_metadata="${RM}`);
    }
  });

  it("the old token runs no tool logic and spends no rate-limit token", async () => {
    const w = providerWorker(varsWith({ EMAIL_PER_MIN: "1" }));
    const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } };
    expect((await w.fetch("/mcp", mcpInit(call, TOKEN))).status).toBe(401);
    expect(w.mailer.sent).toHaveLength(0);
    // A real grant still has its full budget: the refused request was not counted.
    const { tokens } = await fullFlow(w);
    expectSent(await sendAs(w, tokens.access_token, "s"));
    expectRpcError(await sendAs(w, tokens.access_token, "again"), INVALID_REQUEST, LIMIT);
    expect(w.mailer.sent).toHaveLength(1);
  });

  it("stateless: no session id, no handshake needed", async () => {
    const w = providerWorker();
    const { tokens } = await fullFlow(w);
    const init = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } }, tokens.access_token));
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).toBeNull();
    const r = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }, tokens.access_token));
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
    if (fa) expect(fa, "form-action would block the redirect").toContain("https://client.example.test");
    const html = await r.text();
    expect(html).toMatch(/type="password"/);
    expect(html).toMatch(/name="token"/);
    expect(html).toMatch(/name="label"/);
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

  it("pre-fills the label from the client name", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example Desktop");
    const html = await (await w.fetch(`/authorize?${await authorizeQuery(cid)}`)).text();
    expect(labelInput(html).value).toBe("example-desktop");
  });

  it("pre-fills a sanitised value for an awkward client name", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example.ai Connector");
    const html = await (await w.fetch(`/authorize?${await authorizeQuery(cid)}`)).text();
    expect(labelInput(html).value).toBe("example-ai-connector");
  });

  it("the pre-filled label is editable, required, and still validated on POST", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example Desktop");
    const q = await authorizeQuery(cid);
    const { tag, value } = labelInput(await (await w.fetch(`/authorize?${q}`)).text());
    expect(value).toBe("example-desktop");
    expect(tag).toMatch(/\brequired\b/);
    expect(tag).not.toMatch(/\breadonly\b|\bdisabled\b/);
    // The suggestion itself is a valid label...
    expect((await submit(w, q, TOKEN, "example-desktop")).status).toBe(302);
    // ...the human may replace it...
    expect((await submit(w, q, TOKEN, "my-phone")).status).toBe(302);
    // ...and the POST handler still enforces the grammar.
    expect((await submit(w, q, TOKEN, "My Phone")).status).toBe(400);
  });

  it("a reserved client name pre-fills empty, unlike an ordinary one", async () => {
    const w = worker();
    const ordinary = await clientId(w, CALLBACK, "Example Desktop");
    const reserved = await clientId(w, CALLBACK, "operator");
    const ordinaryHtml = await (await w.fetch(`/authorize?${await authorizeQuery(ordinary)}`)).text();
    const reservedHtml = await (await w.fetch(`/authorize?${await authorizeQuery(reserved)}`)).text();
    expect(labelInput(ordinaryHtml).value).toBe("example-desktop");
    expect(labelInput(reservedHtml).value).toBe("");
  });

  it("rejects redirect URIs off the list, even for registered clients", async () => {
    const w = worker();
    for (const evil of ["https://evil.example/callback", "https://evil.vendor.example.attacker.net/cb", "https://vendor.example.evil.net/cb"]) {
      const reg = await register(w, [evil]);
      const cid = reg.status === 201 ? ((await reg.json()) as any).client_id : await clientId(w);
      const q = await authorizeQuery(cid, evil);
      const g = await w.fetch(`/authorize?${q}`, { redirect: "manual" });
      expect(g.status, evil).toBe(400);
      expect(g.headers.get("location"), evil).toBeNull();
      const p = await submit(w, q, TOKEN);
      expect(p.status, evil).toBe(400);
      expect(p.headers.get("location"), evil).toBeNull();
    }
  });

  it("allows the redirects the new rule permits: loopback and allowlisted bare hosts", async () => {
    // Hosted callbacks are opt-in, so the bare host has to be configured.
    const w = worker(varsWith({ OAUTH_REDIRECT_URIS: "https://client.example.test/callback,vendor.example" }));
    for (const redirect of ["http://localhost:33418/callback", "http://127.0.0.1:8976/oauth/done", "https://vendor.example/connector/oauth/callback"]) {
      const cid = await clientId(w, redirect);
      const r = await w.fetch(`/authorize?${await authorizeQuery(cid, redirect)}`);
      expect(r.status, redirect).toBe(200);
      expect(r.headers.get("content-type"), redirect).toMatch(/^text\/html/);
      expect(await r.text(), redirect).toContain('name="token"');
    }
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
    const client = await clientId(w);
    expect((await w.fetch(`/authorize?${await authorizeQuery(client)}`, { redirect: "manual" })).status).toBe(400);
    // A bare-host entry covers any path on that host, still no look-alikes.
    const hosted = worker(varsWith({ OAUTH_REDIRECT_URIS: "custom.example" }));
    const ok = await clientId(hosted, "https://custom.example/any/path");
    expect((await hosted.fetch(`/authorize?${await authorizeQuery(ok, "https://custom.example/any/path")}`)).status).toBe(200);
    const lookalike = await clientId(hosted, "https://custom.example.evil.net/cb");
    expect((await hosted.fetch(`/authorize?${await authorizeQuery(lookalike, "https://custom.example.evil.net/cb")}`, { redirect: "manual" })).status).toBe(400);
  });
});

describe("OAuth flow", () => {
  it("issues tokens that work on /mcp", async () => {
    const w = providerWorker();
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
    const w = providerWorker();
    const { cid, tokens } = await fullFlow(w);
    expect(await mcpStatus(w, tokens.refresh_token)).toBe(401);
    const r = await token(w, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cid });
    expect(r.status).toBe(200);
    expect(await mcpStatus(w, ((await r.json()) as any).access_token)).toBe(200);
  });

  it("rotating the token revokes issued tokens", async () => {
    const w = providerWorker();
    const { tokens } = await fullFlow(w);
    // sha256("ffffffffffffffffffffffffffffffff-rotated")
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: "50dc2b44f1bc3d28011dfa8705527346f8aab7df9a738a8955a8b51197896ef7" }));
    expect(await mcpStatus(rotated, tokens.access_token)).toBe(401);
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
  });
});

describe("hashed token", () => {
  it("the stored hash is not itself a credential", async () => {
    const w = providerWorker();
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

describe("client labels", () => {
  it("sign-in requires a valid label", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (const bad of [null, "", "Personal", "my phone", "a_b", "-lead", "a".repeat(33), "operator", "é", "bearer "]) {
      const r = await submit(w, q, TOKEN, bad);
      expect(r.status, String(bad)).toBe(400);
      expect(r.headers.get("location"), String(bad)).toBeNull();
    }
    for (const good of ["a", "work", "phone-2", "9lives", "a".repeat(32), "bearer"]) {
      expect((await submit(worker(), await authorizeQuery(await clientId(w)), TOKEN, good)).status, good).toBe(302);
    }
  });

  it("the grant is stored under the label", async () => {
    const label = freshLabel("kv");
    await fullFlow(worker(), label);
    const { env } = await import("cloudflare:test");
    const keys = (await env.OAUTH_KV.list({ prefix: `grant:${label}:` })).keys;
    expect(keys).toHaveLength(1);
  });

  it("every email names its client", async () => {
    const w = providerWorker();
    const label = freshLabel("tag");
    const { tokens } = await fullFlow(w, label);
    expectSent(await sendAs(w, tokens.access_token, "via oauth"));
    expect(w.mailer.sent.map((m) => [m.subject, m.headers["X-MCP-Client"]])).toEqual([["via oauth", label]]);
    expect(JSON.stringify(w.mailer.sent)).not.toContain('"bearer"');
  });

  it("CLIENT_EMAIL_PER_MIN caps each client, under the global cap", async () => {
    const w = providerWorker(varsWith({ CLIENT_EMAIL_PER_MIN: "2", EMAIL_PER_MIN: "3" }));
    const a = (await fullFlow(w, freshLabel("a"))).tokens.access_token;
    const b = (await fullFlow(w, freshLabel("b"))).tokens.access_token;
    const c = (await fullFlow(w, freshLabel("c"))).tokens.access_token;
    expectSent(await sendAs(w, a, "a1"));
    expectSent(await sendAs(w, a, "a2"));
    expectRpcError(await sendAs(w, a, "a3"), INVALID_REQUEST, LIMIT); // a's own window; global untouched
    expectSent(await sendAs(w, b, "b1")); // global now 3/3
    expectRpcError(await sendAs(w, b, "b2"), INVALID_REQUEST, LIMIT); // global window
    expectRpcError(await sendAs(w, c, "c1"), INVALID_REQUEST, LIMIT); // global window, fresh client window
    expect(w.mailer.sent.map((m) => m.subject)).toEqual(["a1", "a2", "b1"]);
  });

  it("without CLIENT_EMAIL_PER_MIN only the global cap applies", async () => {
    const w = providerWorker(varsWith({ EMAIL_PER_MIN: "3" }));
    const a = (await fullFlow(w, freshLabel("solo"))).tokens.access_token;
    for (const s of ["1", "2", "3"]) expectSent(await sendAs(w, a, s));
    expectRpcError(await sendAs(w, a, "4"), INVALID_REQUEST, LIMIT);
  });
});

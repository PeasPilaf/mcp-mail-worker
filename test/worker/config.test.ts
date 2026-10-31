// Configuration contract (`parseConfig`).
//
// All configuration is Worker secrets, set by the operator in Cloudflare
// (dashboard or `wrangler secret put`), never in GitHub. Nothing comes from
// the MCP client. `parseConfig(env)` returns a validated Config or throws a
// ConfigError whose `key` names the offending variable (never its value).
// A Worker cannot refuse to start, so "fail loudly" means: every request
// against a broken config gets HTTP 500 with an empty body on every route
// (test/worker/auth.test.ts), and the ConfigError message is logged for
// `wrangler tail`.
//
// | key                 | required | notes                                                       |
// |---------------------|----------|-------------------------------------------------------------|
// | MCP_AUTH_TOKEN_SHA256 | yes    | sha256 of the operator token, exactly 64 LOWERCASE hex chars. |
//                                  The token itself is never stored anywhere server-side; it is
//                                  generated and set by `npm run rotate-token` (test/node).
// | PUBLIC_URL          | yes      | https origin (http only for localhost/127.0.0.1); no path   |
// | SMTP_HOST           | yes      | e.g. smtp.example.com / smtp.example.eu / smtp.example.com         |
// | SMTP_PORT           | no       | 465 (default, implicit TLS) or 587 (STARTTLS); nothing else |
// | SMTP_USERNAME       | yes      |                                                             |
// | SMTP_PASSWORD       | yes      | the mail provider app-specific password                                  |
// | SMTP_FROM           | no       | mailbox (display name allowed); default = SMTP_USERNAME     |
// | EMAIL_PER_MIN       | yes      | integer > 0                                                 |
// | MAIL_ALLOW_TO       | yes      | comma-separated BARE addresses, non-empty                   |
// | MAIL_DEFAULT_TO     | no       | must be on the allowlist; default = first entry             |
// | MAX_BODY_BYTES      | no       | integer >= 0; absent = no cap                               |
// | OAUTH_REDIRECT_URIS | no       | comma list of https URLs; default = vendor.example/vendor.example     |
// | EMAIL_BATCHING      | no       | RESERVED: read, never validated, never acted on             |
//
// Empty strings count as absent. Non-string values (bindings) are ignored.

import { describe, expect, it } from "vitest";
import { ConfigError, DEFAULT_REDIRECT_URIS, parseAddress, parseConfig, parseMailbox } from "../../src/config";
import { ALICE, BOB, DEFAULT_TO, FROM, OFF_LIST, PASSWORD, PUBLIC, SMTP_HOST, TOKEN, TOKEN_SHA256, USERNAME, baseVars, varsWith, varsWithout } from "./helpers";

function err(vars: Record<string, unknown>): ConfigError {
  try {
    parseConfig(vars);
  } catch (e) {
    expect(e).toBeInstanceOf(ConfigError);
    return e as ConfigError;
  }
  throw new Error("configuration should have been rejected");
}

describe("addresses", () => {
  it("parses bare addresses and rejects junk", () => {
    expect(parseAddress("alice@example.com")).toBe("alice@example.com");
    expect(parseAddress("Bob.Builder@Example.org")).toBe("Bob.Builder@Example.org");
    expect(parseAddress("  a.b+tag@sub.example.co  ")).toBe("a.b+tag@sub.example.co");
    for (const bad of ["", "not-an-email", "a@b", "@example.com", "a@@example.com", "a b@example.com",
      "Alice <alice@example.com>", "<alice@example.com>", "a@example.com,b@example.com",
      "a@example.com\r\nBcc: x@y.z", "a@-bad-.com", "a@exa mple.com"]) {
      expect(parseAddress(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("parses mailboxes with optional display names", () => {
    expect(parseMailbox("alice@example.com")).toEqual({ address: "alice@example.com" });
    expect(parseMailbox("Evil Twin <BOB.BUILDER@example.org>")).toEqual({ address: "BOB.BUILDER@example.org", name: "Evil Twin" });
    expect(parseMailbox('"Totally Bob" <Bob.Builder@Example.org>')).toEqual({ address: "Bob.Builder@Example.org", name: "Totally Bob" });
    for (const bad of ["", "garbage", "Name <not-an-email>", "alice@example.com, mallory@evil.example", "Name <a@example.com> trailing"]) {
      expect(parseMailbox(bad), JSON.stringify(bad)).toBeNull();
    }
  });
});

describe("happy path", () => {
  it("parses the canonical config", () => {
    const c = parseConfig(baseVars());
    expect(c.authTokenSha256).toBe(TOKEN_SHA256);
    expect(JSON.stringify(c)).not.toContain(TOKEN);
    expect(c.publicUrl).toBe(PUBLIC);
    expect(c.smtpHost).toBe(SMTP_HOST);
    expect(c.smtpPort).toBe(465);
    expect(c.smtpUsername).toBe(USERNAME);
    expect(c.smtpPassword).toBe(PASSWORD);
    expect(c.smtpFrom.address).toBe(FROM);
    expect(c.emailPerMin).toBe(37);
    expect(c.allowlist.size).toBe(3);
    expect(c.defaultTo).toEqual({ address: DEFAULT_TO });
    expect(c.maxBodyBytes).toBeNull();
    expect(c.oauthRedirectUris).toEqual(DEFAULT_REDIRECT_URIS);
  });

  it("defaults", () => {
    expect(parseConfig(varsWithout("SMTP_PORT")).smtpPort).toBe(465);
    expect(parseConfig(varsWithout("SMTP_FROM")).smtpFrom.address).toBe(USERNAME);
    expect(parseConfig(varsWithout("MAIL_DEFAULT_TO")).defaultTo).toEqual({ address: ALICE });
    // Empty counts as absent.
    const c = parseConfig(varsWith({ SMTP_FROM: "", MAIL_DEFAULT_TO: "", SMTP_PORT: "" }));
    expect(c.smtpFrom.address).toBe(USERNAME);
    expect(c.defaultTo.address).toBe(ALICE);
    expect(c.smtpPort).toBe(465);
  });

  it("accepts 587 and a display-name sender", () => {
    expect(parseConfig(varsWith({ SMTP_PORT: "587" })).smtpPort).toBe(587);
    const c = parseConfig(varsWith({ SMTP_FROM: "Relay Bot <relay-bot@sender.example>" }));
    expect(c.smtpFrom).toEqual({ address: FROM, name: "Relay Bot" });
  });

  it("allowlist: trimmed, empty segments skipped, case-insensitive, canonical", () => {
    const c = parseConfig(varsWith({ MAIL_ALLOW_TO: `  ${ALICE} , ${DEFAULT_TO} ,`, MAIL_DEFAULT_TO: "" }));
    expect(c.allowlist.size).toBe(2);
    expect(c.allowlist.first).toEqual({ address: ALICE });
    const b = parseConfig(baseVars());
    expect(b.allowlist.get("BOB.BUILDER@EXAMPLE.ORG")).toEqual({ address: BOB });
    expect(b.allowlist.get(OFF_LIST)).toBeUndefined();
  });

  it("default_to membership is case-insensitive and canonicalised", () => {
    expect(parseConfig(varsWith({ MAIL_DEFAULT_TO: "bob.builder@example.ORG" })).defaultTo).toEqual({ address: BOB });
  });

  it("public url: trailing slash trimmed, localhost http allowed", () => {
    expect(parseConfig(varsWith({ PUBLIC_URL: `${PUBLIC}/` })).publicUrl).toBe(PUBLIC);
    expect(parseConfig(varsWith({ PUBLIC_URL: "http://localhost:8787" })).publicUrl).toBe("http://localhost:8787");
    expect(parseConfig(varsWith({ PUBLIC_URL: "http://127.0.0.1:8787/" })).publicUrl).toBe("http://127.0.0.1:8787");
  });

  it("max body bytes and redirect uris", () => {
    expect(parseConfig(varsWith({ MAX_BODY_BYTES: "1024" })).maxBodyBytes).toBe(1024);
    expect(parseConfig(varsWith({ MAX_BODY_BYTES: "0" })).maxBodyBytes).toBe(0);
    expect(parseConfig(varsWith({ OAUTH_REDIRECT_URIS: " https://a.example/cb , http://localhost:9999/cb ," })).oauthRedirectUris)
      .toEqual(["https://a.example/cb", "http://localhost:9999/cb"]);
  });

  it("ignores non-string bindings in env", () => {
    expect(() => parseConfig({ ...baseVars(), OAUTH_KV: {}, RATE_LIMITER: {} })).not.toThrow();
  });
});

describe("reserved key", () => {
  it("EMAIL_BATCHING is read but has no effect", () => {
    const without = JSON.stringify(parseConfig(baseVars()), replacer);
    for (const v of ["true", "false", "1", "not-a-bool", ""]) {
      expect(JSON.stringify(parseConfig(varsWith({ EMAIL_BATCHING: v })), replacer)).toBe(without);
    }
  });
});

describe("loud failures", () => {
  it("each required key is enforced (absent or empty)", () => {
    for (const key of ["MCP_AUTH_TOKEN_SHA256", "PUBLIC_URL", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_PER_MIN", "MAIL_ALLOW_TO"]) {
      const e = err(varsWithout(key));
      expect(e.key, key).toBe(key);
      expect(e.message).toContain(key);
      expect(err(varsWith({ [key]: "" })).key).toBe(key);
    }
  });

  it("token hash must be 64 lowercase hex characters", () => {
    // A plaintext token pasted by mistake must be refused, not hashed again.
    for (const bad of [TOKEN, TOKEN_SHA256.slice(1), `${TOKEN_SHA256}0`, TOKEN_SHA256.toUpperCase(), "g".repeat(64), `sha256:${TOKEN_SHA256}`]) {
      expect(err(varsWith({ MCP_AUTH_TOKEN_SHA256: bad })).key, bad).toBe("MCP_AUTH_TOKEN_SHA256");
    }
    expect(parseConfig(varsWith({ MCP_AUTH_TOKEN_SHA256: "0".repeat(64) })).authTokenSha256).toBe("0".repeat(64));
  });

  it("the old plaintext MCP_AUTH_TOKEN is not accepted in place of the hash", () => {
    expect(err({ ...varsWithout("MCP_AUTH_TOKEN_SHA256"), MCP_AUTH_TOKEN: TOKEN }).key).toBe("MCP_AUTH_TOKEN_SHA256");
  });

  it("numeric keys", () => {
    for (const bad of ["0", "-1", "abc", "1.5", "1e3", " 5x"]) expect(err(varsWith({ EMAIL_PER_MIN: bad })).key).toBe("EMAIL_PER_MIN");
    // Cloudflare blocks outbound port 25; only the two TLS submission ports.
    for (const bad of ["25", "2525", "abc", "70000"]) expect(err(varsWith({ SMTP_PORT: bad })).key).toBe("SMTP_PORT");
    for (const bad of ["lots", "-1", "1.5"]) expect(err(varsWith({ MAX_BODY_BYTES: bad })).key).toBe("MAX_BODY_BYTES");
  });

  it("public url must be an https origin", () => {
    for (const bad of ["mail.example.com", "http://mail.example.com", "ftp://mail.example.com", `${PUBLIC}/mcp`, `${PUBLIC}?x=1`, `${PUBLIC}#f`, "https://"]) {
      expect(err(varsWith({ PUBLIC_URL: bad })).key, bad).toBe("PUBLIC_URL");
    }
  });

  it("sender must be an address", () => {
    expect(err(varsWith({ SMTP_FROM: "not an email" })).key).toBe("SMTP_FROM");
    const v = varsWithout("SMTP_FROM");
    v.SMTP_USERNAME = "plainlogin";
    expect(err(v).key).toBe("SMTP_FROM");
  });

  it("allowlist rules", () => {
    for (const bad of [",", " , , ", "   "]) expect(err(varsWith({ MAIL_ALLOW_TO: bad })).key).toBe("MAIL_ALLOW_TO");
    expect(err(varsWith({ MAIL_ALLOW_TO: `${ALICE},not-an-email` })).key).toBe("MAIL_ALLOW_TO");
    for (const bad of ["Alice <alice@example.com>", '"Alice" <alice@example.com>', "<alice@example.com>"]) {
      expect(err(varsWith({ MAIL_ALLOW_TO: `${bad},${DEFAULT_TO}` })).key, bad).toBe("MAIL_ALLOW_TO");
    }
  });

  it("default must be on the allowlist and parse", () => {
    expect(err(varsWith({ MAIL_DEFAULT_TO: OFF_LIST })).key).toBe("MAIL_DEFAULT_TO");
    expect(err(varsWith({ MAIL_DEFAULT_TO: "nope" })).key).toBe("MAIL_DEFAULT_TO");
  });

  it("redirect uris must be https URLs without fragments", () => {
    for (const bad of ["not a url", "http://a.example/cb", ",", "https://a.example/cb#frag"]) {
      expect(err(varsWith({ OAUTH_REDIRECT_URIS: bad })).key, bad).toBe("OAUTH_REDIRECT_URIS");
    }
  });

  it("errors never echo secret values", () => {
    for (const v of [varsWith({ EMAIL_PER_MIN: "0" }), varsWith({ MAIL_DEFAULT_TO: OFF_LIST }), varsWith({ SMTP_PORT: "nope" }), varsWithout("SMTP_HOST")]) {
      const m = err(v).message;
      expect(m).not.toContain(TOKEN);
      expect(m).not.toContain(PASSWORD);
    }
  });
});

// Allowlist implementations may use Maps; serialise them comparably.
function replacer(_k: string, v: unknown) {
  if (v instanceof Map) return [...v.entries()];
  if (v instanceof Set) return [...v.values()];
  return v;
}

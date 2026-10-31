// OAuth redirect allowlist contract: `redirectAllowed(redirectUri, allowlist)`,
// exported from src/index.ts.
//
// `/authorize` must only hand an authorization code to a redirect URI the
// operator allows. The rule is deliberately narrow:
//
//   * http is allowed ONLY on a loopback hostname (`localhost` or
//     `127.0.0.1`), any port, any path. This is RFC 8252 native-app loopback,
//     not a general "http is fine" hole: look-alike hosts
//     (localhost.evil.example) and remote http never match.
//   * https is allowed when it EQUALS an allowlist entry. An entry is either
//     a full URL (scheme + host + path must match exactly, after URL
//     normalisation of scheme/host case) or a bare hostname, which matches
//     any path on exactly that host. There is no subdomain, prefix or suffix
//     matching: `vendor.example` must NOT match
//     evil.vendor.example.attacker.net, vendor.example.evil.net, sub.vendor.example
//     or vendor.example.au.
//   * Everything else is false: other schemes, credentials in the URL,
//     fragments, unparseable strings, and http on a non-loopback host.
//
// The function is pure: no configuration, no environment, no I/O.

import { describe, expect, it } from "vitest";
import { redirectAllowed } from "../../src/index";
import { DEFAULT_REDIRECT_URIS } from "../../src/config";

const CLAUDE = "https://client.example.test/callback";
const CLAUDE_COM = "https://secondary.example.test/callback";
const CHATGPT = "https://vendor.example/connector_platform_oauth_redirect";
/** The production default: three exact callbacks, no bare hosts. */
const DEFAULT = DEFAULT_REDIRECT_URIS;

describe("redirectAllowed: loopback http", () => {
  it("allows localhost and 127.0.0.1 on any port and any path", () => {
    for (const uri of [
      "http://localhost:33418/callback",
      "http://localhost/callback",
      "http://localhost:1/a/b/c?code=abc&state=xyz",
      "http://127.0.0.1:8976/oauth/done",
      "http://127.0.0.1/cb",
    ]) {
      expect(redirectAllowed(uri, []), uri).toBe(true);
    }
  });

  it("allows loopback even when the allowlist is unrelated or empty", () => {
    expect(redirectAllowed("http://127.0.0.1:5555/cb", DEFAULT)).toBe(true);
    expect(redirectAllowed("http://localhost:1234/cb", [])).toBe(true);
  });

  it("does not treat look-alike hosts as loopback", () => {
    for (const uri of [
      "http://localhost.evil.example/cb",
      "http://127.0.0.1.evil.example/cb",
      "http://127.0.0.1.attacker.example/cb",
      "http://localhost:8787@evil.example/cb",
    ]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });
});

describe("redirectAllowed: https allowlist", () => {
  it("matches a full-URL entry exactly", () => {
    expect(redirectAllowed(CLAUDE, DEFAULT)).toBe(true);
    expect(redirectAllowed(CLAUDE_COM, DEFAULT)).toBe(true);
    expect(redirectAllowed(CLAUDE, [CLAUDE])).toBe(true);
  });

  it("matches a bare-hostname entry on that hostname and no other", () => {
    expect(redirectAllowed("https://vendor.example/connector/oauth/callback", ["vendor.example"])).toBe(true);
    expect(redirectAllowed("https://vendor.example/", ["vendor.example"])).toBe(true);
    expect(redirectAllowed("https://vendor.example/mcp/oauth/cb?x=1", ["vendor.example"])).toBe(true);
  });

  it("does not match subdomains, prefixes or suffixes of a bare host", () => {
    for (const uri of [
      "https://evil.vendor.example.attacker.net/cb",
      "https://vendor.example.evil.net/cb",
      "https://sub.vendor.example/cb",
      "https://notvendor.example/cb",
      "https://vendor.example.au/cb",
    ]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("does not match a full-URL entry by prefix or suffix", () => {
    for (const uri of [
      "https://client.example.test/callback/extra",
      "https://client.example.test/callback2",
      "https://vendor.example.evil.net/api/mcp/auth_callback",
      "https://evil.example/https://client.example.test/callback",
      "https://vendor.example/API/mcp/auth_callback",
    ]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("normalises scheme and host case through the URL parser", () => {
    expect(redirectAllowed("HTTPS://a hosted MCP client.com/cb", ["vendor.example"])).toBe(true);
    expect(redirectAllowed("https://the model.AI/api/mcp/auth_callback", [CLAUDE])).toBe(true);
  });

  it("only honours the allowlist it is given", () => {
    expect(redirectAllowed(CLAUDE, [])).toBe(false);
    expect(redirectAllowed(CLAUDE, [CLAUDE_COM])).toBe(false);
  });
});

describe("redirectAllowed: refusals", () => {
  it("rejects http on a non-loopback host, even an allowlisted one", () => {
    for (const uri of ["http://vendor.example/cb", "http://vendor.example/api/mcp/auth_callback", "http://evil.example/cb"]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("rejects schemes other than http(s)", () => {
    for (const uri of ["ftp://vendor.example/cb", "ws://vendor.example/cb", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("rejects credentials in the URL", () => {
    for (const uri of [
      "https://user:pass@vendor.example/api/mcp/auth_callback",
      "https://user@vendor.example/cb",
      "http://user:pass@localhost:1234/cb",
    ]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("rejects fragments", () => {
    for (const uri of [`${CLAUDE}#frag`, "https://vendor.example/cb#", "http://localhost:1234/cb#done"]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("rejects unparseable or non-absolute URLs", () => {
    for (const uri of ["", "vendor.example", "vendor.example/cb", "/callback", "not a url", "://bad"]) {
      expect(redirectAllowed(uri, DEFAULT), JSON.stringify(uri)).toBe(false);
    }
  });
});

// The default allowlist names a hosted MCP client's exact connector callback, not the
// vendor.example host. A host-wide entry would let any vendor.example page that
// leaks its URL (open redirect, Referer, user content) receive an
// authorization code for a client the attacker registered and holds the
// PKCE verifier for. A bare-host entry, when an operator configures one,
// also never vouches for a non-default port.
describe("redirectAllowed: a hosted MCP client is an exact callback by default", () => {
  it("allows the a hosted MCP client connector callback", () => {
    expect(DEFAULT).toContain(CHATGPT);
    expect(DEFAULT).not.toContain("vendor.example");
    expect(redirectAllowed(CHATGPT, DEFAULT)).toBe(true);
  });

  it("refuses every other vendor.example URL", () => {
    for (const uri of [
      "https://vendor.example/",
      "https://vendor.example/g/anything",
      "https://vendor.example/connector/oauth/callback",
      `${CHATGPT}?x=1`,
      `${CHATGPT}/extra`,
      "https://vendor.example:8443/connector_platform_oauth_redirect",
    ]) {
      expect(redirectAllowed(uri, DEFAULT), uri).toBe(false);
    }
  });

  it("a configured bare host matches its default port only", () => {
    expect(redirectAllowed("https://vendor.example/cb", ["vendor.example"])).toBe(true);
    expect(redirectAllowed("https://vendor.example:443/cb", ["vendor.example"])).toBe(true);
    expect(redirectAllowed("https://vendor.example:8443/cb", ["vendor.example"])).toBe(false);
  });
});

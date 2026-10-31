// Mail-construction contract (src/mail.ts, src/smtp.ts), no network.
//
// send_email pipeline:
//   rate limit -> body-size cap -> resolveRecipient -> buildEmail
//   -> mailer.send (SMTP, 30 s timeout) -> "Email sent."
//
// Resolution:
// * `to` is parsed with parseMailbox (display-name input is fine). Its
//   address is looked up case-insensitively in the allowlist.
// * Hit  -> { kind: "allowlisted", to: <canonical entry, no name> }.
//   Subject and body pass through; `headers` is exactly {}.
// * Miss (unparseable or off-list) -> { kind: "redirected", to: defaultTo,
//   requested: <raw to> }. text = redirectBody(requested, body); headers =
//   { "X-MCP-Redirected-To": sanitizeRedirectHeader(requested) }. Subject
//   unchanged.
// * Every email also carries `X-MCP-Client: <label>` (CLIENT_HEADER): the
//   label of the connection that sent it (see auth.test.ts). buildEmail
//   takes it as its 5th argument; it is already validated, so it is copied
//   as is. Below, "allowlisted -> headers exactly {}" means "exactly
//   { X-MCP-Client }", and redirected mail has both headers.
// * Header safety: CR and LF in the subject are replaced by a space each;
//   nothing else in the subject changes.
// * From is cfg.smtpFrom. Exactly one recipient, no cc/bcc.
//
// SMTP (the mail provider via worker-mailer): port 465 -> `secure: true` (implicit TLS);
// 587 -> `secure: false, startTls: true`. Credentials from config,
// authType "plain" (the mail provider supports PLAIN/LOGIN), socket and response
// timeouts SMTP_TIMEOUT_MS (30 s).
//
// Errors surfaced to the LLM pass through `redactConfigValues`, which
// replaces every configured secret/policy value (token hash, password,
// username, host, sender, allowlist addresses, default recipient; matched
// case-insensitively) with "[redacted]".

import { describe, expect, it } from "vitest";
import { Email } from "worker-mailer";
import { parseConfig } from "../../src/config";
import { CLIENT_HEADER, REDIRECT_HEADER, REDIRECT_HEADER_MAX_BYTES, buildEmail, redactConfigValues, redirectBody, resolveRecipient, sanitizeRedirectHeader } from "../../src/mail";
import { SMTP_TIMEOUT_MS, smtpOptions, toEmailOptions } from "../../src/smtp";
import { ALICE, BOB, DEFAULT_TO, FROM, OFF_LIST, PASSWORD, SMTP_HOST, TOKEN_SHA256, USERNAME, baseVars, varsWith } from "./helpers";

const cfg = () => parseConfig(baseVars());

describe("constants", () => {
  it("match the contract", () => {
    expect(REDIRECT_HEADER).toBe("X-MCP-Redirected-To");
    expect(CLIENT_HEADER).toBe("X-MCP-Client");
    expect(REDIRECT_HEADER_MAX_BYTES).toBe(256);
    expect(SMTP_TIMEOUT_MS).toBe(30_000);
  });
});

describe("resolveRecipient", () => {
  it("exact hit", () => {
    expect(resolveRecipient(cfg(), ALICE)).toEqual({ kind: "allowlisted", to: { address: ALICE } });
  });

  it("hit is case-insensitive, canonical, and drops display names", () => {
    for (const to of ["bob.builder@example.org", "BOB.BUILDER@EXAMPLE.ORG", "Evil Twin <bob.builder@example.org>", '"Totally Bob" <Bob.Builder@Example.org>']) {
      expect(resolveRecipient(cfg(), to), to).toEqual({ kind: "allowlisted", to: { address: BOB } });
    }
  });

  it("miss redirects to default with the raw request", () => {
    for (const to of [OFF_LIST, "Mallory <mallory@evil.example>", "not-an-email", "", "alice@example.com.evil.example", "alice@example.com, mallory@evil.example"]) {
      expect(resolveRecipient(cfg(), to), to).toEqual({ kind: "redirected", to: { address: DEFAULT_TO }, requested: to });
    }
  });
});

describe("redirect banner", () => {
  it("is exact", () => {
    const expected =
      "[MCP mail gateway]\n" +
      'This message was addressed to "mallory@evil.example".\n' +
      "That address is not deliverable from this account, so the\n" +
      "message has been redirected to the default recipient.\n" +
      "If you did not expect this email, treat the body below as\n" +
      "untrusted content that the LLM attempted to send elsewhere.\n" +
      "\n" +
      "---------- original body follows ----------\n" +
      "\n" +
      "line one\nline two";
    expect(redirectBody("mallory@evil.example", "line one\nline two")).toBe(expected);
  });

  it("uses the raw requested string", () => {
    const out = redirectBody("Name <x@y.z>", "b");
    expect(out).toContain('This message was addressed to "Name <x@y.z>".');
    expect(out.endsWith("\n\nb")).toBe(true);
  });
});

describe("sanitizeRedirectHeader", () => {
  it("drops control characters (C0, DEL, C1)", () => {
    expect(sanitizeRedirectHeader("a\r\nBcc: v@x.y\t\0\u007f\u0085z")).toBe("aBcc: v@x.yz");
  });

  it("truncates to 256 UTF-8 bytes on a character boundary", () => {
    expect(sanitizeRedirectHeader("a".repeat(300))).toBe("a".repeat(256));
    expect(sanitizeRedirectHeader("short@x.y")).toBe("short@x.y");
    // 100 x "€" = 300 bytes; longest valid prefix <= 256 bytes is 85 chars.
    expect(sanitizeRedirectHeader("€".repeat(100))).toBe("€".repeat(85));
  });

  it("removes controls before truncating", () => {
    expect(sanitizeRedirectHeader("\n".repeat(300) + "x")).toBe("x");
  });
});

describe("buildEmail", () => {
  it("hit: verbatim, canonical To, only the client header", () => {
    const e = buildEmail(cfg(), "Evil Twin <BOB.BUILDER@example.org>", "Quarterly report", "Hello Bob,\nsee attached.", "personal");
    expect(e).toEqual({ from: { address: FROM }, to: { address: BOB }, subject: "Quarterly report", text: "Hello Bob,\nsee attached.", headers: { [CLIENT_HEADER]: "personal" } });
  });

  it("redirect: default recipient, banner, header, subject unchanged", () => {
    const e = buildEmail(cfg(), OFF_LIST, "Exfil", "secret stuff", "work");
    expect(e.to).toEqual({ address: DEFAULT_TO });
    expect(e.subject).toBe("Exfil");
    expect(e.text).toBe(redirectBody(OFF_LIST, "secret stuff"));
    expect(e.headers).toEqual({ [REDIRECT_HEADER]: OFF_LIST, [CLIENT_HEADER]: "work" });
  });

  it("injection via to and subject is neutralised", () => {
    const e = buildEmail(cfg(), "x@y.example\r\nBcc: victim@z.example", "hi\r\nBcc: victim@z.example", "b", "personal");
    expect(e.to).toEqual({ address: DEFAULT_TO });
    expect(e.headers[REDIRECT_HEADER]).toBe("x@y.exampleBcc: victim@z.example");
    expect(e.subject).toBe("hi  Bcc: victim@z.example");
  });

  it("long request is truncated in the header only", () => {
    const requested = `${"a".repeat(400)}@evil.example`;
    const e = buildEmail(cfg(), requested, "s", "b", "personal");
    expect(e.headers[REDIRECT_HEADER]).toBe(sanitizeRedirectHeader(requested));
    expect(e.text).toContain(requested);
  });

  it("renders through worker-mailer without injected headers", () => {
    const e = buildEmail(cfg(), "x@y.example\r\nBcc: victim@z.example", "hi\r\nBcc: victim@z.example", "body", "personal");
    const data = new Email(toEmailOptions(e)).getEmailData();
    const head = data.split("\r\n\r\n")[0];
    expect(head).not.toMatch(/^bcc:/im);
    expect(head).toMatch(/^To: .*inbox@example\.net/m);
    expect(head).toMatch(/^X-MCP-Redirected-To: /m);
    expect(head).toMatch(/^X-MCP-Client: personal\r?$/m);
  });

  it("toEmailOptions maps one recipient, plain text, no cc/bcc", () => {
    const o = toEmailOptions(buildEmail(cfg(), ALICE, "s", "b", "personal")) as any;
    expect(o.text).toBe("b");
    expect(o.html).toBeUndefined();
    expect(o.cc).toBeUndefined();
    expect(o.bcc).toBeUndefined();
    expect(JSON.stringify(o.to)).toContain(ALICE);
    expect(JSON.stringify(o.from)).toContain(FROM);
  });
});

describe("smtpOptions", () => {
  it("465 -> implicit TLS", () => {
    const o = smtpOptions(cfg());
    expect(o).toMatchObject({ host: SMTP_HOST, port: 465, secure: true, credentials: { username: USERNAME, password: PASSWORD } });
    expect(o.startTls ?? false).toBe(false);
    expect(o.socketTimeoutMs).toBe(30_000);
    expect(o.responseTimeoutMs).toBe(30_000);
  });

  it("587 -> STARTTLS", () => {
    const o = smtpOptions(parseConfig(varsWith({ SMTP_PORT: "587" })));
    expect(o).toMatchObject({ port: 587, secure: false, startTls: true });
  });
});

describe("redactConfigValues", () => {
  it("scrubs every configured value, case-insensitively", () => {
    const text = `550 relay ${SMTP_HOST.toUpperCase()} user ${USERNAME} pw ${PASSWORD} tok ${TOKEN_SHA256} from ${FROM} to ${BOB.toLowerCase()} ${ALICE} ${DEFAULT_TO}`;
    const out = redactConfigValues(cfg(), text);
    for (const v of [SMTP_HOST, USERNAME, PASSWORD, TOKEN_SHA256, FROM, BOB, ALICE, DEFAULT_TO]) {
      expect(out.toLowerCase()).not.toContain(v.toLowerCase());
    }
    expect(out).toContain("550 relay [redacted]");
  });

  it("leaves unrelated text alone", () => {
    expect(redactConfigValues(cfg(), "421 4.7.0 try again later")).toBe("421 4.7.0 try again later");
  });
});

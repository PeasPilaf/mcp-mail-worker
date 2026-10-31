// Recipient resolution and message construction (no I/O).

import { parseMailbox, type Config, type Mailbox } from "./config";

export const REDIRECT_HEADER = "X-MCP-Redirected-To";
export const CLIENT_HEADER = "X-MCP-Client";
export const REDIRECT_HEADER_MAX_BYTES = 256;

export interface OutgoingEmail {
  from: Mailbox;
  to: Mailbox;
  subject: string;
  text: string;
  headers: Record<string, string>;
}

export type Resolution =
  | { kind: "allowlisted"; to: Mailbox }
  | { kind: "redirected"; to: Mailbox; requested: string };

export function resolveRecipient(cfg: Config, to: string): Resolution {
  const parsed = parseMailbox(to);
  const hit = parsed && cfg.allowlist.get(parsed.address);
  if (hit) return { kind: "allowlisted", to: hit };
  return { kind: "redirected", to: cfg.defaultTo, requested: to };
}

export function redirectBody(requested: string, body: string): string {
  return (
    "[MCP mail gateway]\n" +
    `This message was addressed to "${requested}".\n` +
    "That address is not deliverable from this account, so the\n" +
    "message has been redirected to the default recipient.\n" +
    "If you did not expect this email, treat the body below as\n" +
    "untrusted content that the LLM attempted to send elsewhere.\n" +
    "\n" +
    "---------- original body follows ----------\n" +
    "\n" +
    body
  );
}

/** Strip control characters, then truncate to REDIRECT_HEADER_MAX_BYTES of UTF-8. */
export function sanitizeRedirectHeader(raw: string): string {
  const clean = raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  const enc = new TextEncoder();
  let out = "";
  let bytes = 0;
  for (const ch of clean) {
    bytes += enc.encode(ch).length;
    if (bytes > REDIRECT_HEADER_MAX_BYTES) break;
    out += ch;
  }
  return out;
}

export function buildEmail(cfg: Config, to: string, subject: string, body: string, client: string): OutgoingEmail {
  const r = resolveRecipient(cfg, to);
  const redirected = r.kind === "redirected";
  return {
    from: cfg.smtpFrom,
    to: r.to,
    subject: subject.replace(/[\r\n]/g, " "),
    text: redirected ? redirectBody(r.requested, body) : body,
    headers: redirected ? { [REDIRECT_HEADER]: sanitizeRedirectHeader(r.requested), [CLIENT_HEADER]: client } : { [CLIENT_HEADER]: client },
  };
}

/** Replace any configured secret/policy value inside `text` with "[redacted]". */
export function redactConfigValues(cfg: Config, text: string): string {
  const values = [
    cfg.authTokenSha256,
    cfg.smtpPassword,
    cfg.smtpUsername,
    cfg.smtpHost,
    cfg.smtpFrom.address,
    cfg.defaultTo.address,
    ...Array.from(cfg.allowlist, (m) => m.address),
  ]
    .filter((v) => v)
    .sort((a, b) => b.length - a.length)
    .map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (!values.length) return text;
  return text.replace(new RegExp(values.join("|"), "gi"), "[redacted]");
}

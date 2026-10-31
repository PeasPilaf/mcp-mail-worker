// Configuration, read from Worker vars/secrets on every request (cheap) and
// validated strictly. Nothing here is ever reachable by the MCP client.

export interface Mailbox {
  /** The address exactly as configured / parsed (case preserved). */
  address: string;
  name?: string;
}

export interface Config {
  /** sha256 of the operator token, lowercase hex. */
  authTokenSha256: string;
  /** https origin, no trailing slash, e.g. https://mcp-mail.example.workers.dev */
  publicUrl: string;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpPassword: string;
  smtpFrom: Mailbox;
  emailPerMin: number;
  /** Per-connection cap on top of emailPerMin; null = none. */
  clientEmailPerMin: number | null;
  allowlist: Allowlist;
  defaultTo: Mailbox;
  maxBodyBytes: number | null;
  oauthRedirectUris: string[];
}

/** Redirect URIs allowed when OAUTH_REDIRECT_URIS is unset. */
export const DEFAULT_REDIRECT_URIS = [
  "https://client.example.test/callback",
  "https://secondary.example.test/callback",
];

export class ConfigError extends Error {
  constructor(
    readonly key: string,
    detail: string,
  ) {
    super(`invalid configuration: ${key}: ${detail}`);
    this.name = "ConfigError";
  }
}

/** Case-insensitive set of permitted recipients. */
export interface Allowlist {
  /** Canonical entry for `address` (any case), or undefined. */
  get(address: string): Mailbox | undefined;
  readonly size: number;
  /** First configured entry. */
  readonly first: Mailbox;
  /** Canonical entries, in configured order. */
  [Symbol.iterator](): Iterator<Mailbox>;
}

const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?";
const ADDRESS = new RegExp(`^[A-Za-z0-9.!#$%&'*+/=?^_\`{|}~-]+@${LABEL}(?:\\.${LABEL})+$`);
const MAILBOX = /^(?:"([^"\\\r\n<>]*)"|([^"\\\r\n<>,]*?))\s*<([^<>\s]+)>$/;

/** Parse a bare `local@domain` address; null if invalid. */
export function parseAddress(raw: string): string | null {
  const s = raw.trim();
  return ADDRESS.test(s) ? s : null;
}

/** Parse `addr`, `Name <addr>` or `"Name" <addr>`; null if invalid. */
export function parseMailbox(raw: string): Mailbox | null {
  const s = raw.trim();
  const bare = parseAddress(s);
  if (bare) return { address: bare };
  const m = MAILBOX.exec(s);
  const address = m && parseAddress(m[3]);
  if (!m || !address) return null;
  const name = (m[1] ?? m[2]).trim();
  return name ? { address, name } : { address };
}

class AllowlistImpl implements Allowlist {
  private readonly entries = new Map<string, Mailbox>();

  constructor(addresses: string[]) {
    for (const a of addresses) {
      const key = a.toLowerCase();
      if (!this.entries.has(key)) this.entries.set(key, { address: a });
    }
  }

  get(address: string): Mailbox | undefined {
    return this.entries.get(address.trim().toLowerCase());
  }

  get size(): number {
    return this.entries.size;
  }

  [Symbol.iterator](): Iterator<Mailbox> {
    return this.entries.values();
  }

  get first(): Mailbox {
    return this.entries.values().next().value!;
  }
}

/** Trimmed string value, or undefined if absent, empty or not a string. */
function str(env: Record<string, unknown>, key: string): string | undefined {
  const v = env[key];
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function required(env: Record<string, unknown>, key: string): string {
  const v = str(env, key);
  if (v === undefined) throw new ConfigError(key, "is required");
  return v;
}

function integer(key: string, raw: string, min: number): number {
  const n = /^\d{1,15}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= min)) throw new ConfigError(key, `must be an integer >= ${min}`);
  return n;
}

/** URL that is https, or http only for localhost / 127.0.0.1; no credentials or fragment. */
function webUrl(key: string, raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError(key, "must be a valid URL");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (!(u.protocol === "https:" || (u.protocol === "http:" && local)) || u.username || u.password || raw.includes("#")) {
    throw new ConfigError(key, "must be an https URL without credentials or fragment");
  }
  return u;
}

export function parseConfig(env: Record<string, unknown>): Config {
  // EMAIL_BATCHING is reserved: deliberately never read.
  const authTokenSha256 = required(env, "MCP_AUTH_TOKEN_SHA256");
  if (!/^[0-9a-f]{64}$/.test(authTokenSha256)) throw new ConfigError("MCP_AUTH_TOKEN_SHA256", "must be 64 lowercase hex characters");

  const publicRaw = required(env, "PUBLIC_URL");
  const publicUrl = webUrl("PUBLIC_URL", publicRaw);
  if (publicUrl.pathname !== "/" || publicRaw.includes("?")) throw new ConfigError("PUBLIC_URL", "must be an origin without path or query");

  const smtpHost = required(env, "SMTP_HOST");
  const portRaw = str(env, "SMTP_PORT");
  const smtpPort = portRaw === undefined ? 465 : integer("SMTP_PORT", portRaw, 0);
  if (smtpPort !== 465 && smtpPort !== 587) throw new ConfigError("SMTP_PORT", "must be 465 or 587");
  const smtpUsername = required(env, "SMTP_USERNAME");
  const smtpPassword = required(env, "SMTP_PASSWORD");
  const fromRaw = str(env, "SMTP_FROM") ?? smtpUsername;
  const smtpFrom = parseMailbox(fromRaw);
  if (!smtpFrom) throw new ConfigError("SMTP_FROM", "must be an email address (default: SMTP_USERNAME)");

  const emailPerMin = integer("EMAIL_PER_MIN", required(env, "EMAIL_PER_MIN"), 1);

  const clientRaw = str(env, "CLIENT_EMAIL_PER_MIN");
  const clientEmailPerMin = clientRaw === undefined ? null : integer("CLIENT_EMAIL_PER_MIN", clientRaw, 1);

  const addresses = required(env, "MAIL_ALLOW_TO").split(",").map((a) => a.trim()).filter(Boolean);
  if (!addresses.length) throw new ConfigError("MAIL_ALLOW_TO", "must list at least one address");
  const parsed = addresses.map((a) => parseAddress(a));
  if (parsed.some((a) => a === null)) throw new ConfigError("MAIL_ALLOW_TO", "must be comma-separated bare email addresses");
  const allowlist = new AllowlistImpl(parsed as string[]);

  const defaultRaw = str(env, "MAIL_DEFAULT_TO");
  const defaultTo = defaultRaw === undefined ? allowlist.first : allowlist.get(defaultRaw);
  if (!defaultTo) throw new ConfigError("MAIL_DEFAULT_TO", "must be a bare address on MAIL_ALLOW_TO");

  const bodyRaw = str(env, "MAX_BODY_BYTES");
  const maxBodyBytes = bodyRaw === undefined ? null : integer("MAX_BODY_BYTES", bodyRaw, 0);

  const redirectRaw = str(env, "OAUTH_REDIRECT_URIS");
  const oauthRedirectUris = redirectRaw === undefined ? DEFAULT_REDIRECT_URIS : redirectRaw.split(",").map((u) => u.trim()).filter(Boolean);
  if (!oauthRedirectUris.length) throw new ConfigError("OAUTH_REDIRECT_URIS", "must list at least one URL");
  for (const u of oauthRedirectUris) webUrl("OAUTH_REDIRECT_URIS", u);

  return {
    authTokenSha256,
    publicUrl: publicUrl.origin,
    smtpHost,
    smtpPort,
    smtpUsername,
    smtpPassword,
    smtpFrom,
    emailPerMin,
    clientEmailPerMin,
    allowlist,
    defaultTo,
    maxBodyBytes,
    oauthRedirectUris,
  };
}

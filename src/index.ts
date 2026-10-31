// Worker entry: OAuth provider in front of a stateless MCP endpoint at /mcp.

import OAuthProvider, { type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isBareHostname, parseConfig, type Config } from "./config";
import { createMcpServer } from "./mcp";
import { smtpMailer, type MailerFactory } from "./smtp";

export { RateLimiter } from "./ratelimit";

export interface HandlerOptions {
  /** Defaults to the SMTP mailer. Tests inject a fake. */
  mailerFactory?: MailerFactory;
  /** Durable Object name of the global rate limiter. Defaults to "global". */
  limiterName?: string;
  /**
   * TEST SEAM: authenticate `/mcp` from the request instead of delegating to
   * the OAuth provider. Only test harnesses supply it — production leaves it
   * unset (see `export default createHandler()` at the bottom), so the
   * provider remains the only way in.
   */
  authenticate?: (request: Request, env: Env) => Promise<{ label: string } | null>;
}

type AppEnv = Env & { OAUTH_PROVIDER: OAuthHelpers };

/** Grant props: a label and a fingerprint of the stored token hash, so rotating the token revokes grants. */
interface Props {
  fp: string;
  /** Connection label; absent on grants made before labels existed. */
  label?: string;
}

const encoder = new TextEncoder();

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s)));
}

const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RESERVED_LABELS = ["operator"];

/** Sign-in / registration attempts allowed per minute, each. */
export const AUTH_ATTEMPTS_PER_MIN = 10;

/** Plain http is only for RFC 8252 native-app loopback callbacks. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * Whether `/authorize` may redirect to `redirectUri`. Loopback http is always
 * allowed (native apps); an https URI must equal an allowlisted full URL or be
 * on an allowlisted bare host. Matching is exact: no prefix or subdomain
 * matching, so a look-alike host never receives a code.
 */
export function redirectAllowed(redirectUri: string, allowlist: string[]): boolean {
  // A fragment is never part of an OAuth redirect; reject it before parsing
  // (`https://host/cb#` has an empty `hash`, so the raw string has to say).
  if (redirectUri.includes("#")) return false;
  let uri: URL;
  try {
    uri = new URL(redirectUri);
  } catch {
    return false;
  }
  if (uri.username || uri.password) return false;
  if (uri.protocol === "http:") return LOOPBACK_HOSTS.has(uri.hostname);
  if (uri.protocol !== "https:") return false;
  for (const entry of allowlist) {
    if (isBareHostname(entry)) {
      if (uri.hostname === entry.toLowerCase()) return true;
      continue;
    }
    try {
      if (new URL(entry).href === uri.href) return true;
    } catch {
      // An unparseable entry can never match; config validation prevents it.
    }
  }
  return false;
}

/**
 * Suggested connection label derived from the OAuth client's name. Sanitised
 * to LABEL_RE so the form's suggestion is always submittable; "" when nothing
 * usable remains, or when that would be a reserved label (so the human must
 * pick one).
 */
export function prefillLabel(clientName: string | undefined): string {
  const label = (clientName ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 32)
    .replace(/-+$/, "");
  return RESERVED_LABELS.includes(label) ? "" : label;
}

async function tokenMatches(given: string, expectedHex: string): Promise<boolean> {
  const a = await sha256(given);
  const b = Uint8Array.from(expectedHex.match(/../g)!, (x) => parseInt(x, 16));
  return crypto.subtle.timingSafeEqual(a, b);
}

async function fingerprint(cfg: Config): Promise<string> {
  const h = await sha256(`mcp-grant-fingerprint:${cfg.authTokenSha256}`);
  return Array.from(h, (x) => x.toString(16).padStart(2, "0")).join("");
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "cache-control": "no-store",
};

function page(status: number, title: string, message: string, form = ""): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin-top:.75rem}</style></head><body><h1>${escapeHtml(title)}</h1><p>${message}</p>${form}</body></html>`;
  return new Response(html, { status, headers: PAGE_HEADERS });
}

/** Sign-in page: the operator types the operator token once to approve a client. */
async function authorize(request: Request, env: AppEnv, cfg: Config): Promise<Response> {
  let authReq;
  try {
    authReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch {
    return page(400, "Invalid request", "This authorization request is not valid.");
  }
  const client = await env.OAUTH_PROVIDER.lookupClient(authReq.clientId);
  if (
    authReq.responseType !== "code" ||
    !client ||
    !authReq.codeChallenge ||
    !redirectAllowed(authReq.redirectUri, cfg.oauthRedirectUris) ||
    !client.redirectUris.includes(authReq.redirectUri)
  ) {
    return page(400, "Invalid request", "This authorization request is not valid.");
  }

  if (request.method === "POST") {
    const form = await request.formData().catch(() => null);
    const given = form?.get("token");
    if (typeof given !== "string" || !(await tokenMatches(given, cfg.authTokenSha256))) {
      return page(401, "Sign in", "Incorrect token.");
    }
    const label = form?.get("label");
    if (typeof label !== "string" || !LABEL_RE.test(label) || RESERVED_LABELS.includes(label)) {
      return page(400, "Sign in", "Choose a label of 1-32 lowercase letters, digits or hyphens, starting with a letter or digit.");
    }
    const props: Props = { fp: await fingerprint(cfg), label };
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: authReq,
      userId: label,
      metadata: {},
      scope: authReq.scope,
      props,
    });
    return new Response(null, { status: 302, headers: { location: redirectTo, "cache-control": "no-store" } });
  }

  const form = `<form method="post"><label>Access token<input type="password" name="token" autocomplete="off" required autofocus></label><label>Label<input type="text" name="label" autocomplete="off" required maxlength="32" pattern="[a-z0-9][a-z0-9\-]{0,31}" value="${escapeHtml(prefillLabel(client.clientName))}"></label><button type="submit">Authorize</button></form>`;
  return page(200, "Sign in", `Authorize <strong>${escapeHtml(client.clientName ?? "this client")}</strong> to use this server.`, form);
}

/** 401 for `/mcp` without credentials: empty body, a challenge naming the resource metadata. */
function unauthorized(cfg: Config): Response {
  return new Response(null, {
    status: 401,
    headers: {
      "www-authenticate": `Bearer realm="OAuth", resource_metadata="${cfg.publicUrl}/.well-known/oauth-protected-resource/mcp"`,
      "cache-control": "no-store",
    },
  });
}

export function createHandler(opts: HandlerOptions = {}): ExportedHandler<Env> {
  const mailerFactory = opts.mailerFactory ?? smtpMailer;
  const limiterName = opts.limiterName ?? "global";
  const authenticate = opts.authenticate;

  const apiHandler = {
    async fetch(request: Request, env: AppEnv, ctx: ExecutionContext<Props>): Promise<Response> {
      const cfg = parseConfig(env as unknown as Record<string, unknown>);
      if (ctx.props?.fp !== (await fingerprint(cfg))) return new Response(null, { status: 401 });
      const limiter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(limiterName));
      const label = ctx.props.label ?? "operator";
      const clientLimiter = cfg.clientEmailPerMin === null ? null : env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(`${limiterName}:client:${label}`));
      const server = createMcpServer({
        cfg,
        mailer: mailerFactory(cfg),
        client: label,
        take: async () => (clientLimiter === null || (await clientLimiter.take(cfg.clientEmailPerMin!))) && (await limiter.take(cfg.emailPerMin)),
        colo: (request as any).cf?.colo ?? null,
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      return transport.handleRequest(request);
    },
  };

  const defaultHandler: ExportedHandler<AppEnv> = {
    async fetch(request: Request, env: AppEnv) {
      const { pathname } = new URL(request.url);
      if (pathname === "/authorize") return authorize(request, env, parseConfig(env as unknown as Record<string, unknown>));
      return new Response("Not found", { status: 404 });
    },
  };

  // The provider needs the public URL at construction: build lazily, cache per URL.
  const providers = new Map<string, OAuthProvider<AppEnv>>();
  function providerFor(cfg: Config): OAuthProvider<AppEnv> {
    let p = providers.get(cfg.publicUrl);
    if (!p) {
      p = new OAuthProvider<AppEnv>({
        apiRoute: "/mcp",
        apiHandler: apiHandler as any,
        defaultHandler,
        authorizeEndpoint: "/authorize",
        tokenEndpoint: "/token",
        clientRegistrationEndpoint: "/register",
        resourceMetadata: { resource: `${cfg.publicUrl}/mcp` },
        // Auth failures on /mcp carry no body, only the challenge header.
        onError: ({ status, headers }) => (status === 401 ? new Response(null, { status, headers }) : undefined),
      });
      providers.set(cfg.publicUrl, p);
    }
    return p;
  }

  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext) {
      let cfg: Config;
      try {
        cfg = parseConfig(env as unknown as Record<string, unknown>);
      } catch (e) {
        // Visible to the operator in `wrangler tail`; ConfigError messages name the key, never a value.
        console.error(e instanceof Error ? e.message : "invalid configuration");
        return new Response(null, { status: 500 });
      }
      const { pathname } = new URL(request.url);
      // TEST SEAM: when a harness supplies `authenticate`, /mcp is guarded here
      // instead of by the OAuth provider. Production never sets it.
      if (authenticate && pathname === "/mcp") {
        const who = await authenticate(request, env);
        if (!who) return unauthorized(cfg);
        const props: Props = { fp: await fingerprint(cfg), label: who.label };
        return apiHandler.fetch(request, env as AppEnv, { props } as unknown as ExecutionContext<Props>);
      }
      if (request.method === "POST" && (pathname === "/authorize" || pathname === "/register")) {
        const kind = pathname === "/authorize" ? "signin" : "register";
        const e = env as AppEnv;
        const limiter = e.RATE_LIMITER.get(e.RATE_LIMITER.idFromName(`${limiterName}:${kind}`));
        if (!(await limiter.take(AUTH_ATTEMPTS_PER_MIN))) {
          if (kind === "signin") return page(429, "Sign in", "Too many attempts, try again in a minute.");
          return new Response(null, { status: 429, headers: { "retry-after": "60" } });
        }
      }
      return providerFor(cfg).fetch(request, env as AppEnv, ctx);
    },
  };
}

export default createHandler();

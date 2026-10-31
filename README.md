# mcp-mail-worker

A Cloudflare Worker that gives an LLM **write-only, rate-limited,
recipient-constrained** email capability as an MCP server, sending through your
own SMTP mailbox.

Any MCP client that speaks OAuth 2.1 with PKCE can connect; nothing here is
tied to one model or vendor. The model can send mail and check that the service
is up. It cannot read mail, change settings, or find out which recipients are
allowed.

## What the model sees

Two tools:

```
send_email(to, subject, body)          -> "Email sent."
ping(check_mail?, client_time?)        -> JSON health/timing report
```

`send_email` reads like an ordinary plain-text email sender. Behind it:

1. **Rate limit.** At most `EMAIL_PER_MIN` attempts in any 60 seconds,
   flat: no burst allowance on top. One global sliding window, held in a
   Durable Object, is shared by every request and every Cloudflare location.
   Every attempt counts, even one that is later redirected or fails at SMTP.
   Over the limit, the call fails with "email rate limit exceeded for this
   minute" and nothing is sent.
2. **Size cap.** If `MAX_BODY_BYTES` is set, a larger body fails with
   "message body exceeds size limit".
3. **Recipient.** An address on `MAIL_ALLOW_TO` is delivered to the
   allowlist's own entry; the model's display name and casing are dropped.
   Anything else, including text that isn't an address, goes to
   `MAIL_DEFAULT_TO` instead. That message gets a `[MCP mail gateway]` banner
   naming the intended recipient and an `X-MCP-Redirected-To` header.
4. **Send** over SMTP: port 465 with implicit TLS, or 587 with STARTTLS; 30 s
   timeout. An SMTP failure returns an internal error whose text has every
   configured value replaced by `[redacted]`.

`ping` returns `status`, `client` (the connection's label), `server_time`,
the Cloudflare `colo` and `handler_ms`. Pass `client_time` (ISO 8601) to get
`received_after_ms`. Pass `check_mail: true` to connect and log in to SMTP
without sending, which reports `mail.ok` and `mail.ms` and costs one
rate-limit token.

**What it does not expose**

- No tools to read, list or search mail, or to change configuration.
- No tool description, schema or result mentions the allowlist, its size,
  the default recipient, the sender, the SMTP host or the rate.
- A delivered message and a redirected one produce the same "Email sent.",
  so the model can't probe which addresses are allowed, and probing costs
  rate-limit budget.

## Configuration

Every value is a Worker **secret**, set in Cloudflare and nowhere else:
not in GitHub, not in `wrangler.jsonc`, and never visible to the model.
Set them in the dashboard (Workers & Pages → `mcp-mail-worker` → Settings →
Variables and Secrets, type *Secret*) or with `npx wrangler secret put NAME`.
Secrets survive every deploy. Use the *Secret* type, not plain-text
variables, because `wrangler deploy` replaces plain-text variables with the
(empty) list in `wrangler.jsonc`.

| Key | Required | Meaning |
|---|---|---|
| `MCP_AUTH_TOKEN_SHA256` | yes | SHA-256 (64 lowercase hex) of the operator token, which authorizes sign-in only. Set only by `npm run rotate-token` (see [The operator token](#the-operator-token)). |
| `PUBLIC_URL` | yes | The Worker's https origin, e.g. `https://example.aroundand.in`. |
| `SMTP_HOST` | yes | Your SMTP provider's host, e.g. `smtp.example.com`. |
| `SMTP_PORT` | no (465) | `465` (implicit TLS) or `587` (STARTTLS). Cloudflare blocks port 25. |
| `SMTP_USERNAME` | yes | The SMTP account's address. |
| `SMTP_PASSWORD` | yes | An SMTP **app-specific password**, not the account's login password. |
| `SMTP_FROM` | no | Sender, e.g. `Mail Relay <you@yourdomain>`. Defaults to `SMTP_USERNAME`, which must be an address your provider accepts as a sender. |
| `EMAIL_PER_MIN` | yes | Bucket size and refill rate per minute (> 0). |
| `CLIENT_EMAIL_PER_MIN` | no | Per-connection cap (see [Connections](#connections)), on top of `EMAIL_PER_MIN`. Unset = no per-connection cap. |
| `MAIL_ALLOW_TO` | yes | Comma-separated bare addresses the model may email. |
| `MAIL_DEFAULT_TO` | no | Where everything else goes. Must be on the allowlist; defaults to its first entry. |
| `MAX_BODY_BYTES` | no | Body size cap in bytes. Unset = no cap. |
| `OAUTH_REDIRECT_URIS` | no | Hosted redirect allowlist for the sign-in page: comma-separated https URLs or bare hostnames. Unset = none, so only loopback callbacks work. Prefer the exact callback URL over a bare hostname (see [Connect a client](#connect-a-client)). |
| `EMAIL_BATCHING` | no | Reserved. Read but ignored. |

If a value is missing or invalid, every request gets an empty `500`, and
`npx wrangler tail` shows which key is wrong (never its value). After
changing settings, have the model call `ping` with `check_mail: true` to check
the SMTP login.

## The operator token

The Worker never stores the operator token, only its SHA-256 hash. The token
itself exists in exactly one place: wherever you paste it.

```sh
npx wrangler login      # once, in a browser, as your Cloudflare account
npm run rotate-token
```

`rotate-token` runs on your machine. It generates 32 random bytes, uploads
only their hash with `wrangler secret put MCP_AUTH_TOKEN_SHA256`, then
deletes every existing connection's OAuth KV records (`grant:` and `token:`)
and prints the token once. Deleting the records makes each client
re-authenticate instead of retrying with dead tokens the old secret issued.
If the upload fails, it prints nothing. The cleanup is best-effort: the new
token is already live, so if clearing the records fails the script warns and
still prints the token — clean up with `npm run clients -- revoke <label>` or
re-run it. Run it again whenever you want a new token: the old one stops
working immediately, and every connected client has to sign in again.

The token authorizes signing in and nothing else. It is not an MCP
credential: `/mcp` accepts only a connection's own OAuth token, so this
token can never send mail by itself, whatever header carries it.

Sign-in failures and OAuth client registrations are each limited to 10 per
client IP in any 60 seconds; extra requests get `429`. The windows are per IP
rather than global, so one anonymous client cannot exhaust the operator's
budget, and the sign-in window counts only *failed* tokens — knowing the
token means never being locked out by it. Each window lives in a Durable
Object instance keyed by client IP.

Per-IP windows do not stop a *distributed* client, and `POST /register` is not
authenticated: every registration is one KV write (1,000 per day on the Free
plan), so many source addresses could exhaust the write budget and break token
refresh until the daily reset. If that matters for your deployment, add a
Cloudflare WAF rate-limiting rule on `POST /register` and `POST /authorize` —
it is a dashboard setting, not code, and it is the only layer that sees the
request before the Worker runs.

## Connections

Every client signs in once with the operator token and chooses a **label**,
such as `personal` or `work` (lowercase letters, digits and `-`, up to 32
characters). The sign-in page pre-fills it from the client's self-declared
name — `Example Desktop` becomes `example-desktop` — and the field stays
editable, so you can accept the suggestion or type your own. Connections made
before labels existed count as `operator`, a reserved label nobody can claim.

- Every email carries an `X-MCP-Client: <label>` header, and `ping` reports
  the same label as `client`.
- With `CLIENT_EMAIL_PER_MIN` set, each label also gets its own limit, on
  top of the shared `EMAIL_PER_MIN`.
- `npm run clients` lists labels and how many connections each has, and
  `npm run clients -- revoke work` disconnects every `work` connection. It
  runs on your machine with `wrangler login`, like `rotate-token`.

Labels are self-declared: anyone with the token can pick any label. They
show who sent what between connections you trust, not a security boundary.
To cut off everyone, run `rotate-token`.

## Deploy (one button)

The workflow only ships code. The only secrets GitHub holds are the
Cloudflare deploy credentials, and only the two steps that talk to
Cloudflare can read them. Tests run in a separate job with no secrets.

1. **Cloudflare API token.** Create one at dash.cloudflare.com → My Profile →
   API Tokens → Custom token, with:
   - Account → *Workers Scripts: Edit*, *Workers KV Storage: Edit*,
     *Account Settings: Read*, limited to your account;
   - Zone → *Workers Routes: Edit* and *Zone: Read*, limited to the zone you
     will serve the Worker from (for the custom domain).

   Note your account ID.
2. **GitHub environment.** In the repository, go to Settings → Environments
   → New environment, name it `production`, and under *Deployment branches*
   allow only `main`. Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`
   as environment secrets there. Nothing else goes in GitHub.
3. **Run it.** Go to Actions → Deploy → **Run workflow** on `main`. The
   `test` job typechecks and runs the tests; the `deploy` job creates the
   OAuth KV namespace if needed and runs `wrangler deploy`, which also
   creates the `example.aroundand.in` DNS record and certificate. The
   Worker has no `workers.dev` address. To use another hostname, change
   `routes` in `wrangler.jsonc`.
4. **Settings.** After the first deploy the Worker exists in your
   dashboard. Add every required key from the table (and any optional ones)
   as secrets there, or with `npx wrangler secret put`. They are not in
   GitHub and a redeploy leaves them alone.
5. **Make the token.** Run `npm run rotate-token` on your machine (above).

Re-run the workflow only when the code changes.

## Connect a client

Every client signs in through OAuth; there is no header or static token to
configure. On the sign-in page, paste the operator token once and confirm
the pre-filled label. The client then holds its own short-lived OAuth
tokens, and the model never sees them.

Add `https://example.aroundand.in/mcp` as a custom connector or MCP server in
your client, then complete the sign-in page it opens. A desktop or CLI client
usually catches the callback on a loopback address and needs no further
configuration.

The sign-in page only redirects to an allowed callback, decided in two parts.
**Loopback** addresses — `http://localhost:*` and `http://127.0.0.1:*`, any
port and path — are always allowed, which is how desktop and CLI clients
catch the code. **https** callbacks must match `OAUTH_REDIRECT_URIS`, which is
empty by default. An entry is either a full URL, matched exactly, or a bare
hostname, which matches any path on exactly that host (not its subdomains).
Prefer the exact callback URL: a bare hostname also allows user-content paths
on that host, and a code delivered there could be read by a page you did not
intend. Any other redirect is refused with a `400` and is never followed.

A client that can only send a fixed header token, with no interactive
sign-in step, cannot connect.

## Development

```sh
npm install
cp .dev.vars.example .dev.vars   # local values for `wrangler dev`
npm test                          # workerd tests (KV, Durable Object) + repo checks
npm run typecheck
npm run dev
```

Rate-limit state is stored in the Durable Object, so it persists across
deploys and restarts. OAuth grants live in the `OAUTH_KV` namespace.

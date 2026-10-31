# mcp-mail

A Cloudflare Worker that gives the model a **write-only, rate-limited,
recipient-constrained** email capability as an MCP server, sending through
your the mail provider mailbox.

the model can send mail and check that the service is up. It cannot read mail,
change settings, or find out which recipients are allowed.

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
4. **Send** through SMTP: port 465 with implicit TLS, or 587 with
   STARTTLS; 30 s timeout. An SMTP failure returns an internal error whose
   text has every configured value replaced by `[redacted]`.

`ping` returns `status`, `server_time`, the Cloudflare `colo` and
`handler_ms`. Pass `client_time` (ISO 8601) to get `received_after_ms`.
Pass `check_mail: true` to connect and log in to the mail provider without sending,
which reports `mail.ok` and `mail.ms` and costs one rate-limit token.

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
Set them in the dashboard (Workers & Pages → `mcp-mail` → Settings →
Variables and Secrets, type *Secret*) or with `npx wrangler secret put NAME`.
Secrets survive every deploy. Use the *Secret* type, not plain-text
variables, because `wrangler deploy` replaces plain-text variables with the
(empty) list in `wrangler.jsonc`.

| Key | Required | Meaning |
|---|---|---|
| `MCP_AUTH_TOKEN_SHA256` | yes | SHA-256 (64 lowercase hex) of the access token. Set only by `npm run rotate-token` (see [The access token](#the-access-token)). |
| `PUBLIC_URL` | yes | The Worker's https origin, `https://example.aroundand.in`. |
| `SMTP_HOST` | yes | SMTP host for your region/plan: `smtp.example.com`, `smtp.example.eu`, `smtp.example.in`, `smtp.example.com`, … |
| `SMTP_PORT` | no (465) | `465` (implicit TLS) or `587` (STARTTLS). Cloudflare blocks port 25. |
| `SMTP_USERNAME` | yes | Your the mail provider address. |
| `SMTP_PASSWORD` | yes | A the mail provider **app-specific password** (the mail provider Accounts → Security → App passwords), not your login password. |
| `SMTP_FROM` | no | Sender, e.g. `the model <you@yourdomain>`. Defaults to `SMTP_USERNAME`. the mail provider requires it to be your address or an alias. |
| `EMAIL_PER_MIN` | yes | Bucket size and refill rate per minute (> 0). |
| `MAIL_ALLOW_TO` | yes | Comma-separated bare addresses the model may email. |
| `MAIL_DEFAULT_TO` | no | Where everything else goes. Must be on the allowlist; defaults to its first entry. |
| `MAX_BODY_BYTES` | no | Body size cap in bytes. Unset = no cap. |
| `OAUTH_REDIRECT_URIS` | no | Redirect URIs the sign-in page will send codes to. Defaults to the vendor.example and vendor.example connector callbacks. |
| `EMAIL_BATCHING` | no | Reserved. Read but ignored. |

If a value is missing or invalid, every request gets an empty `500`, and
`npx wrangler tail` shows which key is wrong (never its value). After
changing settings, have the model call `ping` with `check_mail: true` to check
the the mail provider login.

## The access token

The Worker never stores the access token, only its SHA-256 hash. The token
itself exists in exactly one place: wherever you paste it.

```sh
npx wrangler login      # once, in a browser, as your Cloudflare account
npm run rotate-token
```

`rotate-token` runs on your machine. It generates 32 random bytes, uploads
only their hash with `wrangler secret put MCP_AUTH_TOKEN_SHA256`, and then
prints the token once. If the upload fails, it prints nothing. Run it again
whenever you want a new token: the old one stops working immediately, and
every connected client has to sign in again.

Sign-in attempts and OAuth client registrations are each limited to 10 in
any 60 seconds; extra requests get `429`.

Several the model accounts can connect: each signs in once with the same
token. They all share the one email limit and allowlist.

## Deploy (one button)

The workflow only ships code. The only secrets GitHub holds are the
Cloudflare deploy credentials, and only the two steps that talk to
Cloudflare can read them. Tests run in a separate job with no secrets.

1. **Cloudflare API token.** Create one at dash.cloudflare.com → My Profile →
   API Tokens → Custom token, with:
   - Account → *Workers Scripts: Edit*, *Workers KV Storage: Edit*,
     *Account Settings: Read*, limited to your account;
   - Zone → *Workers Routes: Edit* and *Zone: Read*, limited to the
     `aroundand.in` zone (for the custom domain).

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

## Connect the model

- **vendor.example / the model apps:** Settings → Connectors → Add custom connector,
  URL `https://example.aroundand.in/mcp`. A sign-in page opens; paste the
  token from `rotate-token` once. vendor.example then holds its own short-lived
  tokens, and the model never sees either.
- **the model Code:**
  `add the MCP server --transport http mail https://example.aroundand.in/mcp --header "Authorization: Bearer <token>"`
- **the model API (MCP connector):** pass the URL and `authorization_token`.

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

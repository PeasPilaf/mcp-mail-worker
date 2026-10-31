// Generate a new operator token, upload only its sha256 to the Worker, then
// delete the OAuth KV records that the new hash just invalidated.
// WRANGLER_CMD overrides the wrangler command (default "npx wrangler").
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TITLE = "mcp-mail-oauth";
const token = randomBytes(32).toString("hex");
const hash = createHash("sha256").update(token).digest("hex");
const [cmd, ...pre] = (process.env.WRANGLER_CMD || "npx wrangler").split(" ").filter(Boolean);

// Uploading the hash IS the rotation, and the only fatal step: until it
// succeeds the token is not live, so there is nothing to print or sweep and
// showing it would be useless and misleading.
const put = spawnSync(cmd, [...pre, "secret", "put", "MCP_AUTH_TOKEN_SHA256"], {
  input: hash,
  stdio: ["pipe", "inherit", "inherit"],
});
if (put.status !== 0) {
  console.error("wrangler failed; the token was not changed.");
  process.exit(1);
}

// Same shape as scripts/clients.mjs so both scripts talk to KV the same way.
// Throws on failure because the sweep is best-effort: the caller decides what
// a failed call means (a warning, never a fatal error).
function wrangler(...args) {
  const r = spawnSync(cmd, [...pre, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  if (r.status !== 0) throw new Error(`wrangler ${args.slice(0, 2).join(" ")} failed`);
  return r.stdout;
}

const json = (out) => JSON.parse(out.slice(out.indexOf("[")));

// Every grant fingerprints the token hash that just changed, so the old
// grants are dead already, but the provider's /token endpoint does not check
// that fingerprint: without this sweep a dead grant keeps minting 60-minute
// access tokens that then 401 on every /mcp call (clients cannot tell that
// apart from a transient failure). Deleting the rows makes refresh fail as a
// proper invalid-grant error, which clients treat as "sign in again".
//
// Best-effort on purpose: the new secret is already live when this runs, so a
// failed lookup or delete must not hide the token. Report it, then print.
try {
  const id = json(wrangler("kv", "namespace", "list")).find((ns) => ns.title === TITLE)?.id;
  if (!id) throw new Error(`KV namespace ${TITLE} not found`);
  const names = ["grant:", "token:"].flatMap((prefix) =>
    json(wrangler("kv", "key", "list", "--namespace-id", id, "--prefix", prefix, "--remote")).map((k) => k.name),
  );
  // Only client registrations live outside these two prefixes; they are not
  // connections and must survive, so the union is exactly the key names we
  // listed rather than a blind prefix sweep.
  if (names.length) {
    const dir = mkdtempSync(join(tmpdir(), "rotate-"));
    try {
      const file = join(dir, "keys.json");
      writeFileSync(file, JSON.stringify(names));
      wrangler("kv", "bulk", "delete", file, "--namespace-id", id, "--remote", "--force");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
} catch (error) {
  console.error(
    `warning: could not clear old sessions (${error.message}); clean up with \`npm run clients -- revoke <label>\` or re-run this script.`,
  );
}

// Print only after the sweep attempt: whatever happened to the sweep, the
// token is live, so the operator needs it exactly once.
console.log(`New token (shown only this time):\n\n${token}\n`);
console.log("Paste it on a client's sign-in page when it asks you to authorize the connection.");
console.log("Every previously connected client must sign in again.");

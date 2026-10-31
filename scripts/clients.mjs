// List and revoke OAuth connections by label, using your own wrangler login.
//   npm run clients                 one line per label with its connection count
//   npm run clients -- revoke LABEL delete that label's grants and tokens
// WRANGLER_CMD overrides the wrangler command (default "npx wrangler").
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TITLE = "mcp-mail-oauth";
const [cmd, ...pre] = (process.env.WRANGLER_CMD || "npx wrangler").split(" ").filter(Boolean);

function wrangler(...args) {
  const r = spawnSync(cmd, [...pre, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  if (r.status !== 0) {
    console.error(`wrangler ${args.slice(0, 2).join(" ")} failed.`);
    process.exit(1);
  }
  return r.stdout;
}

const json = (out) => JSON.parse(out.slice(out.indexOf("[")));

const id = json(wrangler("kv", "namespace", "list")).find((ns) => ns.title === TITLE)?.id;
if (!id) {
  console.error(`KV namespace ${TITLE} not found.`);
  process.exit(1);
}

const keys = (prefix) =>
  json(wrangler("kv", "key", "list", "--namespace-id", id, "--prefix", prefix, "--remote")).map((k) => k.name);

const [action, label] = process.argv.slice(2);

if (action === undefined) {
  const counts = new Map();
  for (const k of keys("grant:")) {
    const l = k.split(":")[1];
    counts.set(l, (counts.get(l) ?? 0) + 1);
  }
  if (!counts.size) console.log("No connections.");
  for (const l of [...counts.keys()].sort()) console.log(`${l}  ${counts.get(l)} connection(s)`);
} else if (action === "revoke" && label) {
  const grants = keys(`grant:${label}:`);
  if (!grants.length) {
    console.error(`No connections labelled "${label}".`);
    process.exit(1);
  }
  const dir = mkdtempSync(join(tmpdir(), "clients-"));
  try {
    const file = join(dir, "keys.json");
    writeFileSync(file, JSON.stringify([...grants, ...keys(`token:${label}:`)]));
    wrangler("kv", "bulk", "delete", file, "--namespace-id", id, "--remote", "--force");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(`Revoked ${grants.length} connection(s) for "${label}". They must sign in again.`);
} else {
  console.error("usage: npm run clients [-- revoke <label>]");
  process.exit(1);
}

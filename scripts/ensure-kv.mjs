// Find (or create) the KV namespace that stores OAuth grants, and write its
// id into wrangler.jsonc for this deploy. Idempotent; run by deploy.yml.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const TITLE = "mcp-mail-oauth";
const PLACEHOLDER = "00000000000000000000000000000000";
const wrangler = (...args) => execFileSync("npx", ["wrangler", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });

function findId() {
  const out = wrangler("kv", "namespace", "list");
  const list = JSON.parse(out.slice(out.indexOf("[")));
  return list.find((ns) => ns.title === TITLE)?.id;
}

let id = findId();
if (!id) {
  wrangler("kv", "namespace", "create", TITLE);
  id = findId();
}
if (!/^[0-9a-f]{32}$/.test(id ?? "")) throw new Error(`could not resolve KV namespace ${TITLE}`);

const path = new URL("../wrangler.jsonc", import.meta.url);
const config = readFileSync(path, "utf8");
if (!config.includes(PLACEHOLDER)) throw new Error("wrangler.jsonc has no KV id placeholder");
writeFileSync(path, config.replace(PLACEHOLDER, id));
console.log(`OAUTH_KV -> ${TITLE}`);

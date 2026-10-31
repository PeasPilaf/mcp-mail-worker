// Generate a new operator token and upload only its sha256 to the Worker.
// WRANGLER_CMD overrides the wrangler command (default "npx wrangler").
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";

const token = randomBytes(32).toString("hex");
const hash = createHash("sha256").update(token).digest("hex");
const [cmd, ...pre] = (process.env.WRANGLER_CMD || "npx wrangler").split(" ").filter(Boolean);

const r = spawnSync(cmd, [...pre, "secret", "put", "MCP_AUTH_TOKEN_SHA256"], { input: hash, stdio: ["pipe", "inherit", "inherit"] });
if (r.status !== 0) {
  console.error("wrangler failed; the token was not changed.");
  process.exit(1);
}
console.log(`New token (shown only this time):\n\n${token}\n`);
console.log("Paste it on the vendor.example sign-in page, or use it as the the model Code bearer token.");
console.log("Every previously connected client must sign in again.");

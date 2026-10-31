// `npm run rotate-token` (scripts/rotate-token.mjs) is how the operator
// token comes into existence. It runs on the operator's machine with their
// own Cloudflare login (`wrangler login`), never in CI.
//
// * Generates a fresh token: 32 bytes from a CSPRNG, as 64 lowercase hex
//   chars. A new one every run.
// * Computes sha256(token) as 64 lowercase hex chars and uploads ONLY that,
//   by running `wrangler secret put MCP_AUTH_TOKEN_SHA256` with the hash
//   written to wrangler's stdin (no trailing newline needed; the Worker
//   trims). Exactly those three arguments: nothing secret on the command
//   line, and the plaintext token never goes to wrangler at all.
// * The wrangler command defaults to `npx wrangler`; the WRANGLER_CMD
//   environment variable overrides it (split on spaces, first word is the
//   program), which is how this test substitutes a fake.
// * Only after wrangler exits 0 does it print the token, once, to stdout,
//   with a reminder that it is shown only this time and that every
//   previously connected client must sign in again.
// * If wrangler fails: exit non-zero, and the token is never printed (it
//   was never stored, so showing it would be useless and misleading).

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..");
const fake = join(__dirname, "fixtures", "fake-wrangler.mjs");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const HEX64 = /\b[0-9a-f]{64}\b/g;

function run(exit = 0) {
  const log = join(mkdtempSync(join(tmpdir(), "rotate-")), "wrangler.json");
  const r = spawnSync(process.execPath, ["scripts/rotate-token.mjs"], {
    cwd: root,
    env: { PATH: process.env.PATH ?? "", WRANGLER_CMD: `${process.execPath} ${fake}`, FAKE_WRANGLER_LOG: log, FAKE_WRANGLER_EXIT: String(exit) },
    encoding: "utf8",
    timeout: 30_000,
  });
  const call = JSON.parse(readFileSync(log, "utf8")) as { argv: string[]; stdin: string };
  return { code: r.status, stdout: r.stdout, out: `${r.stdout}${r.stderr}`, call };
}

describe("rotate-token", () => {
  it("is an npm script", () => {
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts["rotate-token"]).toMatch(/scripts\/rotate-token\.mjs/);
  });

  it("uploads only the hash and prints the token once", () => {
    const r = run();
    expect(r.code, r.out).toBe(0);
    expect(r.call.argv).toEqual(["secret", "put", "MCP_AUTH_TOKEN_SHA256"]);
    const hash = r.call.stdin.trim();
    expect(hash).toMatch(/^[0-9a-f]{64}$/);

    const shown = (r.stdout.match(HEX64) ?? []).filter((h) => h !== hash);
    expect(shown, "exactly one token printed").toHaveLength(1);
    const token = shown[0];
    expect(sha256(token)).toBe(hash);
    expect(r.stdout.split(token)).toHaveLength(2);
    expect(r.call.stdin).not.toContain(token);
    expect(r.call.argv.join(" ")).not.toContain(token);
    expect(r.stdout.toLowerCase()).toContain("only");
    expect(r.stdout.toLowerCase()).toContain("sign in again");
  });

  it("makes a new token every time", () => {
    const a = run().call.stdin.trim();
    const b = run().call.stdin.trim();
    expect(a).not.toBe(b);
  });

  it("does not show a token that was not stored", () => {
    const r = run(1);
    expect(r.code).not.toBe(0);
    const hash = r.call.stdin.trim();
    expect((r.out.match(HEX64) ?? []).filter((h) => h !== hash)).toEqual([]);
  });
});

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
// * Putting the new secret live invalidates every existing OAuth connection
//   (each grant properties fingerprint the old hash), so the same run then
//   sweeps those dead KV records: it finds the namespace titled
//   "mcp-mail-oauth" with the same `wrangler kv namespace list` lookup
//   scripts/clients.mjs uses, lists `grant:` and `token:` keys with
//   `--remote`, and deletes all of them in ONE `wrangler kv bulk delete`
//   call (file argument = JSON array of key names). Client registrations
//   (`client:...`) are not connections and are never touched.
// * An empty sweep makes NO bulk delete call: there is nothing to delete.
// * The sweep is best-effort. The new secret is already live when it runs, so
//   a failed sweep (or a namespace that cannot be found) must not hide the
//   token: the script warns on stderr (clean up with
//   `npm run clients -- revoke <label>` / re-run), still prints the new token
//   once, and exits 0. The token is printed only after the sweep attempt.
// * The wrangler command defaults to `npx wrangler`; the WRANGLER_CMD
//   environment variable overrides it (split on spaces, first word is the
//   program), which is how these tests substitute a fake. The fake records
//   every call, and a NODE_OPTIONS=--require hook records every stdout write
//   at the moment the script makes it, so ORDER is observable (secret put
//   before the sweep; the token after it), not just presence.
// * If the secret upload itself fails: exit 1, do not touch KV at all, and
//   never print the token (it was never stored, so showing it would be
//   useless and misleading).
// * Only after a successful put does it sweep, then print the token, once, to
//   stdout, with a reminder that it is shown only this time and that every
//   previously connected client must sign in again.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..");
const fake = join(__dirname, "fixtures", "fake-wrangler.mjs");
const stdoutHook = join(__dirname, "fixtures", "stdout-trace.cjs");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const HEX64 = /\b[0-9a-f]{64}\b/g;
const SECRET_PUT = ["secret", "put", "MCP_AUTH_TOKEN_SHA256"];
const NS = "0123456789abcdef0123456789abcdef";
const NAMESPACES = [
  { id: NS, title: "mcp-mail-oauth" },
  { id: "f".repeat(32), title: "other" },
];
const KEYS = [
  "client:abc",
  "grant:work:g1",
  "token:work:g1:t1",
  "token:work:g1:t2",
  "grant:work:g2",
  "token:work:g2:t3",
  "grant:work-2:g3",
  "token:work-2:g3:t4",
  "grant:personal:g4",
  "token:personal:g4:t5",
];
const CONNECTIONS = KEYS.filter((k) => k.startsWith("grant:") || k.startsWith("token:"));
const REGISTRATIONS = KEYS.filter((k) => !CONNECTIONS.includes(k));

interface Call {
  argv: string[];
  stdin: string;
  file?: string;
}

interface RunOptions {
  keys?: string[];
  namespaces?: { id: string; title: string }[];
  fail?: string;
}

const command = (call: Call) => call.argv.slice(0, 3).join(" ");
const isSecretPut = (call: Call) => call.argv.join(" ") === SECRET_PUT.join(" ");
const isBulkDelete = (call: Call) => command(call) === "kv bulk delete";
const isKeyList = (call: Call) => command(call) === "kv key list";
const isNamespaceList = (call: Call) => call.argv.join(" ") === "kv namespace list";
const flag = (argv: string[], name: string) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const keyListFor = (calls: Call[], prefix: string) => calls.find((c) => isKeyList(c) && flag(c.argv, "prefix") === prefix);
const markerAt = (trace: string, prefix: string) =>
  trace.split("\n").findIndex((line) => line.startsWith(`[wrangler-call] ${prefix}`));
const lastMarkerAt = (trace: string) =>
  trace.split("\n").reduce((at, line, i) => (line.startsWith("[wrangler-call] ") ? i : at), -1);
const tokenWriteAt = (trace: string, token: string) =>
  trace.split("\n").findIndex((line) => line.startsWith("[stdout] ") && line.includes(token));

function run(options: RunOptions = {}) {
  const dir = mkdtempSync(join(tmpdir(), "rotate-"));
  const state = join(dir, "kv-state.json");
  const log = join(dir, "wrangler-calls.jsonl");
  const trace = join(dir, "trace.log");
  writeFileSync(state, JSON.stringify({ namespaces: options.namespaces ?? NAMESPACES, keys: options.keys ?? KEYS }));
  writeFileSync(log, "");
  writeFileSync(trace, "");
  // The fake appends a marker to the trace for every wrangler call, and a
  // --require hook appends one for every stdout write at the moment the
  // script makes it. Both appends are synchronous, so the trace preserves
  // order even though the OS may flush the script's stdout pipe later.
  const r = spawnSync(process.execPath, ["scripts/rotate-token.mjs"], {
    cwd: root,
    env: {
      PATH: process.env.PATH ?? "",
      WRANGLER_CMD: `${process.execPath} ${fake}`,
      FAKE_WRANGLER_LOG: log,
      FAKE_KV_STATE: state,
      FAKE_WRANGLER_TRACE: trace,
      FAKE_STDOUT_TRACE: trace,
      FAKE_WRANGLER_FAIL: options.fail ?? "",
      NODE_OPTIONS: `--require ${stdoutHook}`,
    },
    encoding: "utf8",
    timeout: 30_000,
  });

  const calls = readFileSync(log, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Call);
  const traceText = readFileSync(trace, "utf8");
  const stdout = r.stdout ?? "";
  const hash = calls.find(isSecretPut)?.stdin.trim() ?? "";
  const tokens = (stdout.match(HEX64) ?? []).filter((h) => h !== hash);
  return {
    code: r.status,
    stdout,
    stderr: r.stderr ?? "",
    trace: traceText,
    calls,
    hash,
    tokens,
    keysNow: () => (JSON.parse(readFileSync(state, "utf8")).keys as string[]),
  };
}

describe("rotate-token", () => {
  it("is an npm script", () => {
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts["rotate-token"]).toMatch(/scripts\/rotate-token\.mjs/);
  });

  it("uploads only the hash and prints the token once", () => {
    const r = run();
    expect(r.code, `${r.stdout}${r.stderr}`).toBe(0);
    const puts = r.calls.filter(isSecretPut);
    expect(puts).toHaveLength(1);
    expect(puts[0].argv).toEqual(SECRET_PUT);
    const hash = r.hash;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);

    expect(r.tokens, "exactly one token printed").toHaveLength(1);
    const token = r.tokens[0];
    expect(sha256(token)).toBe(hash);
    expect(r.stdout.split(token)).toHaveLength(2);
    expect(puts[0].stdin).not.toContain(token);
    expect(puts[0].argv.join(" ")).not.toContain(token);
    expect(r.stdout.toLowerCase()).toContain("only");
    expect(r.stdout.toLowerCase()).toContain("sign in again");
  });

  it("makes a new token every time", () => {
    const a = run().hash;
    const b = run().hash;
    expect(a).not.toBe(b);
  });

  it("does not show a token that was not stored", () => {
    const r = run({ fail: "secret put" });
    expect(r.code, "wrangler secret put failed, so the run failed").toBe(1);
    expect(r.tokens).toEqual([]);
  });

  it("does not touch KV when the secret upload failed", () => {
    // Guard for an unchanged invariant: the sweep only ever runs after a
    // successful put. (Passes on the pre-sweep script too, vacuously.)
    const r = run({ fail: "secret put" });
    expect(r.calls.filter((call) => call.argv[0] === "kv"), "no KV call after a failed upload").toEqual([]);
  });
});

describe("rotate-token sweep", () => {
  it("uploads the new hash before deleting the invalidated records", () => {
    const r = run();
    const putAt = r.calls.findIndex(isSecretPut);
    const deleteAt = r.calls.findIndex(isBulkDelete);
    expect(putAt, "secret uploaded").toBeGreaterThanOrEqual(0);
    expect(deleteAt, "bulk delete recorded").toBeGreaterThanOrEqual(0);
    expect(putAt, "the secret is live before anything is deleted").toBeLessThan(deleteAt);
  });

  it("prints the token only after the sweep has run", () => {
    const r = run();
    const deleteAt = markerAt(r.trace, "kv bulk delete");
    expect(deleteAt, "sweep call recorded in the trace").toBeGreaterThanOrEqual(0);
    expect(r.tokens, "token printed").toHaveLength(1);
    const tokenAt = tokenWriteAt(r.trace, r.tokens[0]);
    expect(tokenAt, "token write recorded in the trace").toBeGreaterThanOrEqual(0);
    expect(tokenAt, "token printed after the sweep").toBeGreaterThan(deleteAt);
  });

  it("finds the OAuth namespace by title and lists both prefixes remotely", () => {
    const r = run();
    const lookups = r.calls.filter(isNamespaceList);
    expect(lookups, "namespace looked up by title").toHaveLength(1);
    expect(lookups[0].argv).toEqual(["kv", "namespace", "list"]);
    expect(r.calls.filter(isKeyList), "one listing per prefix").toHaveLength(2);
    for (const prefix of ["grant:", "token:"]) {
      const list = keyListFor(r.calls, prefix);
      expect(list, `lists ${prefix} keys`).toBeTruthy();
      expect(flag(list!.argv, "namespace-id"), prefix).toBe(NS);
      expect(list!.argv, prefix).toContain("--remote");
    }
    for (const call of r.calls.filter((c) => c.argv[0] === "kv" && !isNamespaceList(c))) {
      expect(flag(call.argv, "namespace-id"), call.argv.join(" ")).toBe(NS);
    }
  });

  it("deletes every grant and token row in one bulk delete, keeping client registrations", () => {
    const r = run();
    const deletes = r.calls.filter(isBulkDelete);
    expect(deletes, "exactly one bulk delete").toHaveLength(1);
    const args = deletes[0].argv;
    expect(args.slice(0, 3)).toEqual(["kv", "bulk", "delete"]);
    expect(flag(args, "namespace-id")).toBe(NS);
    expect(args).toContain("--remote");
    expect(args).toContain("--force");
    const deleted = JSON.parse(deletes[0].file ?? "null") as string[];
    expect([...deleted].sort(), "every connection key, and nothing else").toEqual([...CONNECTIONS].sort());
    expect(r.keysNow(), "client registrations survive").toEqual(REGISTRATIONS);
  });

  it("does not bulk delete when there is nothing to sweep", () => {
    const r = run({ keys: ["client:abc"] });
    expect(r.calls.filter(isKeyList), "it looked for connections").toHaveLength(2);
    expect(r.calls.filter(isBulkDelete), "an empty sweep is not a bulk delete").toHaveLength(0);
    expect(r.code).toBe(0);
    expect(r.tokens).toHaveLength(1);
    expect(sha256(r.tokens[0])).toBe(r.hash);
  });

  it("still prints the token when the sweep fails", () => {
    for (const fail of ["kv namespace list", "kv key list", "kv bulk delete"]) {
      const r = run({ fail });
      expect(r.code, `${fail}: rotation still succeeded`).toBe(0);
      expect(r.tokens, `${fail}: token still printed`).toHaveLength(1);
      expect(sha256(r.tokens[0]), fail).toBe(r.hash);
      expect(r.calls.filter((call) => call.argv[0] === "kv").length, `${fail}: sweep attempted`).toBeGreaterThan(0);
      expect(r.stderr, fail).toMatch(/warning/i);
      expect(r.stderr, fail).toMatch(/npm run clients/);
      expect(r.stderr, fail).toMatch(/revoke/);
      const last = lastMarkerAt(r.trace);
      expect(last, `${fail}: failed call recorded`).toBeGreaterThanOrEqual(0);
      const tokenAt = tokenWriteAt(r.trace, r.tokens[0]);
      expect(tokenAt, `${fail}: token write recorded`).toBeGreaterThanOrEqual(0);
      expect(tokenAt, `${fail}: token printed after the failed sweep`).toBeGreaterThan(last);
    }
  });

  it("still prints the token when the OAuth namespace is missing", () => {
    const r = run({ namespaces: [{ id: "f".repeat(32), title: "something-else" }] });
    expect(r.code, "rotation still succeeded").toBe(0);
    expect(r.tokens, "token still printed").toHaveLength(1);
    expect(sha256(r.tokens[0])).toBe(r.hash);
    expect(r.calls.filter(isNamespaceList), "namespace lookup attempted").toHaveLength(1);
    expect(r.calls.filter(isBulkDelete), "nothing deleted without a namespace").toHaveLength(0);
    expect(r.stderr).toMatch(/warning/i);
    expect(r.stderr).toMatch(/npm run clients/);
    expect(r.stderr).toMatch(/revoke/);
  });
});

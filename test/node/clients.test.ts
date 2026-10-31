// `npm run clients` (scripts/clients.mjs): list and revoke connections by
// label, from the operator's machine with their own wrangler login. No web
// UI, no admin endpoint on the Worker.
//
// Each OAuth sign-in stores its grant with userId = the label the operator
// typed, so the OAuth KV namespace (title "mcp-mail-oauth", found by title
// via `wrangler kv namespace list`; wrangler.jsonc only holds a
// placeholder id) has keys `grant:<label>:<grantId>` and
// `token:<label>:<grantId>:<tokenId>`. Other keys (e.g. `client:...`) are
// not connections and are never touched.
//
// * `npm run clients` -> one line per label: `<label>  <n> connection(s)`
//   (n = number of grant keys), sorted by label. "No connections." if none.
// * `npm run clients -- revoke <label>` -> deletes every `grant:<label>:`
//   and `token:<label>:` key with ONE `kv bulk delete` call, then prints how
//   many connections were revoked. Those clients must sign in again.
//   - Unknown label (no grant keys) -> exit 1, nothing deleted.
//   - There is no "bearer" special case: the static bearer token path is
//     gone, so "bearer" is an ordinary label like any other (usually with no
//     connections, which is the unknown-label path).
//   - Labels are matched exactly: revoking "work" never touches "work-2".
// * Every `kv key` / `kv bulk` call passes `--remote` and
//   `--namespace-id <id>`. Missing namespace -> exit 1.
// * The wrangler command defaults to `npx wrangler`; WRANGLER_CMD overrides
//   it (split on spaces), as for rotate-token.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..");
const fake = join(__dirname, "fixtures", "fake-wrangler-kv.mjs");
const NS = "0123456789abcdef0123456789abcdef";
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

function setup(keys = KEYS, namespaces = [{ id: NS, title: "mcp-mail-oauth" }, { id: "f".repeat(32), title: "other" }]) {
  const dir = mkdtempSync(join(tmpdir(), "clients-"));
  const state = join(dir, "state.json");
  const log = join(dir, "log.jsonl");
  writeFileSync(state, JSON.stringify({ namespaces, keys }));
  writeFileSync(log, "");
  const run = (...args: string[]) => {
    const r = spawnSync(process.execPath, ["scripts/clients.mjs", ...args], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "", WRANGLER_CMD: `${process.execPath} ${fake}`, FAKE_KV_STATE: state, FAKE_WRANGLER_LOG: log },
      encoding: "utf8",
      timeout: 30_000,
    });
    return { code: r.status, stdout: r.stdout, out: `${r.stdout}${r.stderr}` };
  };
  const keysNow = () => JSON.parse(readFileSync(state, "utf8")).keys as string[];
  const calls = () => readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]);
  return { run, keysNow, calls };
}

describe("clients", () => {
  it("is an npm script", () => {
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts.clients).toMatch(/scripts\/clients\.mjs/);
  });

  it("lists labels with connection counts", () => {
    const { run } = setup();
    const r = run();
    expect(r.code, r.out).toBe(0);
    const lines = r.stdout.trim().split("\n").map((l) => l.trim().split(/\s+/).slice(0, 2));
    expect(lines).toEqual([["personal", "1"], ["work", "2"], ["work-2", "1"]]);
  });

  it("says so when there are none", () => {
    const { run } = setup(["client:abc"]);
    const r = run();
    expect(r.code, r.out).toBe(0);
    expect(r.stdout).toContain("No connections.");
  });

  it("revokes exactly one label in one bulk delete", () => {
    const { run, keysNow, calls } = setup();
    const r = run("revoke", "work");
    expect(r.code, r.out).toBe(0);
    expect(r.stdout).toMatch(/\b2\b/);
    expect(keysNow()).toEqual(["client:abc", "grant:work-2:g3", "token:work-2:g3:t4", "grant:personal:g4", "token:personal:g4:t5"]);
    const kvCalls = calls().filter((c) => c[0] === "kv" && c[1] !== "namespace");
    expect(kvCalls.filter((c) => c[1] === "bulk")).toHaveLength(1);
    for (const c of kvCalls) {
      expect(c, c.join(" ")).toContain("--remote");
      expect(c[c.indexOf("--namespace-id") + 1]).toBe(NS);
    }
  });

  it("refuses labels with no connections, including the retired bearer label", () => {
    for (const label of ["nobody", "bearer", "wor"]) {
      const { run, keysNow, calls } = setup();
      const r = run("revoke", label);
      expect(r.code, label).toBe(1);
      expect(keysNow(), label).toEqual(KEYS);
      expect(calls().some((c) => c[1] === "bulk"), label).toBe(false);
      expect(r.out, label).toContain(`No connections labelled "${label}".`);
    }
  });

  it("revokes a bearer-labelled connection like any other label", () => {
    const keys = [...KEYS, "grant:bearer:g9", "token:bearer:g9:t9"];
    const { run, keysNow } = setup(keys);
    const r = run("revoke", "bearer");
    expect(r.code, r.out).toBe(0);
    expect(keysNow()).toEqual(KEYS);
  });

  it("fails without the OAuth namespace", () => {
    const { run } = setup(KEYS, [{ id: NS, title: "something-else" }]);
    expect(run().code).toBe(1);
  });
});

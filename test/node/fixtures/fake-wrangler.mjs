// Stand-in for `wrangler` in the rotate-token tests. A rotation no longer
// makes a single call: it uploads the new hash and then sweeps the OAuth KV
// records it just invalidated, so this fake keeps KV state and records every
// invocation.
//
// State: $FAKE_KV_STATE is a JSON file
//   { namespaces: [{ id, title }], keys: ["name", ...] }.
// Log:   every invocation appends one JSON line { argv, stdin, file } to
//   $FAKE_WRANGLER_LOG. `file` is the JSON array read from the file argument
//   of `kv bulk delete` (captured before the script deletes its temp file).
// Trace: when $FAKE_WRANGLER_TRACE is set, each invocation also appends
//   "[wrangler-call] <argv joined>" to it. The tests' stdout-trace.cjs hook
//   appends a marker for every script stdout write to the same file, so
//   marker order proves the script prints the token only after the sweep,
//   not merely that both happened.
// Failure: $FAKE_WRANGLER_FAIL is a substring of the joined argv; a matching
//   call records itself (marker + log line), writes a stderr line, and exits
//   1, mimicking wrangler failing at that step.
//
// Supported (flags as `--flag value`, any order):
//   secret put MCP_AUTH_TOKEN_SHA256                    hash on stdin
//   kv namespace list                                   prints namespaces JSON
//   kv key list --namespace-id ID --prefix P --remote   prints [{ name }] JSON
//   kv bulk delete FILE --namespace-id ID --remote --force
//                                         FILE = JSON array of key names
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const argv = process.argv.slice(2);
const arg = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const trace = (line) => {
  const path = process.env.FAKE_WRANGLER_TRACE;
  if (path) appendFileSync(path, `[wrangler-call] ${line}\n`);
};

let stdin = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (stdin += chunk));
process.stdin.on("end", () => {
  const cmd = argv.slice(0, 3).join(" ");
  trace(argv.join(" "));
  const bulkFile = cmd === "kv bulk delete" ? readFileSync(argv[3], "utf8") : undefined;
  appendFileSync(process.env.FAKE_WRANGLER_LOG, `${JSON.stringify({ argv, stdin, file: bulkFile })}\n`);

  const failing = process.env.FAKE_WRANGLER_FAIL;
  if (failing && argv.join(" ").includes(failing)) {
    process.stderr.write(`fake wrangler: ${argv.join(" ")} failed\n`);
    process.exit(1);
  }

  const state = JSON.parse(readFileSync(process.env.FAKE_KV_STATE, "utf8"));
  const knownNamespace = () => {
    const id = arg("namespace-id");
    if (!state.namespaces.some((ns) => ns.id === id)) {
      process.stderr.write(`unknown namespace ${id}\n`);
      process.exit(1);
    }
  };

  if (cmd === "secret put MCP_AUTH_TOKEN_SHA256") {
    // The hash arrived on stdin; nothing to print.
  } else if (cmd === "kv namespace list") {
    process.stdout.write(JSON.stringify(state.namespaces, null, 2));
  } else if (cmd === "kv key list") {
    knownNamespace();
    const prefix = arg("prefix") ?? "";
    const rows = state.keys.filter((key) => key.startsWith(prefix)).map((name) => ({ name }));
    process.stdout.write(JSON.stringify(rows));
  } else if (cmd === "kv bulk delete") {
    knownNamespace();
    const doomed = new Set(JSON.parse(bulkFile));
    state.keys = state.keys.filter((key) => !doomed.has(key));
    writeFileSync(process.env.FAKE_KV_STATE, JSON.stringify(state));
    process.stdout.write("Success!\n");
  } else {
    process.stderr.write(`fake wrangler: unsupported ${argv.join(" ")}\n`);
    process.exit(2);
  }
});

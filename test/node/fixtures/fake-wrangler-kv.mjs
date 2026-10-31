// Stand-in for `wrangler` in the clients test. State lives in the JSON
// file $FAKE_KV_STATE: { namespaces: [{ id, title }], keys: ["name", ...] }.
// Every call's argv is appended to $FAKE_WRANGLER_LOG (one JSON array per
// line). Supported (flags as `--flag value`, in any order):
//   kv namespace list                                   -> prints namespaces JSON
//   kv key list --namespace-id ID --prefix P --remote   -> prints [{ name }] JSON
//   kv bulk delete FILE --namespace-id ID --remote --force
//                                         FILE = JSON array of key names
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const argv = process.argv.slice(2);
appendFileSync(process.env.FAKE_WRANGLER_LOG, `${JSON.stringify(argv)}\n`);
const state = JSON.parse(readFileSync(process.env.FAKE_KV_STATE, "utf8"));
const flag = (n) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const ns = flag("namespace-id");
const knownNs = () => {
  if (!state.namespaces.some((n) => n.id === ns)) {
    process.stderr.write(`unknown namespace ${ns}\n`);
    process.exit(1);
  }
};

const cmd = argv.filter((a) => !a.startsWith("--")).slice(0, 3).join(" ");
if (cmd === "kv namespace list") {
  process.stdout.write(JSON.stringify(state.namespaces, null, 2));
} else if (cmd.startsWith("kv key list")) {
  knownNs();
  const prefix = flag("prefix") ?? "";
  process.stdout.write(JSON.stringify(state.keys.filter((k) => k.startsWith(prefix)).map((name) => ({ name }))));
} else if (cmd.startsWith("kv bulk delete")) {
  knownNs();
  const file = argv[argv.indexOf("delete") + 1];
  const del = new Set(JSON.parse(readFileSync(file, "utf8")));
  state.keys = state.keys.filter((k) => !del.has(k));
  writeFileSync(process.env.FAKE_KV_STATE, JSON.stringify(state));
  process.stdout.write(`Success!\n`);
} else {
  process.stderr.write(`fake wrangler: unsupported ${argv.join(" ")}\n`);
  process.exit(2);
}

// Stand-in for `wrangler` in the rotate-token test. Records its argv and
// everything it reads on stdin to $FAKE_WRANGLER_LOG (JSON), then exits
// with $FAKE_WRANGLER_EXIT (default 0).
import { writeFileSync } from "node:fs";

let stdin = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (stdin += c));
process.stdin.on("end", () => {
  writeFileSync(process.env.FAKE_WRANGLER_LOG, JSON.stringify({ argv: process.argv.slice(2), stdin }));
  const code = Number(process.env.FAKE_WRANGLER_EXIT ?? "0");
  if (code) process.stderr.write("fake wrangler: failed\n");
  process.exit(code);
});

// Loaded into the rotate-token script via NODE_OPTIONS=--require by the
// rotate-token tests. Every process.stdout.write is recorded in
// $FAKE_STDOUT_TRACE at the moment the script produces it, before the bytes
// are handed to the stream. That makes the ORDER of the script's own output
// against the fake wrangler's call markers observable: the OS may flush fd 1
// later (or out of order), so the trace file alone cannot be trusted.
//
// The fake wrangler inherits NODE_OPTIONS and records its own (irrelevant)
// stdout writes here too; markers never contain the token.
const { appendFileSync } = require("node:fs");

const trace = process.env.FAKE_STDOUT_TRACE;
if (trace) {
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk, encoding, callback) {
    appendFileSync(trace, `[stdout] ${JSON.stringify(String(chunk))}\n`);
    return write(chunk, encoding, callback);
  };
}

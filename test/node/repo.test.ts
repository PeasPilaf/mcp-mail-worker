// Repository deliverables outside the Worker code (runs in Node).
//
// * package.json pins the runtime deps the Worker is built on.
// * wrangler.jsonc binds OAUTH_KV and the RateLimiter Durable Object, and
//   carries NO configuration values: everything in the config table is a
//   Worker secret set in Cloudflare.
// * The Worker is served ONLY at its custom domain, example.aroundand.in
//   (a Cloudflare-managed zone): one route with `custom_domain: true`, so
//   `wrangler deploy` creates the DNS record and certificate itself, and
//   `workers_dev: false` so no *.workers.dev address answers.
// * Runtime configuration lives ONLY in Cloudflare (dashboard -> Worker ->
//   Settings -> Variables and Secrets, or `wrangler secret put`). GitHub
//   never holds a Worker secret: no config key appears in any workflow, and
//   there is no script that turns environment variables into Worker secrets.
// * .github/workflows/deploy.yml is the "button" and only ships code:
//   - manual trigger only (workflow_dispatch), read-only GitHub token;
//   - job `test`: install, typecheck, tests. It references NO secrets.
//   - job `deploy`: `needs: test`, runs in the GitHub environment
//     `production` (where the operator keeps the Cloudflare token and
//     restricts deployment to main), and only when the ref is main.
//     Install is `npm ci --ignore-scripts`. The only secrets in the whole
//     file are CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID, and they are
//     set only as step-level env on the steps that call Cloudflare (ensure
//     the KV namespace, `wrangler deploy`). No workflow- or job-level env.
//     No `wrangler secret` anywhere: a deploy never changes configuration.
// * .github/workflows/ci.yml runs typecheck + tests on pull requests.
// * .gitignore keeps .dev.vars out of git.
// * .dev.vars.example (for `wrangler dev`) lists every key, is itself a
//   valid configuration, says values are server-side and never reach the
//   LLM, and marks EMAIL_BATCHING `# Not implemented; read but ignored.`
// * README.md documents every key, the repository secrets to create, and
//   how to run the deploy workflow and connect the model, and says that
//   runtime values are set in Cloudflare, not GitHub.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { parseConfig } from "../../src/config";

const root = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

export const CONFIG_KEYS = [
  "MCP_AUTH_TOKEN_SHA256", "PUBLIC_URL", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
  "EMAIL_PER_MIN", "CLIENT_EMAIL_PER_MIN", "MAIL_ALLOW_TO", "MAIL_DEFAULT_TO", "MAX_BODY_BYTES", "OAUTH_REDIRECT_URIS", "EMAIL_BATCHING",
];

/** Strip // and /* *\/ comments (outside strings) and trailing commas. */
function jsonc(text: string): any {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === "\\") out += text[++i];
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i) + 1;
    } else out += c;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

describe("package.json", () => {
  it("depends on the Worker building blocks", () => {
    const pkg = JSON.parse(read("package.json"));
    for (const d of ["@cloudflare/workers-oauth-provider", "@modelcontextprotocol/sdk", "worker-mailer"]) expect(pkg.dependencies[d], d).toBeTruthy();
    for (const s of ["test", "typecheck", "deploy", "rotate-token", "clients"]) expect(pkg.scripts[s], s).toBeTruthy();
  });

  it("has no path from environment variables to Worker secrets", () => {
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.scripts["check-config"]).toBeUndefined();
    for (const f of ["scripts/secrets-file.mjs", "scripts/check-config.ts"]) expect(existsSync(join(root, f)), f).toBe(false);
  });
});

describe("wrangler.jsonc", () => {
  const w = jsonc(read("wrangler.jsonc"));
  it("binds KV and the rate limiter", () => {
    expect(w.main).toBe("src/index.ts");
    expect(w.kv_namespaces.map((k: any) => k.binding)).toContain("OAUTH_KV");
    expect(w.durable_objects.bindings).toContainEqual({ name: "RATE_LIMITER", class_name: "RateLimiter" });
    expect(JSON.stringify(w.migrations)).toContain("RateLimiter");
    expect(w.compatibility_flags).toContain("nodejs_compat");
  });

  it("serves only the custom domain", () => {
    expect(w.routes).toEqual([{ pattern: "example.aroundand.in", custom_domain: true }]);
    expect(w.workers_dev).toBe(false);
  });

  it("carries no configuration values", () => {
    for (const k of CONFIG_KEYS) expect(w.vars?.[k], `${k} must be a secret, not a var`).toBeUndefined();
  });
});

describe("deploy workflow", () => {
  const text = read(".github/workflows/deploy.yml");
  const wf = parseYaml(text);
  const jobs: Record<string, any> = wf.jobs;
  const SECRET = /\$\{\{\s*secrets\.(\w+)\s*\}\}/g;
  const secretsIn = (v: unknown) => [...JSON.stringify(v ?? null).matchAll(SECRET)].map((m) => m[1]);
  const runs = (s: any, re: RegExp) => typeof s.run === "string" && re.test(s.run);
  const idx = (steps: any[], re: RegExp) => {
    const i = steps.findIndex((s) => runs(s, re));
    expect(i, String(re)).toBeGreaterThanOrEqual(0);
    return i;
  };

  it("is a manual button only", () => {
    expect(Object.keys(wf.on ?? wf[true as any])).toEqual(["workflow_dispatch"]);
  });

  it("uses a read-only GitHub token", () => {
    expect(wf.permissions).toEqual({ contents: "read" });
  });

  it("tests in a job with no secrets", () => {
    const steps: any[] = jobs.test.steps;
    const install = idx(steps, /npm ci/);
    const typecheck = idx(steps, /npm run typecheck/);
    const test = idx(steps, /npm test/);
    expect(install < typecheck && typecheck < test).toBe(true);
    expect(secretsIn(jobs.test)).toEqual([]);
  });

  it("deploys from a separate job in the production environment, main only", () => {
    const d = jobs.deploy;
    expect(Object.keys(jobs).sort()).toEqual(["deploy", "test"]);
    expect([d.needs].flat()).toEqual(["test"]);
    expect(typeof d.environment === "string" ? d.environment : d.environment?.name).toBe("production");
    expect(String(d.if ?? "")).toMatch(/github\.ref\s*==\s*'refs\/heads\/main'/);
    const steps: any[] = d.steps;
    const install = idx(steps, /npm ci/);
    expect(steps[install].run).toMatch(/npm ci --ignore-scripts/);
    expect(install).toBeLessThan(idx(steps, /wrangler deploy/));
  });

  it("holds only the Cloudflare credentials, on the Cloudflare steps only", () => {
    expect(new Set(secretsIn(wf))).toEqual(new Set(["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]));
    expect(secretsIn(wf.env), "workflow-level env").toEqual([]);
    for (const [name, job] of Object.entries(jobs)) {
      expect(secretsIn(job.env), `${name} job-level env`).toEqual([]);
      for (const s of job.steps as any[]) {
        const uses = secretsIn(s);
        if (!uses.length) continue;
        expect(runs(s, /wrangler deploy|ensure-kv/), `secrets on step "${s.name ?? s.run ?? s.uses}"`).toBe(true);
        expect(secretsIn({ ...s, env: undefined }), "secrets only via env").toEqual([]);
      }
    }
  });

  it("never sets Worker configuration", () => {
    expect(text).not.toMatch(/wrangler secret/);
    expect(text).not.toMatch(/check-config|secrets-file/);
    for (const k of CONFIG_KEYS) expect(text, k).not.toContain(k);
  });

  it("never prints secrets", () => {
    expect(text).not.toMatch(/echo\s+.*\$\{\{\s*secrets\./);
    expect(text).not.toMatch(/set -x/);
  });
});

describe("ci workflow", () => {
  it("runs typecheck and tests on pull requests", () => {
    const wf = parseYaml(read(".github/workflows/ci.yml"));
    expect(Object.keys(wf.on ?? wf[true as any])).toContain("pull_request");
    const runs = JSON.stringify(wf.jobs);
    expect(runs).toContain("npm run typecheck");
    expect(runs).toContain("npm test");
  });
});

describe(".dev.vars.example", () => {
  const text = (() => {
    try {
      return read(".dev.vars.example");
    } catch {
      return "";
    }
  })();
  const map: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i > 0) map[t.slice(0, i).trim()] = t.slice(i + 1).split(" #")[0].trim().replace(/^"|"$/g, "");
  }

  it("is gitignored once copied", () => {
    expect(read(".gitignore").split("\n").map((l) => l.trim())).toContain(".dev.vars");
  });

  it("lists every key", () => {
    for (const k of CONFIG_KEYS) expect(text, k).toMatch(new RegExp(`^(# )?${k}=`, "m"));
  });

  it("marks EMAIL_BATCHING as not implemented", () => {
    const lines = text.split("\n");
    const i = lines.findIndex((l) => /^(# )?EMAIL_BATCHING=/.test(l));
    expect(lines[i].includes("# Not implemented; read but ignored.") || lines[i - 1]?.trim() === "# Not implemented; read but ignored.").toBe(true);
  });

  it("says values are server-side and never reach the LLM", () => {
    const lower = text.toLowerCase();
    expect(lower).toContain("server-side");
    expect(lower).toContain("never");
    expect(lower).toContain("llm");
  });

  it("is a valid configuration", () => {
    expect(() => parseConfig(map)).not.toThrow();
  });
});

describe("README", () => {
  it("documents keys, secrets, deploy and connecting", () => {
    const lower = read("README.md").toLowerCase();
    for (const k of [...CONFIG_KEYS, "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]) expect(lower, k).toContain(k.toLowerCase());
    for (const n of ["npm run clients", "x-mcp-client", "rotate-token", "wrangler login", "wrangler secret put", "variables and secrets", "production", "not in github", "run workflow", "smtp", "app-specific password", "custom connector", "add the MCP server", "send_email", "ping", "durable object", "does not"]) {
      expect(lower, n).toContain(n);
    }
  });
});

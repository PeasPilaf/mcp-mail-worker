// Worker bindings declared in wrangler.jsonc.
//
// Runtime globals (KVNamespace, DurableObjectNamespace, Request, ...) come from
// @cloudflare/workers-types, which tsconfig lists under "types". `wrangler
// types` also emits a 16k-line copy of those runtime types; that copy is
// redundant, so this file declares only the project-specific bindings. The
// Cloudflare namespace mirrors what the generator emits, because the vitest
// Workers pool reads its provided Env through it.
interface __BaseEnv_Env {
  OAUTH_KV: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace<import("./index").RateLimiter>;
}
declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("./index");
    durableNamespaces: "RateLimiter";
  }
  interface Env extends __BaseEnv_Env {}
}
interface Env extends __BaseEnv_Env {}

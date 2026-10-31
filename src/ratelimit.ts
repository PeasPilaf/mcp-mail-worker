// One global token bucket, held by a single Durable Object instance.

import { DurableObject } from "cloudflare:workers";

export interface BucketState {
  tokens: number;
  updatedMs: number;
}

/** Pure token-bucket step: capacity = perMinute, refill perMinute per 60 s. */
export function takeToken(
  state: BucketState | undefined,
  perMinute: number,
  nowMs: number,
): { allowed: boolean; state: BucketState } {
  const elapsed = state ? Math.max(0, nowMs - state.updatedMs) : 0;
  const available = state ? Math.min(perMinute, state.tokens + (elapsed * perMinute) / 60_000) : perMinute;
  const allowed = available >= 1;
  return { allowed, state: { tokens: allowed ? available - 1 : available, updatedMs: nowMs } };
}

export class RateLimiter extends DurableObject {
  /** Atomically take one token; false if the bucket is empty. */
  async take(perMinute: number): Promise<boolean> {
    const current = await this.ctx.storage.get<BucketState>("bucket");
    const { allowed, state } = takeToken(current, perMinute, Date.now());
    await this.ctx.storage.put("bucket", state);
    return allowed;
  }
}

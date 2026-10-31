// One global flat sliding-window limiter, held by a single Durable Object instance.

import { DurableObject } from "cloudflare:workers";

/** Pure sliding-window step: at most perMinute allowed in any 60 s. `sent` = live stamps, ascending. */
export function takeSlot(
  sent: number[] | undefined,
  perMinute: number,
  nowMs: number,
): { allowed: boolean; sent: number[] } {
  const live = (sent ?? []).filter((t) => t > nowMs - 60_000);
  const allowed = live.length < perMinute;
  if (allowed) live.push(nowMs);
  return { allowed, sent: live };
}

export class RateLimiter extends DurableObject {
  /** Atomically take one slot; false if the window is full. */
  async take(perMinute: number): Promise<boolean> {
    const current = await this.ctx.storage.get<number[]>("window");
    const { allowed, sent } = takeSlot(current, perMinute, Date.now());
    await this.ctx.storage.put("window", sent);
    return allowed;
  }
}

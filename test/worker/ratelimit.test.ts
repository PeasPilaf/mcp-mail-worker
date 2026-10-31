// Rate-limit contract.
//
// * ONE global SLIDING WINDOW, flat: in ANY 60-second span at most
//   EMAIL_PER_MIN attempts are allowed. No burst on top, no refill credit.
//   (A token bucket was used before and allowed ~2x in a 60 s span; the
//   operator wants a hard cap.)
// * Implementation: a single Durable Object instance (RATE_LIMITER, name
//   "global" in production) whose `take(perMinute)` atomically decides.
//   It keeps the timestamps (ms) of ALLOWED takes; a take at `now` is
//   allowed iff fewer than perMinute of them are > now - 60_000 (a stamp
//   exactly 60 s old has expired). Refused takes are not recorded, so
//   hammering a full window can't extend it. The pure step is
//   `takeSlot(sent, perMinute, nowMs) -> { allowed, sent }`, where `sent`
//   is the pruned, ascending list of live stamps (undefined = empty).
// * State is in Durable Object storage, so it survives isolate restarts and
//   is shared by every Cloudflare location. It is stored under a NEW key,
//   not the old token bucket's "bucket" key, so leftover bucket state from
//   an earlier deploy is ignored.
// * The check is the FIRST step of send_email, before the body cap and
//   recipient resolution: every attempt counts (allowlisted,
//   redirected, unparseable, oversize, and attempts that later fail at
//   SMTP). `ping` with `check_mail: true` also counts (it opens an
//   SMTP connection); plain `ping` does not.
// * Exhausted -> JSON-RPC error -32600 "email rate limit exceeded for this
//   minute", nothing sent.

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { takeSlot } from "../../src/ratelimit";
import { ALICE, INTERNAL_ERROR, INVALID_REQUEST, OFF_LIST, SMTP_FAILURE, expectRpcError, expectSent, varsWith, worker } from "./helpers";

const LIMIT = "email rate limit exceeded for this minute";

describe("takeSlot (pure)", () => {
  const run = (perMinute: number, times: number[]) => {
    let s: number[] | undefined;
    return times.map((now) => {
      const r = takeSlot(s, perMinute, now);
      s = r.sent;
      return r.allowed;
    });
  };

  it("allows perMinute, then refuses", () => {
    expect(run(3, [1_000, 1_000, 1_000, 1_000])).toEqual([true, true, true, false]);
  });

  it("never allows more than perMinute in any 60 s span", () => {
    // Kartik's case: 20/min, one attempt every second for six minutes.
    const times = Array.from({ length: 360 }, (_, i) => i * 1_000);
    const ok = run(20, times);
    const allowedAt = times.filter((_, i) => ok[i]);
    for (const start of allowedAt) {
      expect(allowedAt.filter((t) => t >= start && t < start + 60_000).length, `window at ${start}`).toBeLessThanOrEqual(20);
    }
    // ...and the cap is reached, not undershot: 20 per minute over 6 minutes.
    expect(allowedAt.length).toBe(120);
  });

  it("a slot frees exactly 60 s after it was used", () => {
    // 2/min: used at 0 and 10 s. Full until 60 s, then one slot, then 70 s.
    expect(run(2, [0, 10_000, 59_999, 60_000, 60_001, 69_999, 70_000])).toEqual([true, true, false, true, false, false, true]);
  });

  it("no burst credit after idling", () => {
    expect(run(3, [0, 3_600_000, 3_600_000, 3_600_000, 3_600_000])).toEqual([true, true, true, true, false]);
  });

  it("refused attempts don't extend the window", () => {
    // Hammering a full window every 100 ms still frees the slot on time.
    const times = [0, ...Array.from({ length: 600 }, (_, i) => 100 + i * 100)];
    const ok = run(1, times);
    expect(times.filter((_, i) => ok[i])).toEqual([0, 60_000]);
  });

  it("keeps only live stamps", () => {
    let s: number[] | undefined;
    for (let i = 0; i < 1_000; i++) s = takeSlot(s, 5, i * 30_000).sent;
    expect(s!.length).toBeLessThanOrEqual(5);
    expect(s!.every((t) => t > 999 * 30_000 - 60_000)).toBe(true);
  });
});

describe("RateLimiter Durable Object", () => {
  it("is shared through its name", async () => {
    const name = crypto.randomUUID();
    const a = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(name));
    const b = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(name));
    expect(await a.take(2)).toBe(true);
    expect(await b.take(2)).toBe(true);
    expect(await a.take(2)).toBe(false);
  });
});

describe("through the tool", () => {
  it("EMAIL_PER_MIN + 1 fails and is not delivered", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "3" }));
    for (let i = 0; i < 3; i++) expectSent(await w.sendEmail(ALICE, `m${i}`, "b"));
    expectRpcError(await w.sendEmail(ALICE, "m3", "b"), INVALID_REQUEST, LIMIT);
    expect(w.mailer.sent.map((m) => m.subject)).toEqual(["m0", "m1", "m2"]);
  });

  it("redirected and unparseable sends count against the same limit", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "2" }));
    expectSent(await w.sendEmail(OFF_LIST, "s", "b"));
    expectSent(await w.sendEmail("garbage", "s", "b"));
    expectRpcError(await w.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
    expect(w.mailer.sent).toHaveLength(2);
  });

  it("rate limit is checked before the body cap", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "1", MAX_BODY_BYTES: "5" }));
    expectRpcError(await w.sendEmail(ALICE, "s", "too long body"), INVALID_REQUEST, "message body exceeds size limit");
    expectRpcError(await w.sendEmail(ALICE, "s", "ok"), INVALID_REQUEST, LIMIT);
    expect(w.mailer.sent).toHaveLength(0);
  });

  it("SMTP failures consume budget", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "1" }));
    w.mailer.failWith = SMTP_FAILURE;
    expect((await w.sendEmail(ALICE, "s", "b")).error.code).toBe(INTERNAL_ERROR);
    expectRpcError(await w.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
  });

  it("concurrent requests share one limit", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "4" }));
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => w.sendEmail(ALICE, `c${i}`, "b")));
    expect(results.filter((r) => r.result).length).toBe(4);
    expect(results.filter((r) => r.error?.message === LIMIT).length).toBe(6);
    expect(w.mailer.sent).toHaveLength(4);
  });

  it("separate handler instances with the same limiter name share the limit", async () => {
    // Models several isolates/colos: the window lives in the Durable
    // Object, not in handler memory.
    const name = crypto.randomUUID();
    const a = worker(varsWith({ EMAIL_PER_MIN: "1" }), { limiterName: name });
    const b = worker(varsWith({ EMAIL_PER_MIN: "1" }), { limiterName: name });
    expectSent(await a.sendEmail(ALICE, "s", "b"));
    expectRpcError(await b.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
  });

  it("plain ping is free; ping with check_mail counts", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "1" }));
    for (let i = 0; i < 3; i++) expect((await w.ping()).error).toBeUndefined();
    expect((await w.ping({ check_mail: true })).error).toBeUndefined();
    expectRpcError(await w.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
    expectRpcError(await w.ping({ check_mail: true }), INVALID_REQUEST, LIMIT);
    expect(w.mailer.verifies).toBe(1);
  });
});

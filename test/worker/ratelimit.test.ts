// Rate-limit contract.
//
// * ONE global token bucket: a single Durable Object instance
//   (RATE_LIMITER, name "global" in production) whose `take(perMinute)`
//   atomically takes a token. Capacity = EMAIL_PER_MIN, refilled
//   continuously at EMAIL_PER_MIN per 60 s. State is in Durable Object
//   storage, so it survives isolate restarts and is shared by every
//   Cloudflare location (a per-isolate or per-colo counter would not be).
// * The check is the FIRST step of send_email, before the body cap and
//   recipient resolution: every attempt costs a token (allowlisted,
//   redirected, unparseable, oversize, and attempts that later fail at
//   SMTP). `ping` with `check_mail: true` also costs a token (it opens an
//   SMTP connection); plain `ping` does not.
// * Exhausted -> JSON-RPC error -32600 "email rate limit exceeded for this
//   minute", nothing sent.

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { takeToken } from "../../src/ratelimit";
import { ALICE, INTERNAL_ERROR, INVALID_REQUEST, OFF_LIST, SMTP_FAILURE, expectRpcError, expectSent, varsWith, worker } from "./helpers";

const LIMIT = "email rate limit exceeded for this minute";

describe("takeToken (pure)", () => {
  it("starts full and empties", () => {
    let s = undefined;
    for (let i = 0; i < 3; i++) {
      const r = takeToken(s, 3, 1_000);
      expect(r.allowed).toBe(true);
      s = r.state;
    }
    expect(takeToken(s, 3, 1_000).allowed).toBe(false);
  });

  it("refills continuously at perMinute per 60 s, capped at perMinute", () => {
    let s = undefined;
    for (let i = 0; i < 6; i++) s = takeToken(s, 6, 0).state; // empty
    expect(takeToken(s, 6, 9_999).allowed).toBe(false); // 6/min = one per 10 s
    const r = takeToken(s, 6, 10_000);
    expect(r.allowed).toBe(true);
    expect(takeToken(r.state, 6, 10_000).allowed).toBe(false);

    // A long idle period never accumulates more than the capacity.
    let t = takeToken(r.state, 6, 3_600_000).state;
    let granted = 1;
    while (takeToken(t, 6, 3_600_000).allowed) {
      t = takeToken(t, 6, 3_600_000).state;
      granted++;
      if (granted > 10) break;
    }
    expect(granted).toBe(6);
  });

  it("never goes negative on refused takes", () => {
    let s = undefined;
    for (let i = 0; i < 2; i++) s = takeToken(s, 2, 0).state;
    for (let i = 0; i < 5; i++) s = takeToken(s!, 2, 0).state;
    expect(s!.tokens).toBeGreaterThanOrEqual(0);
    expect(takeToken(s, 2, 30_000).allowed).toBe(true);
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

  it("redirected and unparseable sends spend the same bucket", async () => {
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

  it("concurrent requests share one bucket", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "4" }));
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => w.sendEmail(ALICE, `c${i}`, "b")));
    expect(results.filter((r) => r.result).length).toBe(4);
    expect(results.filter((r) => r.error?.message === LIMIT).length).toBe(6);
    expect(w.mailer.sent).toHaveLength(4);
  });

  it("separate handler instances with the same limiter name share the bucket", async () => {
    // Models several isolates/colos: the bucket lives in the Durable
    // Object, not in handler memory.
    const name = crypto.randomUUID();
    const a = worker(varsWith({ EMAIL_PER_MIN: "1" }), { limiterName: name });
    const b = worker(varsWith({ EMAIL_PER_MIN: "1" }), { limiterName: name });
    expectSent(await a.sendEmail(ALICE, "s", "b"));
    expectRpcError(await b.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
  });

  it("plain ping is free; ping with check_mail costs a token", async () => {
    const w = worker(varsWith({ EMAIL_PER_MIN: "1" }));
    for (let i = 0; i < 3; i++) expect((await w.ping()).error).toBeUndefined();
    expect((await w.ping({ check_mail: true })).error).toBeUndefined();
    expectRpcError(await w.sendEmail(ALICE, "s", "b"), INVALID_REQUEST, LIMIT);
    expectRpcError(await w.ping({ check_mail: true }), INVALID_REQUEST, LIMIT);
    expect(w.mailer.verifies).toBe(1);
  });
});

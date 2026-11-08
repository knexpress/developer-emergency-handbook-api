import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { computePurgeDueAt, computeStreak, isPurgeEligible, selectPurgeCandidates } from "./rules.js";

const HOUR = 60 * 60 * 1000;
const start = Date.parse("2026-01-01T00:00:00.000Z");
const resolvedAt = new Date(start).toISOString();
const purgeDueAt = computePurgeDueAt(resolvedAt);

describe("48 hour retention boundary", () => {
  it("schedules purge exactly 48 hours after resolvedAt in UTC", () => {
    assert.equal(purgeDueAt, "2026-01-03T00:00:00.000Z");
  });

  it("does not delete at 47h 59m or one millisecond early", () => {
    const at4759 = start + (47 * 60 + 59) * 60 * 1000;
    assert.equal(isPurgeEligible(subject(), at4759), false);
    assert.equal(isPurgeEligible(subject(), start + 48 * HOUR - 1), false);
  });

  it("is eligible at exactly 48 hours and after", () => {
    assert.equal(isPurgeEligible(subject(), start + 48 * HOUR), true);
    assert.equal(isPurgeEligible(subject(), start + 48 * HOUR + 1), true);
  });

  it("never selects an unresolved error, even with an old timestamp or a stray due date", () => {
    const open = subject({ status: "open", resolvedAt: null, purgeDueAt: null });
    const ancient = subject({ status: "open", resolvedAt: null, purgeDueAt });
    assert.equal(isPurgeEligible(open, start + 30 * 24 * HOUR), false);
    assert.equal(isPurgeEligible(ancient, start + 30 * 24 * HOUR), false);
    assert.deepEqual(selectPurgeCandidates([open, ancient, subject()], start + 47 * HOUR), []);
    assert.equal(selectPurgeCandidates([subject()], start + 48 * HOUR).length, 1);
  });

  it("ignores blocked and already purged rows", () => {
    assert.equal(isPurgeEligible(subject({ purgeBlockReason: "source_detached" }), start + 72 * HOUR), false);
    assert.equal(isPurgeEligible(subject({ purgedAt: purgeDueAt }), start + 72 * HOUR), false);
  });
});

describe("reward streak", () => {
  it("counts consecutive UTC award days and stays alive through yesterday", () => {
    const now = Date.parse("2026-06-04T18:00:00.000Z");
    assert.equal(computeStreak([{ awardedAt: "2026-06-04T01:00:00.000Z" }, { awardedAt: "2026-06-03T05:00:00.000Z" }, { awardedAt: "2026-06-02T23:00:00.000Z" }], now), 3);
    assert.equal(computeStreak([{ awardedAt: "2026-06-03T05:00:00.000Z" }, { awardedAt: "2026-06-02T23:00:00.000Z" }], now), 2);
    assert.equal(computeStreak([{ awardedAt: "2026-06-02T23:00:00.000Z" }], now), 0);
    assert.equal(computeStreak([{ awardedAt: "2026-06-04T01:00:00.000Z" }, { awardedAt: "2026-06-02T01:00:00.000Z" }], now), 1);
  });
});

function subject(overrides: Record<string, unknown> = {}) {
  return {
    status: "resolved" as const,
    resolvedAt,
    purgeDueAt,
    purgedAt: null,
    purgeBlockReason: null,
    ...overrides,
  };
}

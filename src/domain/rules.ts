import {
  PURGE_AFTER_MS,
  type Incident,
  type RewardLedgerEntry,
  type Severity,
} from "./types.js";

export const POINTS: Record<Severity, number> = {
  critical: 50,
  high: 30,
  medium: 15,
  low: 5,
};

export const REWARD_RULES: readonly string[] = [
  "Errors Solved increases by one the first time a canonical incident moves from open to resolved.",
  "A second tap, a retry, or a race on the same incident does not add another count or more points.",
  "Reopening keeps the ledger entry. Resolving that same incident again does not award a second time.",
  "Points are awarded once, with the first resolution: critical 50, high 30, medium 15, low 5.",
  "A streak day is a UTC day with at least one first-time resolution. The streak stays alive when the latest award was today or yesterday on the handbook clock.",
  "The ledger is not stored in Backend_errors. Purging the source document does not change Errors Solved.",
  "Badges read that ledger. They are illustrative markers, not a review of on-call performance.",
  "Marking resolved records acknowledgement. It does not change application code on the monitored system.",
];

export interface BadgeDefinition {
  id: string;
  name: string;
  rule: string;
}

export const BADGE_DEFS: readonly BadgeDefinition[] = [
  { id: "first-response", name: "First response", rule: "Resolve one distinct incident." },
  { id: "steady-hand", name: "Steady hand", rule: "Resolve five distinct incidents." },
  { id: "night-watch", name: "Night watch", rule: "Resolve ten distinct incidents." },
  { id: "critical-closer", name: "Critical closer", rule: "Resolve three distinct critical incidents." },
  { id: "three-day-watch", name: "Three-day watch", rule: "First-time resolutions on three consecutive UTC days." },
];

export interface PurgeSubject {
  status: Incident["status"];
  resolvedAt: string | null;
  purgeDueAt: string | null;
  purgedAt: string | null;
  purgeBlockReason: string | null;
}

/** Eligible only at or after resolvedAt + 48 hours. Open errors are never eligible. */
export function isPurgeEligible(incident: PurgeSubject, nowMs: number): boolean {
  if (incident.purgedAt) return false;
  if (incident.purgeBlockReason) return false;
  if (incident.status !== "resolved") return false;
  if (!incident.resolvedAt || !incident.purgeDueAt) return false;
  const due = Date.parse(incident.purgeDueAt);
  if (Number.isNaN(due)) return false;
  return nowMs >= due;
}

export function computePurgeDueAt(resolvedAtIso: string): string {
  const t = Date.parse(resolvedAtIso);
  if (Number.isNaN(t)) throw new Error("resolvedAt is not a valid time.");
  return new Date(t + PURGE_AFTER_MS).toISOString();
}

export function selectPurgeCandidates<T extends PurgeSubject>(incidents: T[], nowMs: number): T[] {
  return incidents.filter((incident) => isPurgeEligible(incident, nowMs));
}

export function utcDay(isoOrMs: string | number): string {
  const ms = typeof isoOrMs === "number" ? isoOrMs : Date.parse(isoOrMs);
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Consecutive UTC award days ending today, or ending yesterday if today has none.
 * Days without a first-time award break the streak. Re-awards cannot add days because
 * the ledger stores one row per incident.
 */
export function computeStreak(ledger: Pick<RewardLedgerEntry, "awardedAt">[], nowMs: number): number {
  const days = new Set(ledger.map((entry) => utcDay(entry.awardedAt)));
  let cursor = Date.parse(`${utcDay(nowMs)}T00:00:00.000Z`);
  if (!days.has(utcDay(cursor))) {
    cursor -= 24 * 60 * 60 * 1000;
    if (!days.has(utcDay(cursor))) return 0;
  }
  let streak = 0;
  while (days.has(utcDay(cursor))) {
    streak += 1;
    cursor -= 24 * 60 * 60 * 1000;
  }
  return streak;
}

export function badgeEarned(
  id: string,
  stats: { solved: number; criticalSolved: number; streak: number },
): boolean {
  switch (id) {
    case "first-response":
      return stats.solved >= 1;
    case "steady-hand":
      return stats.solved >= 5;
    case "night-watch":
      return stats.solved >= 10;
    case "critical-closer":
      return stats.criticalSolved >= 3;
    case "three-day-watch":
      return stats.streak >= 3;
    default:
      return false;
  }
}

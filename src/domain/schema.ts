import type { Severity } from "./types.js";
import { fingerprintFrom, safeContext, sanitizeErrorText } from "./security.js";

export interface SchemaMap {
  id: string;
  label: string;
  description: string;
  paths: {
    severity: string;
    message: string;
    stack: string;
    timestamp: string;
    fingerprint: string;
    context: string;
    occurrenceCount: string;
  };
  severityMap: Record<string, Severity>;
}

export const MONGODB_BACKEND_ERRORS_V1: SchemaMap = {
  id: "mongodb-backend-errors-v1",
  label: "MongoDB Backend_errors",
  description: "Default assumption for an existing collection named Backend_errors with level, msg, stack, ts, and meta.",
  paths: {
    severity: "level",
    message: "msg",
    stack: "stack",
    timestamp: "ts",
    fingerprint: "fingerprint",
    context: "meta",
    occurrenceCount: "count",
  },
  severityMap: {
    fatal: "critical",
    critical: "critical",
    error: "high",
    high: "high",
    warn: "medium",
    warning: "medium",
    medium: "medium",
    info: "low",
    low: "low",
    debug: "low",
  },
};

export const POSTGRES_BACKEND_ERRORS_V1: SchemaMap = {
  id: "postgres-backend-errors-v1",
  label: "Postgres Backend_errors",
  description: "Column mapping when Backend_errors is a Postgres table. Opt-in with DEH_ENABLE_POSTGRES=1.",
  paths: {
    severity: "severity",
    message: "message",
    stack: "stack_trace",
    timestamp: "created_at",
    fingerprint: "fingerprint",
    context: "context",
    occurrenceCount: "occurrence_count",
  },
  severityMap: {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
  },
};

export const SCHEMA_MAPS: Record<string, SchemaMap> = {
  [MONGODB_BACKEND_ERRORS_V1.id]: MONGODB_BACKEND_ERRORS_V1,
  [POSTGRES_BACKEND_ERRORS_V1.id]: POSTGRES_BACKEND_ERRORS_V1,
};

export function readPath(obj: unknown, path: string): unknown {
  if (!path) return undefined;
  let current: unknown = obj;
  for (const key of path.split(".")) {
    if (!current || typeof current !== "object" || !(key in current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

export interface NormalizedError {
  severity: Severity;
  message: string;
  stackRedacted: string;
  timestamp: string;
  fingerprint: string;
  context: Record<string, string>;
  occurrenceCount: number;
}

export function mapBackendError(doc: Record<string, unknown>, map: SchemaMap, fallbackTime: string): NormalizedError {
  const rawSeverity = String(readPath(doc, map.paths.severity) ?? "error").toLowerCase();
  const severity = map.severityMap[rawSeverity] ?? "high";
  const message = sanitizeErrorText(String(readPath(doc, map.paths.message) ?? "Untitled backend error")).slice(0, 400);
  const stackRedacted = sanitizeErrorText(String(readPath(doc, map.paths.stack) ?? "")).slice(0, 4000);
  const tsRaw = readPath(doc, map.paths.timestamp);
  const timestamp = typeof tsRaw === "string" && !Number.isNaN(Date.parse(tsRaw)) ? new Date(tsRaw).toISOString() : fallbackTime;
  const fpRaw = readPath(doc, map.paths.fingerprint);
  const fingerprint = typeof fpRaw === "string" && /^[a-z0-9_-]{6,64}$/i.test(fpRaw)
    ? fpRaw.toLowerCase()
    : fingerprintFrom(message, stackRedacted);
  const contextRaw = readPath(doc, map.paths.context);
  const context = contextRaw && typeof contextRaw === "object"
    ? safeContext(contextRaw as Record<string, unknown>)
    : {};
  const countRaw = readPath(doc, map.paths.occurrenceCount);
  const occurrenceCount = typeof countRaw === "number" && Number.isFinite(countRaw) && countRaw > 0
    ? Math.min(Math.floor(countRaw), 10_000)
    : 1;
  return { severity, message, stackRedacted, timestamp, fingerprint, context, occurrenceCount };
}

export const SAMPLE_MONGODB_BACKEND_ERROR: Record<string, unknown> = {
  _id: "demo_doc_1",
  level: "error",
  msg: "Charge capture failed after authorization hold",
  stack: "Error: Charge capture failed after authorization hold\n    at CaptureService.commit (src/payments/capture.ts:188:11)",
  ts: "2026-06-01T12:00:00.000Z",
  fingerprint: "c7e1a9f0b3d24e18",
  count: 4,
  meta: {
    requestId: "req_demo_18f3",
    region: "synthetic-eu",
    password: "should-not-pass",
    note: "operator pinged oncall@example.com",
  },
};

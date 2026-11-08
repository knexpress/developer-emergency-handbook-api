export const APP_NAME = "Developer Emergency Handbook";
/** Default collection/table name when the operator does not pick one. */
export const COLLECTION_NAME = "Backend_errors" as const;
export const PURGE_AFTER_MS = 48 * 60 * 60 * 1000;
export const RETENTION_BATCH_LIMIT = 25;
export const RETENTION_MAX_ATTEMPTS = 5;

export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "open" | "resolved";
export type SourceHealth = "connected" | "disconnected" | "stale";
export type EnvironmentName = "production" | "staging" | "development";
export type AdapterKind = "mongodb" | "postgres";
export type StatusBasis = "simulated-scenario" | "unchecked" | "adapter-stub" | "last-test" | "live";
export type GatewayMode = "demo" | "live" | "production";

export interface ConnectionProfile {
  id: string;
  displayName: string;
  system: string;
  environment: EnvironmentName;
  databaseName: string;
  collectionName: string;
  adapterKind: AdapterKind;
  /** Demo-only fake reference. Never a URI. Omitted from API responses. */
  secretRef: string | null;
  secretMasked: string;
  /** Encrypted URI on the gateway. Never returned by the API. */
  secretCiphertext: string | null;
  status: SourceHealth;
  statusBasis: StatusBasis;
  lastCheckedAt: string | null;
  staleAfterMinutes: number;
  detachedAt: string | null;
  schemaMapId: string;
  createdAt: string;
  updatedAt: string;
}

export interface SourceDocument {
  sourceDocumentId: string;
  sourceId: string;
  collectionName: string;
  databaseName: string;
  body: Record<string, unknown>;
}

export interface SourceSnapshot {
  displayName: string;
  system: string;
  environment: EnvironmentName;
  databaseName: string;
  collectionName: string;
}

export interface Incident {
  id: string;
  sourceId: string;
  sourceDocumentIds: string[];
  fingerprint: string;
  severity: Severity;
  message: string;
  stackRedacted: string;
  context: Record<string, string>;
  firstSeenAt: string;
  lastSeenAt: string;
  status: IncidentStatus;
  resolvedAt: string | null;
  resolvedBy: string | null;
  purgeDueAt: string | null;
  resolutionVersion: number;
  notes: string;
  purgedAt: string | null;
  purgeBlockReason: string | null;
  snapshot: SourceSnapshot;
}

export interface RewardLedgerEntry {
  incidentId: string;
  sourceId: string;
  fingerprint: string;
  severity: Severity;
  points: number;
  awardedAt: string;
  actor: string;
}

/** Minimal proof of deletion. Must not carry the error payload. */
export interface PurgeReceipt {
  id: string;
  incidentId: string;
  sourceId: string;
  fingerprint: string;
  severity: Severity;
  documentCount: number;
  resolvedAt: string;
  purgeDueAt: string;
  purgedAt: string;
  resolutionVersion: number;
}

export interface DeadLetter {
  id: string;
  incidentId: string;
  sourceId: string;
  reason: string;
  attempts: number;
  at: string;
}

export interface RetryState {
  incidentId: string;
  attempts: number;
  nextAttemptAt: string;
  lastError: string;
}

export type AuditAction =
  | "incident.resolved"
  | "incident.resolve_duplicate"
  | "incident.reopened"
  | "incident.purged"
  | "incident.note"
  | "incident.recurrence"
  | "source.created"
  | "source.updated"
  | "source.detached"
  | "source.tested"
  | "retention.deadletter"
  | "demo.reset"
  | "demo.clock";

export interface AuditEvent {
  id: string;
  at: string;
  actor: string;
  action: AuditAction;
  incidentId?: string;
  sourceId?: string;
  detail: string;
}

export interface StoreData {
  clockOffsetMs: number;
  sources: ConnectionProfile[];
  incidents: Incident[];
  ledger: RewardLedgerEntry[];
  receipts: PurgeReceipt[];
  deadletters: DeadLetter[];
  retries: RetryState[];
  audit: AuditEvent[];
  collections: Record<string, SourceDocument[]>;
}

export interface Clock {
  nowMs(): number;
  iso(): string;
}

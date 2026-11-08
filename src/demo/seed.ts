import { createHash, randomUUID } from "node:crypto";
import { COLLECTION_NAME, type Incident, type Severity, type SourceDocument, type StoreData } from "../domain/types.js";
import { computePurgeDueAt, POINTS } from "../domain/rules.js";
import { sanitizeErrorText } from "../domain/security.js";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

function fp(seed: string): string {
  return createHash("sha256").update(seed).digest("hex").slice(0, 16);
}

interface SourceSeed {
  id: string;
  displayName: string;
  system: string;
  environment: "production" | "staging" | "development";
  databaseName: string;
  secretRef: string;
  status: "connected" | "disconnected" | "stale";
  lastCheckedAgeMs: number;
  staleAfterMinutes: number;
  adapterKind?: "mongodb" | "postgres";
}

interface IncidentSeed {
  id: string;
  sourceId: string;
  severity: Severity;
  message: string;
  stack: string;
  context: Record<string, string>;
  occurrences: number;
  lastSeenAgeMs: number;
  historyMs: number;
  resolvedAgeMs?: number;
  notes?: string;
}

const SOURCES: SourceSeed[] = [
  {
    id: "src_ledger_prod",
    displayName: "Ledger API",
    system: "Ledger API",
    environment: "production",
    databaseName: "payments_ledger",
    secretRef: "ref_demo_ledger_prod",
    status: "connected",
    lastCheckedAgeMs: 4 * MINUTE,
    staleAfterMinutes: 30,
  },
  {
    id: "src_ledger_stage",
    displayName: "Ledger API",
    system: "Ledger API",
    environment: "staging",
    databaseName: "payments_ledger",
    secretRef: "ref_demo_ledger_stage",
    status: "connected",
    lastCheckedAgeMs: 6 * MINUTE,
    staleAfterMinutes: 30,
  },
  {
    id: "src_dispatch_prod",
    displayName: "Dispatch Worker",
    system: "Dispatch Worker",
    environment: "production",
    databaseName: "dispatch_runtime",
    secretRef: "ref_demo_dispatch_prod",
    status: "stale",
    lastCheckedAgeMs: 3 * HOUR,
    staleAfterMinutes: 45,
  },
  {
    id: "src_identity_prod",
    displayName: "Identity Gateway",
    system: "Identity Gateway",
    environment: "production",
    databaseName: "identity_core",
    secretRef: "ref_demo_identity_prod",
    status: "disconnected",
    lastCheckedAgeMs: 26 * HOUR,
    staleAfterMinutes: 20,
  },
  {
    id: "src_catalog_prod",
    displayName: "Catalog Edge",
    system: "Catalog Edge",
    environment: "production",
    databaseName: "catalog_edge",
    secretRef: "ref_demo_catalog_prod",
    status: "connected",
    lastCheckedAgeMs: 2 * MINUTE,
    staleAfterMinutes: 30,
    adapterKind: "postgres",
  },
];

const INCIDENTS: IncidentSeed[] = [
  {
    id: "inc_capture",
    sourceId: "src_ledger_prod",
    severity: "critical",
    message: "Charge capture failed after authorization hold",
    stack: [
      "Error: Charge capture failed after authorization hold",
      "    at CaptureService.commit (src/payments/capture.ts:188:11)",
      "    at Route.handler (src/http/routes/charges.ts:74:5)",
    ].join("\n"),
    context: { requestId: "req_demo_18f3", region: "synthetic-eu", holdId: "hold_demo_441" },
    occurrences: 14,
    lastSeenAgeMs: 12 * MINUTE,
    historyMs: 6 * HOUR,
  },
  {
    id: "inc_settlement",
    sourceId: "src_ledger_prod",
    severity: "high",
    message: "Settlement batch rejected by the clearing window",
    stack: [
      "Error: Settlement batch rejected by the clearing window",
      "    at BatchPoster.submit (src/payments/settlement.ts:96:9)",
    ].join("\n"),
    context: { batchId: "batch_demo_77", region: "synthetic-eu" },
    occurrences: 3,
    lastSeenAgeMs: 40 * MINUTE,
    historyMs: 2 * HOUR,
  },
  {
    id: "inc_projection",
    sourceId: "src_ledger_prod",
    severity: "high",
    message: "Balance projection lag crossed the paging threshold",
    stack: [
      "Error: Balance projection lag crossed the paging threshold",
      "    at ProjectionLag.watch (src/payments/projection.ts:41:7)",
    ].join("\n"),
    context: { lagMs: "8420", consumer: "balances" },
    occurrences: 5,
    lastSeenAgeMs: 2 * HOUR,
    historyMs: 5 * HOUR,
  },
  {
    id: "inc_replay",
    sourceId: "src_ledger_prod",
    severity: "medium",
    message: "Replay window rejected a duplicate transfer id",
    stack: [
      "Error: Replay window rejected a duplicate transfer id",
      "    at TransferInbox.accept (src/payments/inbox.ts:55:4)",
    ].join("\n"),
    context: { transferId: "xfer_demo_2201" },
    occurrences: 1,
    lastSeenAgeMs: 12 * 24 * HOUR,
    historyMs: 2 * HOUR,
  },
  {
    id: "inc_webhook",
    sourceId: "src_ledger_stage",
    severity: "medium",
    message: "Sandbox webhook signature did not match",
    stack: [
      "Error: Sandbox webhook signature did not match",
      "    at WebhookGuard.verify (src/http/webhook.ts:33:6)",
    ].join("\n"),
    context: { provider: "sandbox-clearing", event: "capture.updated" },
    occurrences: 6,
    lastSeenAgeMs: 25 * MINUTE,
    historyMs: 3 * HOUR,
  },
  {
    id: "inc_sandbox_timeout",
    sourceId: "src_ledger_stage",
    severity: "low",
    message: "Sandbox ledger timed out waiting for a fixture account",
    stack: [
      "Error: Sandbox ledger timed out waiting for a fixture account",
      "    at FixtureBank.lookup (src/sandbox/fixtures.ts:22:3)",
    ].join("\n"),
    context: { account: "fixture_demo_9" },
    occurrences: 2,
    lastSeenAgeMs: 3 * HOUR,
    historyMs: HOUR,
  },
  {
    id: "inc_route",
    sourceId: "src_dispatch_prod",
    severity: "high",
    message: "Route assignment exceeded the courier SLA",
    stack: [
      "Error: Route assignment exceeded the courier SLA",
      "    at Assigner.claim (src/dispatch/assign.ts:140:8)",
    ].join("\n"),
    context: { zone: "synthetic-north", slaSeconds: "180" },
    occurrences: 9,
    lastSeenAgeMs: 55 * MINUTE,
    historyMs: 4 * HOUR,
  },
  {
    id: "inc_label",
    sourceId: "src_dispatch_prod",
    severity: "medium",
    message: "Label printer acknowledgement arrived late",
    stack: [
      "Error: Label printer acknowledgement arrived late",
      "    at PrinterAck.wait (src/dispatch/labels.ts:61:2)",
    ].join("\n"),
    context: { station: "pack-demo-4" },
    occurrences: 4,
    lastSeenAgeMs: 5 * HOUR,
    historyMs: 2 * HOUR,
  },
  {
    id: "inc_token",
    sourceId: "src_identity_prod",
    severity: "critical",
    message: "Token introspection timed out during session exchange",
    stack: [
      "Error: Token introspection timed out during session exchange",
      "    at Introspector.fetch (src/identity/introspect.ts:77:5)",
    ].join("\n"),
    context: { audience: "handbook-demo", region: "synthetic-eu" },
    occurrences: 21,
    lastSeenAgeMs: 8 * MINUTE,
    historyMs: 9 * HOUR,
  },
  {
    id: "inc_session",
    sourceId: "src_identity_prod",
    severity: "high",
    message: "Refresh grant replay was refused",
    stack: [
      "Error: Refresh grant replay was refused",
      "    at GrantStore.consume (src/identity/grants.ts:29:4)",
    ].join("\n"),
    context: { grant: "grant_demo_11" },
    occurrences: 7,
    lastSeenAgeMs: HOUR,
    historyMs: 6 * HOUR,
  },
  {
    id: "inc_price",
    sourceId: "src_catalog_prod",
    severity: "low",
    message: "Stale price snapshot served from the edge cache",
    stack: [
      "Error: Stale price snapshot served from the edge cache",
      "    at PriceCache.read (src/catalog/prices.ts:18:6)",
    ].join("\n"),
    context: { sku: "sku_demo_100", edge: "pop-synthetic-1" },
    occurrences: 2,
    lastSeenAgeMs: 4 * HOUR,
    historyMs: 8 * HOUR,
  },
  {
    id: "inc_image",
    sourceId: "src_catalog_prod",
    severity: "low",
    message: "Image derivative missing for a catalog sku",
    stack: [
      "Error: Image derivative missing for a catalog sku",
      "    at DerivativeStore.open (src/catalog/images.ts:44:3)",
    ].join("\n"),
    context: { sku: "sku_demo_204", variant: "thumb" },
    occurrences: 1,
    lastSeenAgeMs: 26 * HOUR,
    historyMs: HOUR,
  },
  {
    id: "inc_fx_round",
    sourceId: "src_ledger_prod",
    severity: "medium",
    message: "FX rounding residual exceeded the daily tolerance",
    stack: [
      "Error: FX rounding residual exceeded the daily tolerance",
      "    at FxBook.residual (src/payments/fx.ts:70:4)",
    ].join("\n"),
    context: { book: "synthetic-usd" },
    occurrences: 2,
    lastSeenAgeMs: 6 * HOUR,
    historyMs: 3 * HOUR,
    resolvedAgeMs: 6 * HOUR,
    notes: "Acknowledged during the demo seed. No code change was made.",
  },
  {
    id: "inc_courier_ack",
    sourceId: "src_dispatch_prod",
    severity: "high",
    message: "Courier check-in ack missing after dispatch",
    stack: [
      "Error: Courier check-in ack missing after dispatch",
      "    at CheckIn.await (src/dispatch/checkin.ts:19:5)",
    ].join("\n"),
    context: { route: "route_demo_8" },
    occurrences: 3,
    lastSeenAgeMs: 30 * HOUR,
    historyMs: 2 * HOUR,
    resolvedAgeMs: 30 * HOUR,
  },
  {
    id: "inc_cache_header",
    sourceId: "src_catalog_prod",
    severity: "low",
    message: "Cache vary header omitted on a catalog response",
    stack: [
      "Error: Cache vary header omitted on a catalog response",
      "    at CacheHeader.write (src/catalog/http.ts:27:2)",
    ].join("\n"),
    context: { path: "/v1/prices" },
    occurrences: 1,
    lastSeenAgeMs: 46 * HOUR,
    historyMs: HOUR,
    resolvedAgeMs: 46 * HOUR,
  },
  {
    id: "inc_oauth_clock",
    sourceId: "src_identity_prod",
    severity: "high",
    message: "Token clock skew rejected a fresh assertion",
    stack: [
      "Error: Token clock skew rejected a fresh assertion",
      "    at ClockSkew.assert (src/identity/time.ts:15:3)",
    ].join("\n"),
    context: { skewSeconds: "42" },
    occurrences: 4,
    lastSeenAgeMs: 2 * HOUR,
    historyMs: HOUR,
    resolvedAgeMs: 2 * HOUR,
  },
  {
    id: "inc_stage_double",
    sourceId: "src_ledger_stage",
    severity: "critical",
    message: "Staging double-entry pair failed to balance",
    stack: [
      "Error: Staging double-entry pair failed to balance",
      "    at Journal.post (src/payments/journal.ts:101:6)",
    ].join("\n"),
    context: { journal: "jnl_demo_3" },
    occurrences: 2,
    lastSeenAgeMs: 10 * HOUR,
    historyMs: 4 * HOUR,
    resolvedAgeMs: 10 * HOUR,
  },
];

function mask(ref: string): string {
  return `${ref.slice(0, 8)}••••${ref.slice(-4)}`;
}

export function buildSeed(nowMs: number): StoreData {
  const nowIso = new Date(nowMs).toISOString();
  const sources = SOURCES.map((source) => {
    const adapterKind = source.adapterKind ?? "mongodb";
    return {
      id: source.id,
      displayName: source.displayName,
      system: source.system,
      environment: source.environment,
      databaseName: source.databaseName,
      collectionName: COLLECTION_NAME,
      adapterKind,
      secretRef: source.secretRef,
      secretMasked: mask(source.secretRef),
      secretCiphertext: null,
      status: source.status,
      statusBasis: "simulated-scenario" as const,
      lastCheckedAt: new Date(nowMs - source.lastCheckedAgeMs).toISOString(),
      staleAfterMinutes: source.staleAfterMinutes,
      detachedAt: null,
      schemaMapId: adapterKind === "postgres" ? "postgres-backend-errors-v1" : "mongodb-backend-errors-v1",
      createdAt: new Date(nowMs - 20 * 24 * HOUR).toISOString(),
      updatedAt: nowIso,
    };
  });

  const sourceById = Object.fromEntries(sources.map((source) => [source.id, source]));
  const incidents: Incident[] = [];
  const collections: Record<string, SourceDocument[]> = {};

  for (const item of INCIDENTS) {
    const source = sourceById[item.sourceId];
    if (!source) throw new Error(`Unknown seed source ${item.sourceId}`);
    const lastSeenAt = new Date(nowMs - item.lastSeenAgeMs).toISOString();
    const firstSeenAt = new Date(nowMs - item.lastSeenAgeMs - item.historyMs).toISOString();
    const ids: string[] = [];
    for (let n = 1; n <= item.occurrences; n += 1) {
      const sourceDocumentId = `${item.id}_doc_${n}`;
      ids.push(sourceDocumentId);
      const body =
        source.adapterKind === "postgres"
          ? {
              id: sourceDocumentId,
              severity: item.severity,
              message: item.message,
              stack_trace: item.stack,
              created_at: n === item.occurrences ? lastSeenAt : firstSeenAt,
              fingerprint: fp(item.id),
              occurrence_count: 1,
              context: item.context,
              synthetic: true,
            }
          : {
              _id: sourceDocumentId,
              level: item.severity,
              msg: item.message,
              ts: n === item.occurrences ? lastSeenAt : firstSeenAt,
              fingerprint: fp(item.id),
              synthetic: true,
            };
      const doc: SourceDocument = {
        sourceDocumentId,
        sourceId: source.id,
        collectionName: COLLECTION_NAME,
        databaseName: source.databaseName,
        body,
      };
      const bucket = collections[source.id] ?? [];
      bucket.push(doc);
      collections[source.id] = bucket;
    }
    const resolved = item.resolvedAgeMs !== undefined;
    const resolvedAt = resolved ? new Date(nowMs - item.resolvedAgeMs!).toISOString() : null;
    incidents.push({
      id: item.id,
      sourceId: source.id,
      sourceDocumentIds: ids,
      fingerprint: fp(item.id),
      severity: item.severity,
      message: item.message,
      stackRedacted: sanitizeErrorText(item.stack),
      context: item.context,
      firstSeenAt,
      lastSeenAt,
      status: resolved ? "resolved" : "open",
      resolvedAt,
      resolvedBy: resolved ? "demo-operator" : null,
      purgeDueAt: resolvedAt ? computePurgeDueAt(resolvedAt) : null,
      resolutionVersion: resolved ? 1 : 0,
      notes: item.notes ?? "",
      purgedAt: null,
      purgeBlockReason: null,
      snapshot: {
        displayName: source.displayName,
        system: source.system,
        environment: source.environment,
        databaseName: source.databaseName,
        collectionName: COLLECTION_NAME,
      },
    });
  }

  const purgedResolvedAt = new Date(nowMs - 51 * HOUR).toISOString();
  const purgedAt = new Date(nowMs - 3 * HOUR).toISOString();
  const ledger = incidents
    .filter((incident) => incident.status === "resolved" && incident.resolvedAt)
    .map((incident) => ({
      incidentId: incident.id,
      sourceId: incident.sourceId,
      fingerprint: incident.fingerprint,
      severity: incident.severity,
      points: POINTS[incident.severity],
      awardedAt: incident.resolvedAt as string,
      actor: "demo-operator",
    }));

  ledger.push({
    incidentId: "inc_checksum",
    sourceId: "src_ledger_prod",
    fingerprint: fp("inc_checksum"),
    severity: "medium",
    points: POINTS.medium,
    awardedAt: purgedResolvedAt,
    actor: "demo-operator",
  });

  return {
    clockOffsetMs: 0,
    sources,
    incidents,
    ledger,
    receipts: [
      {
        id: "rcpt_checksum",
        incidentId: "inc_checksum",
        sourceId: "src_ledger_prod",
        fingerprint: fp("inc_checksum"),
        severity: "medium",
        documentCount: 2,
        resolvedAt: purgedResolvedAt,
        purgeDueAt: computePurgeDueAt(purgedResolvedAt),
        purgedAt,
        resolutionVersion: 1,
      },
    ],
    deadletters: [],
    retries: [],
    audit: [
      {
        id: `audit_${randomUUID().slice(0, 8)}`,
        at: nowIso,
        actor: "demo-seed",
        action: "demo.reset",
        detail: "Loaded the illustrative demo seed. No external database was contacted.",
      },
    ],
    collections,
  };
}

import { randomUUID } from "node:crypto";
import {
  deleteDemoDocument,
  deleteMongoDocument,
  deletePostgresDocument,
  insertDemoDocument,
} from "../adapters/collections.js";
import {
  adapterKindFromUri,
  discoverDatabase,
  fetchErrorDocuments,
  testLiveConnection,
} from "../adapters/live.js";
import { buildSeed } from "../demo/seed.js";
import {
  badgeEarned,
  BADGE_DEFS,
  computePurgeDueAt,
  computeStreak,
  isPurgeEligible,
  POINTS,
  REWARD_RULES,
  selectPurgeCandidates,
  utcDay,
} from "../domain/rules.js";
import { mapBackendError, SCHEMA_MAPS } from "../domain/schema.js";
import {
  assertDemoSecretRef,
  decryptString,
  encryptString,
  fingerprintFrom,
  maskDatabaseUri,
  maskSecretRef,
  safeContext,
  sanitizeErrorText,
  validateDatabaseTarget,
} from "../domain/security.js";
import {
  APP_NAME,
  COLLECTION_NAME,
  RETENTION_BATCH_LIMIT,
  RETENTION_MAX_ATTEMPTS,
  type AdapterKind,
  type AuditAction,
  type AuditEvent,
  type Clock,
  type ConnectionProfile,
  type EnvironmentName,
  type GatewayMode,
  type Incident,
  type Severity,
  type StoreData,
} from "../domain/types.js";
import type { Store } from "../store/store.js";

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export interface ExternalDeleteArgs {
  uri: string;
  databaseName: string;
  collectionName: string;
  sourceDocumentId: string;
  adapterKind: AdapterKind;
}

export interface ServiceOptions {
  mode: GatewayMode;
  retentionIntervalMs: number;
  allowPrivateNetworks: boolean;
  mongodbEnabled: boolean;
  postgresEnabled: boolean;
  masterKey?: Buffer;
  /** When false, createSource stores the URI without opening a socket (tests). */
  verifyLiveConnection?: boolean;
  deleteExternal?: (args: ExternalDeleteArgs) => Promise<"deleted" | "not_found">;
}

export interface RetentionHooks {
  beforeEachDelete?: (draft: StoreData, incidentId: string, sourceDocumentId: string) => void;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function uid(prefix: string): string {
  return `${prefix}_${randomUUID().slice(0, 8)}`;
}

function pushAudit(
  draft: StoreData,
  event: Omit<AuditEvent, "id" | "at"> & { at?: string },
  at: string,
): void {
  draft.audit.push({
    id: uid("audit"),
    at: event.at ?? at,
    actor: event.actor,
    action: event.action,
    incidentId: event.incidentId,
    sourceId: event.sourceId,
    detail: sanitizeErrorText(event.detail).slice(0, 300),
  });
  if (draft.audit.length > 300) draft.audit.splice(0, draft.audit.length - 300);
}

function activeSources(draft: StoreData): ConnectionProfile[] {
  return draft.sources.filter((source) => !source.detachedAt);
}

function sourceAlias(source: { displayName: string; environment: string }): string {
  const env = source.environment.slice(0, 1).toUpperCase() + source.environment.slice(1);
  return `${source.displayName} · ${env}`;
}

export class HandbookService {
  constructor(
    private readonly store: Store,
    private readonly clock: Clock,
    private readonly options: ServiceOptions,
  ) {}

  async ensureDemoSeed(): Promise<void> {
    // Live/production start empty. Demo seed is opt-in only for local illustration.
    if (this.options.mode !== "demo" || process.env.DEH_SEED_DEMO !== "1") return;
    const state = this.store.read();
    if (state.sources.length > 0) return;
    const wall = this.clock.nowMs() - state.clockOffsetMs;
    const seeded = buildSeed(wall);
    await this.store.transaction((draft) => {
      Object.assign(draft, seeded);
    });
  }

  async meta() {
    const now = this.clock.iso();
    const live = this.options.mode !== "demo";
    return {
      appName: APP_NAME,
      mode: this.options.mode,
      simulated: this.options.mode === "demo",
      now,
      retentionIntervalMs: this.options.retentionIntervalMs,
      purgeAfterHours: 48,
      collectionName: COLLECTION_NAME,
      dataOrigin: this.options.mode === "demo" ? "illustrative-demo-seed" : "live-sources",
      adapterAssumption:
        "Add a database URI in Settings, pick the error collection or table, and give it a nickname. The gateway stores the URI encrypted and syncs incidents into the board.",
      deviceClockUnchanged: true,
      real: [
        "Resolve and reopen are conditional state transitions with a resolution version.",
        "Purge eligibility is resolvedAt plus 48 hours UTC, never createdAt.",
        "The retention pass deletes one error document at a time from the incident's original source collection.",
        "Errors Solved is a ledger keyed by incident id and survives purge.",
        "Detaching a profile does not drop a database or collection.",
        "MongoDB and Postgres: discover collections, sync errors, and purge with opt-in drivers.",
      ],
      simulatedNotes: live
        ? ["Nothing is simulated in live mode. Counts come from collections you attach."]
        : [
            "Source health, documents, and the time simulator in demo mode.",
            "Test connection does not open a socket in demo mode.",
            "Demo profiles accept only fake ref_demo_* reference ids.",
          ],
      scaffold: [
        "Production auth is one admin bearer token, not full per-user RBAC.",
        "Live mode encrypts URIs on the gateway; the phone never stores the password after submit.",
      ],
    };
  }

  async discover(input: { uri: string; databaseName?: string }) {
    if (this.options.mode === "demo") {
      throw new HttpError(403, "live_only", "Database discovery is available in live mode. Set DEH_MODE=live.");
    }
    try {
      return await discoverDatabase(input.uri, {
        allowPrivateNetworks: this.options.allowPrivateNetworks,
        databaseName: input.databaseName,
      });
    } catch (error) {
      throw new HttpError(400, "discover_failed", error instanceof Error ? error.message : "Discovery failed.");
    }
  }

  async listSources() {
    const draft = this.store.read();
    return activeSources(draft).map((source) => this.publicSource(draft, source));
  }

  async listDetached() {
    const draft = this.store.read();
    return draft.sources.filter((source) => source.detachedAt).map((source) => this.publicSource(draft, source));
  }

  async createSource(
    input: {
      displayName: string;
      system?: string;
      environment?: EnvironmentName;
      databaseName: string;
      collectionName?: string;
      adapterKind?: AdapterKind;
      secretRef?: string;
      uri?: string;
      sync?: boolean;
    },
    actor: string,
  ) {
    const displayName = requireLabel(input.displayName, "Nickname");
    const system = requireLabel(input.system || input.displayName, "System");
    const environment = requireEnvironment(input.environment || "production");
    const databaseName = requireDatabaseName(input.databaseName);
    const collectionName = requireCollectionName(input.collectionName || COLLECTION_NAME);
    let adapterKind = input.adapterKind ?? "mongodb";

    let secretRef: string | null = null;
    let secretMasked = "ref_demo••••";
    let secretCiphertext: string | null = null;
    let statusBasis: ConnectionProfile["statusBasis"] = "simulated-scenario";
    let status: ConnectionProfile["status"] = "connected";

    if (this.options.mode === "demo") {
      if (input.uri) {
        throw new HttpError(400, "uri_rejected", "Demo mode does not accept a connection URI.");
      }
      if (adapterKind !== "mongodb" && adapterKind !== "postgres") {
        throw new HttpError(400, "invalid_adapter", "Adapter must be mongodb or postgres.");
      }
      try {
        secretRef = assertDemoSecretRef(input.secretRef ?? "");
      } catch (error) {
        throw new HttpError(400, "uri_rejected", error instanceof Error ? error.message : "Reference rejected.");
      }
      secretMasked = maskSecretRef(secretRef);
    } else {
      if (!input.uri) {
        throw new HttpError(400, "uri_required", "Submit a database URI. It is encrypted and stored only on the gateway.");
      }
      if (!this.options.masterKey) {
        throw new HttpError(500, "missing_master_key", "DEH_MASTER_KEY is not configured.");
      }
      try {
        adapterKind = input.adapterKind ?? adapterKindFromUri(input.uri);
      } catch (error) {
        throw new HttpError(400, "invalid_adapter", error instanceof Error ? error.message : "Invalid URI.");
      }
      const verdict = validateDatabaseTarget(input.uri, { allowPrivateNetworks: this.options.allowPrivateNetworks });
      if (!verdict.ok) throw new HttpError(400, "target_rejected", verdict.reason ?? "Target rejected.");
      if (this.options.verifyLiveConnection !== false) {
        try {
          await testLiveConnection({
            uri: input.uri,
            adapterKind,
            databaseName,
            collectionName,
          });
          status = "connected";
          statusBasis = "live";
        } catch (error) {
          throw new HttpError(400, "connect_failed", error instanceof Error ? error.message : "Could not connect.");
        }
      } else {
        status = "disconnected";
        statusBasis = "unchecked";
      }
      secretCiphertext = encryptString(input.uri, this.options.masterKey);
      secretMasked = maskDatabaseUri(input.uri);
      secretRef = null;
    }

    const now = this.clock.iso();
    const source: ConnectionProfile = {
      id: uid("src"),
      displayName,
      system,
      environment,
      databaseName,
      collectionName,
      adapterKind,
      secretRef,
      secretMasked,
      secretCiphertext,
      status,
      statusBasis,
      lastCheckedAt: status === "connected" ? now : null,
      staleAfterMinutes: 30,
      detachedAt: null,
      schemaMapId: adapterKind === "postgres" ? "postgres-backend-errors-v1" : "mongodb-backend-errors-v1",
      createdAt: now,
      updatedAt: now,
    };

    await this.store.transaction((draft) => {
      draft.sources.push(source);
      draft.collections[source.id] = draft.collections[source.id] ?? [];
      pushAudit(draft, {
        actor,
        action: "source.created",
        sourceId: source.id,
        detail: `Attached ${sourceAlias(source)} → ${databaseName}.${collectionName}.`,
      }, now);
    });

    if (this.options.mode !== "demo" && input.sync !== false && this.options.verifyLiveConnection !== false) {
      try {
        await this.syncSource(source.id, actor);
      } catch {
        // Source is saved; sync can be retried from refresh.
      }
    }
    const live = this.store.read().sources.find((item) => item.id === source.id) ?? source;
    return this.publicSource(this.store.read(), live);
  }

  async updateSource(
    id: string,
    patch: Partial<{ displayName: string; system: string; environment: EnvironmentName; databaseName: string }>,
    actor: string,
  ) {
    const now = this.clock.iso();
    await this.store.transaction((draft) => {
      const source = requireActiveSource(draft, id);
      if (patch.displayName !== undefined) source.displayName = requireLabel(patch.displayName, "Display name");
      if (patch.system !== undefined) source.system = requireLabel(patch.system, "System");
      if (patch.environment !== undefined) source.environment = requireEnvironment(patch.environment);
      if (patch.databaseName !== undefined) source.databaseName = requireDatabaseName(patch.databaseName);
      source.updatedAt = now;
      pushAudit(draft, {
        actor,
        action: "source.updated",
        sourceId: id,
        detail: "Updated the profile labels. Existing incidents keep the snapshot they were opened with.",
      }, now);
    });
    const source = this.store.read().sources.find((item) => item.id === id);
    if (!source) throw new HttpError(404, "not_found", "Source not found.");
    return this.publicSource(this.store.read(), source);
  }

  async detachSource(id: string, actor: string) {
    const now = this.clock.iso();
    const result = await this.store.transaction((draft) => {
      const source = requireActiveSource(draft, id);
      const before = (draft.collections[id] ?? []).length;
      source.detachedAt = now;
      source.updatedAt = now;
      let pending = 0;
      for (const incident of draft.incidents) {
        if (incident.sourceId === id && !incident.purgedAt && incident.status === "resolved") {
          incident.purgeBlockReason = "source_detached";
          pending += 1;
        }
      }
      draft.retries = draft.retries.filter((retry) => {
        const incident = draft.incidents.find((item) => item.id === retry.incidentId);
        return incident?.sourceId !== id;
      });
      const after = (draft.collections[id] ?? []).length;
      if (before !== after) {
        throw new HttpError(500, "detach_mutated_data", "Detach must not change source documents.");
      }
      pushAudit(draft, {
        actor,
        action: "source.detached",
        sourceId: id,
        detail: `Detached ${sourceAlias(source)}. ${source.databaseName}.${COLLECTION_NAME} was not dropped. ${pending} purge task(s) blocked.`,
      }, now);
      return {
        detached: true,
        databaseDropped: false,
        collectionDropped: false,
        documentsDeleted: 0,
        documentsRemaining: after,
        pendingPurgesBlocked: pending,
        databaseName: source.databaseName,
        collectionName: COLLECTION_NAME,
        displayName: sourceAlias(source),
        message: `Detached ${sourceAlias(source)}. ${source.databaseName}.${COLLECTION_NAME} was not dropped and no source documents were deleted. ${pending} scheduled purge(s) are now blocked.`,
      };
    });
    return result;
  }

  async testSource(id: string, actor: string) {
    const now = this.clock.iso();
    if (this.options.mode !== "demo") {
      const draft = this.store.read();
      const source = requireActiveSource(draft, id);
      if (!source.secretCiphertext || !this.options.masterKey) {
        throw new HttpError(400, "missing_secret", "This profile has no stored URI.");
      }
      const uri = decryptString(source.secretCiphertext, this.options.masterKey);
      try {
        const result = await testLiveConnection({
          uri,
          adapterKind: source.adapterKind,
          databaseName: source.databaseName,
          collectionName: source.collectionName,
        });
        await this.store.transaction((next) => {
          const live = requireActiveSource(next, id);
          live.status = "connected";
          live.statusBasis = "live";
          live.lastCheckedAt = now;
          live.updatedAt = now;
          pushAudit(next, { actor, action: "source.tested", sourceId: id, detail: result.message }, now);
        });
        return {
          simulated: false,
          networkCall: true,
          ok: true,
          status: "connected" as const,
          statusBasis: "live",
          message: result.message,
        };
      } catch (error) {
        const message = sanitizeErrorText(error instanceof Error ? error.message : "Connection failed.");
        await this.store.transaction((next) => {
          const live = requireActiveSource(next, id);
          live.status = "disconnected";
          live.statusBasis = "last-test";
          live.lastCheckedAt = now;
          live.updatedAt = now;
          pushAudit(next, { actor, action: "source.tested", sourceId: id, detail: message }, now);
        });
        return {
          simulated: false,
          networkCall: true,
          ok: false,
          status: "disconnected" as const,
          statusBasis: "last-test",
          message,
        };
      }
    }
    return this.store.transaction((draft) => {
      const source = requireActiveSource(draft, id);
      let message: string;
      if (source.status === "connected") {
        message = `Scenario status is Connected (${source.adapterKind}). No socket was opened and no URI was read.`;
      } else if (source.status === "stale") {
        message = `Scenario status is Stale (${source.adapterKind}). The last simulated check is older than the threshold. No socket was opened.`;
      } else {
        message = `Scenario status is Disconnected (${source.adapterKind}). The demo did not attempt a network connection.`;
      }
      pushAudit(draft, { actor, action: "source.tested", sourceId: id, detail: message }, now);
      return {
        simulated: true,
        networkCall: false,
        ok: source.status === "connected",
        status: source.status,
        statusBasis: source.statusBasis,
        message,
      };
    });
  }

  async syncSource(id: string, actor: string) {
    if (this.options.mode === "demo") {
      throw new HttpError(403, "live_only", "Sync is available in live mode.");
    }
    if (!this.options.masterKey) {
      throw new HttpError(500, "missing_master_key", "DEH_MASTER_KEY is not configured.");
    }
    const snapshot = this.store.read();
    const source = requireActiveSource(snapshot, id);
    if (!source.secretCiphertext) {
      throw new HttpError(400, "missing_secret", "This profile has no stored URI.");
    }
    const uri = decryptString(source.secretCiphertext, this.options.masterKey);
    let docs;
    try {
      docs = await fetchErrorDocuments({
        uri,
        adapterKind: source.adapterKind,
        databaseName: source.databaseName,
        collectionName: source.collectionName,
        limit: 500,
      });
    } catch (error) {
      await this.store.transaction((draft) => {
        const live = requireActiveSource(draft, id);
        live.status = "disconnected";
        live.statusBasis = "last-test";
        live.lastCheckedAt = this.clock.iso();
      });
      throw new HttpError(502, "sync_failed", error instanceof Error ? error.message : "Sync failed.");
    }

    const map = SCHEMA_MAPS[source.schemaMapId];
    if (!map) throw new HttpError(500, "schema_missing", "Schema map is missing for this source.");
    const now = this.clock.iso();
    let created = 0;
    let updated = 0;

    await this.store.transaction((draft) => {
      const live = requireActiveSource(draft, id);
      live.status = "connected";
      live.statusBasis = "live";
      live.lastCheckedAt = now;
      live.updatedAt = now;
      draft.collections[id] = [];

      for (const doc of docs) {
        const normalized = mapBackendError(doc.body, map, now);
        draft.collections[id].push({
          sourceDocumentId: doc.sourceDocumentId,
          sourceId: id,
          collectionName: live.collectionName,
          databaseName: live.databaseName,
          body: doc.body,
        });

        const open = draft.incidents.find(
          (incident) =>
            !incident.purgedAt &&
            incident.status === "open" &&
            incident.sourceId === id &&
            incident.fingerprint === normalized.fingerprint,
        );
        if (open) {
          if (!open.sourceDocumentIds.includes(doc.sourceDocumentId)) {
            open.sourceDocumentIds.push(doc.sourceDocumentId);
            updated += 1;
          }
          if (Date.parse(normalized.timestamp) >= Date.parse(open.lastSeenAt)) {
            open.lastSeenAt = normalized.timestamp;
            open.message = normalized.message;
            open.stackRedacted = normalized.stackRedacted;
            open.severity = normalized.severity;
            open.context = normalized.context;
          }
          continue;
        }

        const knownDoc = draft.incidents.find(
          (incident) =>
            !incident.purgedAt &&
            incident.sourceId === id &&
            incident.sourceDocumentIds.includes(doc.sourceDocumentId),
        );
        if (knownDoc) continue;

        draft.incidents.push({
          id: uid("inc"),
          sourceId: id,
          sourceDocumentIds: [doc.sourceDocumentId],
          fingerprint: normalized.fingerprint,
          severity: normalized.severity,
          message: normalized.message,
          stackRedacted: normalized.stackRedacted,
          context: normalized.context,
          firstSeenAt: normalized.timestamp,
          lastSeenAt: normalized.timestamp,
          status: "open",
          resolvedAt: null,
          resolvedBy: null,
          purgeDueAt: null,
          resolutionVersion: 0,
          notes: "",
          purgedAt: null,
          purgeBlockReason: null,
          snapshot: {
            displayName: live.displayName,
            system: live.system,
            environment: live.environment,
            databaseName: live.databaseName,
            collectionName: live.collectionName,
          },
        });
        created += 1;
      }

      pushAudit(draft, {
        actor,
        action: "source.tested",
        sourceId: id,
        detail: `Synced ${docs.length} document(s) from ${live.databaseName}.${live.collectionName}. Created ${created}, updated ${updated}.`,
      }, now);
    });

    return { ok: true, fetched: docs.length, created, updated, now };
  }

  async syncAll(actor: string) {
    const sources = activeSources(this.store.read());
    const results = [];
    for (const source of sources) {
      if (!source.secretCiphertext) continue;
      try {
        results.push({ sourceId: source.id, ...(await this.syncSource(source.id, actor)) });
      } catch (error) {
        results.push({
          sourceId: source.id,
          ok: false,
          error: error instanceof HttpError ? error.message : "Sync failed.",
        });
      }
    }
    return { now: this.clock.iso(), results };
  }

  async refreshHealth(actor: string) {
    if (this.options.mode !== "demo") {
      const synced = await this.syncAll(actor);
      return { now: synced.now, simulated: false, synced };
    }
    const now = this.clock.iso();
    await this.store.transaction((draft) => {
      for (const source of activeSources(draft)) {
        if (source.status === "connected" && source.statusBasis === "simulated-scenario") {
          source.lastCheckedAt = now;
        }
      }
      pushAudit(draft, {
        actor,
        action: "source.tested",
        detail: "Refresh re-read scenario health. Disconnected and stale sources were not marked connected.",
      }, now);
    });
    return { now, simulated: this.options.mode === "demo" };
  }

  async listIncidents(query: {
    sourceId?: string;
    status?: "open" | "resolved" | "all";
    severity?: Severity | "all";
    q?: string;
    sort?: "recent" | "severity" | "occurrences" | "purge";
    purge?: "pending" | "blocked" | "any";
  }) {
    const draft = this.store.read();
    const q = query.q?.trim().toLowerCase() ?? "";
    let rows = draft.incidents.filter((incident) => !incident.purgedAt);
    if (query.sourceId && query.sourceId !== "all") {
      rows = rows.filter((incident) => incident.sourceId === query.sourceId);
    }
    if (query.status && query.status !== "all") rows = rows.filter((incident) => incident.status === query.status);
    if (query.severity && query.severity !== "all") rows = rows.filter((incident) => incident.severity === query.severity);
    if (query.purge === "pending") {
      rows = rows.filter((incident) => incident.status === "resolved" && incident.purgeDueAt && !incident.purgeBlockReason);
    }
    if (query.purge === "blocked") rows = rows.filter((incident) => Boolean(incident.purgeBlockReason));
    if (q) {
      rows = rows.filter((incident) => {
        const hay = [
          incident.message,
          incident.fingerprint,
          incident.snapshot.displayName,
          incident.snapshot.system,
          incident.snapshot.environment,
          incident.snapshot.databaseName,
          incident.severity,
          incident.status,
        ].join(" ").toLowerCase();
        return hay.includes(q);
      });
    }
    const sort = query.sort ?? "recent";
    rows.sort((a, b) => compareIncidents(a, b, sort));
    return rows.map((incident) => this.summary(draft, incident));
  }

  async getIncident(id: string) {
    const draft = this.store.read();
    const incident = draft.incidents.find((item) => item.id === id);
    if (!incident || incident.purgedAt) {
      const receipt = draft.receipts.find((item) => item.incidentId === id);
      if (receipt) {
        throw new HttpError(410, "purged", "This error was deleted from its source collection. The reward ledger entry remains.");
      }
      throw new HttpError(404, "not_found", "Incident not found.");
    }
    return this.detail(draft, incident);
  }

  async resolveIncident(
    id: string,
    actor: string,
    claim?: { expectedVersion?: number; sourceId?: string },
  ) {
    const now = this.clock.iso();
    return this.store.transaction(async (draft) => {
      await Promise.resolve();
      const incident = requireLiveIncident(draft, id);
      if (claim?.sourceId && claim.sourceId !== incident.sourceId) {
        throw new HttpError(
          409,
          "source_mismatch",
          "This incident stays bound to its original source. Changing the workspace selector cannot move the deletion.",
        );
      }
      if (claim?.expectedVersion !== undefined && claim.expectedVersion !== incident.resolutionVersion) {
        throw new HttpError(409, "version_conflict", "The incident changed. Refresh and try again.");
      }
      if (incident.status === "resolved") {
        pushAudit(draft, {
          actor,
          action: "incident.resolve_duplicate",
          incidentId: id,
          sourceId: incident.sourceId,
          detail: "Duplicate resolve ignored. The purge time and reward ledger were left unchanged.",
        }, now);
        return {
          idempotent: true,
          rewardCreated: false,
          codeChanged: false as const,
          incident: this.detail(draft, incident),
        };
      }
      incident.status = "resolved";
      incident.resolvedAt = now;
      incident.resolvedBy = actor;
      incident.purgeDueAt = computePurgeDueAt(now);
      incident.purgeBlockReason = null;
      incident.resolutionVersion += 1;
      const rewardCreated = awardOnce(draft, incident, actor, now);
      draft.retries = draft.retries.filter((retry) => retry.incidentId !== id);
      pushAudit(draft, {
        actor,
        action: "incident.resolved",
        incidentId: id,
        sourceId: incident.sourceId,
        detail: `Acknowledged. Deletion from ${incident.snapshot.databaseName}.${COLLECTION_NAME} is due at ${incident.purgeDueAt}. No application code was changed.`,
      }, now);
      return {
        idempotent: false,
        rewardCreated,
        codeChanged: false as const,
        incident: this.detail(draft, incident),
      };
    });
  }

  async reopenIncident(id: string, actor: string, claim?: { expectedVersion?: number; sourceId?: string }) {
    const now = this.clock.iso();
    return this.store.transaction(async (draft) => {
      const incident = requireLiveIncident(draft, id);
      if (claim?.sourceId && claim.sourceId !== incident.sourceId) {
        throw new HttpError(409, "source_mismatch", "Reopen stays on the incident's original source.");
      }
      if (claim?.expectedVersion !== undefined && claim.expectedVersion !== incident.resolutionVersion) {
        throw new HttpError(409, "version_conflict", "The incident changed. Refresh and try again.");
      }
      if (incident.status === "open") {
        return { idempotent: true, incident: this.detail(draft, incident) };
      }
      incident.status = "open";
      incident.resolvedAt = null;
      incident.purgeDueAt = null;
      incident.resolvedBy = null;
      incident.purgeBlockReason = null;
      incident.resolutionVersion += 1;
      draft.retries = draft.retries.filter((retry) => retry.incidentId !== id);
      draft.deadletters = draft.deadletters.filter((item) => item.incidentId !== id);
      pushAudit(draft, {
        actor,
        action: "incident.reopened",
        incidentId: id,
        sourceId: incident.sourceId,
        detail: "Reopened. The scheduled source deletion was cancelled. The reward ledger was not increased or removed.",
      }, now);
      return { idempotent: false, incident: this.detail(draft, incident) };
    });
  }

  async setNotes(id: string, notes: string, actor: string) {
    const clean = sanitizeErrorText(notes).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").slice(0, 800);
    const now = this.clock.iso();
    return this.store.transaction((draft) => {
      const incident = requireLiveIncident(draft, id);
      incident.notes = clean;
      pushAudit(draft, {
        actor,
        action: "incident.note",
        incidentId: id,
        sourceId: incident.sourceId,
        detail: "Updated the operator note.",
      }, now);
      return this.detail(draft, incident);
    });
  }

  async recordOccurrence(input: {
    sourceId: string;
    message: string;
    severity: Severity;
    stack: string;
    context?: Record<string, unknown>;
    fingerprint?: string;
    observedAt?: string;
  }, actor: string) {
    if (this.options.mode !== "demo") {
      throw new HttpError(403, "demo_only", "Synthetic recurrence is available only in demo mode.");
    }
    const now = input.observedAt ?? this.clock.iso();
    return this.store.transaction((draft) => {
      const source = requireActiveSource(draft, input.sourceId);
      const message = sanitizeErrorText(input.message).slice(0, 400);
      const stackRedacted = sanitizeErrorText(input.stack).slice(0, 4000);
      const fingerprint = input.fingerprint && /^[a-z0-9_-]{6,64}$/i.test(input.fingerprint)
        ? input.fingerprint.toLowerCase()
        : fingerprintFrom(message, stackRedacted);
      const sourceDocumentId = uid("doc");
      insertDemoDocument(draft, {
        sourceDocumentId,
        sourceId: source.id,
        collectionName: COLLECTION_NAME,
        databaseName: source.databaseName,
        body: {
          _id: sourceDocumentId,
          level: input.severity,
          msg: message,
          ts: now,
          fingerprint,
          synthetic: true,
        },
      });
      const open = draft.incidents.find(
        (incident) =>
          !incident.purgedAt &&
          incident.status === "open" &&
          incident.sourceId === source.id &&
          incident.fingerprint === fingerprint,
      );
      if (open) {
        open.sourceDocumentIds.push(sourceDocumentId);
        open.lastSeenAt = now;
        pushAudit(draft, {
          actor,
          action: "incident.recurrence",
          incidentId: open.id,
          sourceId: source.id,
          detail: "Grouped into the open incident with the same fingerprint. Simulated. No socket was opened.",
        }, now);
        return { kind: "increment" as const, incident: this.detail(draft, open) };
      }
      const incident: Incident = {
        id: uid("inc"),
        sourceId: source.id,
        sourceDocumentIds: [sourceDocumentId],
        fingerprint,
        severity: input.severity,
        message,
        stackRedacted,
        context: safeContext(input.context ?? {}),
        firstSeenAt: now,
        lastSeenAt: now,
        status: "open",
        resolvedAt: null,
        resolvedBy: null,
        purgeDueAt: null,
        resolutionVersion: 0,
        notes: "",
        purgedAt: null,
        purgeBlockReason: null,
        snapshot: {
          displayName: source.displayName,
          system: source.system,
          environment: source.environment,
          databaseName: source.databaseName,
          collectionName: COLLECTION_NAME,
        },
      };
      draft.incidents.push(incident);
      pushAudit(draft, {
        actor,
        action: "incident.recurrence",
        incidentId: incident.id,
        sourceId: source.id,
        detail: "Opened a new incident. A resolved copy with this fingerprint keeps its own purge schedule.",
      }, now);
      return { kind: "created" as const, incident: this.detail(draft, incident) };
    });
  }

  async dashboard(sourceId?: string) {
    const draft = this.store.read();
    const nowMs = this.clock.nowMs();
    const scoped = draft.incidents.filter((incident) => {
      if (incident.purgedAt) return false;
      if (sourceId && sourceId !== "all" && incident.sourceId !== sourceId) return false;
      return true;
    });
    const open = scoped.filter((incident) => incident.status === "open");
    const resolved = scoped.filter((incident) => incident.status === "resolved");
    const severityOpen = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const incident of open) severityOpen[incident.severity] += 1;
    const purgePending = resolved.filter((incident) => incident.purgeDueAt && !incident.purgeBlockReason);
    const purgeDueNow = purgePending.filter((incident) => Date.parse(incident.purgeDueAt as string) <= nowMs);
    const sources = sourceId && sourceId !== "all"
      ? activeSources(draft).filter((source) => source.id === sourceId)
      : activeSources(draft);
    const trend = buildTrend(scoped, nowMs);
    const recent = [...scoped].sort((a, b) => compareIncidents(a, b, "recent")).slice(0, 5).map((incident) => this.summary(draft, incident));
    return {
      dataOrigin: this.options.mode === "demo" ? "illustrative-demo-seed" : "gateway",
      generatedAt: new Date(nowMs).toISOString(),
      sourceId: sourceId && sourceId !== "all" ? sourceId : "all",
      counts: {
        open: open.length,
        resolved: resolved.length,
        criticalOpen: severityOpen.critical,
        purgePending: purgePending.length,
        purgeDueNow: purgeDueNow.length,
        purgeBlocked: resolved.filter((incident) => incident.purgeBlockReason).length,
      },
      severityOpen,
      trend,
      recent,
      freshness: {
        label: this.options.mode === "demo" ? "Simulated scenario health" : "Gateway cache",
        connected: sources.filter((source) => source.status === "connected").length,
        stale: sources.filter((source) => source.status === "stale").length,
        disconnected: sources.filter((source) => source.status === "disconnected").length,
        oldestCheckAt: oldest(sources.map((source) => source.lastCheckedAt)),
      },
    };
  }

  async rewards() {
    const draft = this.store.read();
    const nowMs = this.clock.nowMs();
    const solved = draft.ledger.length;
    const points = draft.ledger.reduce((sum, entry) => sum + entry.points, 0);
    const criticalSolved = draft.ledger.filter((entry) => entry.severity === "critical").length;
    const streak = computeStreak(draft.ledger, nowMs);
    const stats = { solved, criticalSolved, streak };
    const purged = new Set(draft.receipts.map((receipt) => receipt.incidentId));
    return {
      dataOrigin: this.options.mode === "demo" ? "illustrative-demo-seed" : "gateway",
      illustrative: true,
      errorsSolved: solved,
      points,
      streak,
      criticalSolved,
      rules: REWARD_RULES,
      badges: BADGE_DEFS.map((badge) => ({
        ...badge,
        earned: badgeEarned(badge.id, stats),
      })),
      ledger: [...draft.ledger]
        .sort((a, b) => Date.parse(b.awardedAt) - Date.parse(a.awardedAt))
        .map((entry) => ({
          incidentId: entry.incidentId,
          sourceId: entry.sourceId,
          fingerprint: entry.fingerprint,
          severity: entry.severity,
          points: entry.points,
          awardedAt: entry.awardedAt,
          purged: purged.has(entry.incidentId),
          actor: entry.actor,
        })),
    };
  }

  async advanceMinutes(minutes: number, actor: string) {
    if (this.options.mode !== "demo") {
      throw new HttpError(403, "demo_only", "The time simulator exists only in demo mode.");
    }
    if (!Number.isFinite(minutes) || minutes <= 0 || minutes > 14 * 24 * 60) {
      throw new HttpError(400, "invalid_advance", "Advance between 1 minute and 14 days.");
    }
    const whole = Math.round(minutes);
    await this.store.transaction((draft) => {
      draft.clockOffsetMs += whole * 60 * 1000;
      pushAudit(draft, {
        actor,
        action: "demo.clock",
        detail: `Advanced the demo clock by ${whole} minutes. The device clock was not changed.`,
      }, new Date(Date.now() + draft.clockOffsetMs).toISOString());
    });
    return {
      now: this.clock.iso(),
      simulated: true,
      deviceClockUnchanged: true,
      minutes: whole,
    };
  }

  async resetDemo(actor: string) {
    if (this.options.mode !== "demo") {
      throw new HttpError(403, "demo_only", "Reset is available only in demo mode.");
    }
    const state = this.store.read();
    const wall = this.clock.nowMs() - state.clockOffsetMs;
    const seeded = buildSeed(wall);
    await this.store.transaction((draft) => {
      draft.clockOffsetMs = 0;
      draft.sources = seeded.sources;
      draft.incidents = seeded.incidents;
      draft.ledger = seeded.ledger;
      draft.receipts = seeded.receipts;
      draft.deadletters = seeded.deadletters;
      draft.retries = seeded.retries;
      draft.audit = seeded.audit;
      draft.collections = seeded.collections;
      pushAudit(draft, {
        actor,
        action: "demo.reset",
        detail: "Restored the illustrative seed. No external database was contacted.",
      }, new Date(wall).toISOString());
    });
    return { ok: true, now: this.clock.iso(), simulated: true };
  }

  async runRetention(actor = "retention-worker", hooks?: RetentionHooks) {
    const nowMs = this.clock.nowMs();
    const now = new Date(nowMs).toISOString();
    return this.store.transaction(async (draft) => {
      const candidates = selectPurgeCandidates(draft.incidents, nowMs).sort(
        (a, b) => Date.parse(a.purgeDueAt as string) - Date.parse(b.purgeDueAt as string),
      );
      const batch = candidates.slice(0, RETENTION_BATCH_LIMIT);
      const report = {
        considered: batch.length,
        waitingBeyondBatch: candidates.length - batch.length,
        purged: [] as string[],
        skipped: [] as { incidentId: string; reason: string }[],
        retried: [] as { incidentId: string; reason: string; attempts: number }[],
        deadlettered: [] as { incidentId: string; reason: string }[],
        ranAt: now,
        independentOfMobile: true,
      };

      for (const candidate of batch) {
        const incident = draft.incidents.find((item) => item.id === candidate.id);
        if (
          !incident ||
          !isPurgeEligible(incident, nowMs) ||
          incident.resolutionVersion !== candidate.resolutionVersion ||
          incident.sourceId !== candidate.sourceId
        ) {
          report.skipped.push({ incidentId: candidate.id, reason: "state_changed" });
          continue;
        }
        const source = draft.sources.find((item) => item.id === incident.sourceId);
        if (!source || source.detachedAt) {
          incident.purgeBlockReason = "source_detached";
          addDeadletter(draft, incident, "source_detached", now, 1);
          report.deadlettered.push({ incidentId: incident.id, reason: "source_detached" });
          continue;
        }
        const retry = draft.retries.find((item) => item.incidentId === incident.id);
        if (retry && Date.parse(retry.nextAttemptAt) > nowMs) {
          report.skipped.push({ incidentId: incident.id, reason: "waiting_backoff" });
          continue;
        }
        if (source.adapterKind !== "mongodb" && source.adapterKind !== "postgres") {
          failAttempt(draft, incident, "adapter_unavailable", nowMs, report);
          continue;
        }
        if (source.status === "disconnected") {
          failAttempt(draft, incident, "source_disconnected", nowMs, report);
          continue;
        }
        let externalAborted = false;
        if (this.options.mode !== "demo") {
          const adapterOn =
            source.adapterKind === "mongodb" ? this.options.mongodbEnabled : this.options.postgresEnabled;
          if (!adapterOn || !this.options.masterKey || !source.secretCiphertext) {
            failAttempt(draft, incident, "adapter_disabled", nowMs, report);
            continue;
          }
          try {
            const uri = decryptString(source.secretCiphertext, this.options.masterKey);
            const version = incident.resolutionVersion;
            const boundSource = incident.sourceId;
            for (const docId of [...incident.sourceDocumentIds]) {
              const live = draft.incidents.find((item) => item.id === incident.id);
              if (!live || !isPurgeEligible(live, nowMs) || live.resolutionVersion !== version || live.sourceId !== boundSource) {
                externalAborted = true;
                break;
              }
              const args = {
                uri,
                databaseName: live.snapshot.databaseName,
                sourceDocumentId: docId,
                adapterKind: source.adapterKind,
              };
              const deleteArgs = {
                ...args,
                collectionName: live.snapshot.collectionName || source.collectionName,
              };
              if (this.options.deleteExternal) {
                await this.options.deleteExternal(deleteArgs);
              } else if (source.adapterKind === "postgres") {
                await deletePostgresDocument(deleteArgs);
              } else {
                await deleteMongoDocument(deleteArgs);
              }
            }
          } catch (error) {
            const safe = sanitizeErrorText(error instanceof Error ? error.message : "delete failed");
            failAttempt(draft, incident, safe, nowMs, report);
            continue;
          }
          if (externalAborted) {
            report.skipped.push({ incidentId: incident.id, reason: "recheck_failed" });
            continue;
          }
        }

        const version = incident.resolutionVersion;
        const sourceId = incident.sourceId;
        let deleted = 0;
        let missing = 0;
        let aborted = false;
        if (this.options.mode === "demo") {
          for (const docId of [...incident.sourceDocumentIds]) {
            hooks?.beforeEachDelete?.(draft, incident.id, docId);
            const live = draft.incidents.find((item) => item.id === incident.id);
            if (!live || !isPurgeEligible(live, nowMs) || live.resolutionVersion !== version || live.sourceId !== sourceId) {
              aborted = true;
              break;
            }
            const outcome = deleteDemoDocument(draft, {
              sourceId: live.sourceId,
              databaseName: live.snapshot.databaseName,
              collectionName: live.snapshot.collectionName || COLLECTION_NAME,
              sourceDocumentId: docId,
            });
            if (outcome === "deleted") deleted += 1;
            else missing += 1;
          }
        }
        if (aborted) {
          report.skipped.push({ incidentId: incident.id, reason: "recheck_failed" });
          continue;
        }
        const documentCount = this.options.mode === "demo" ? deleted + missing : incident.sourceDocumentIds.length;
        finishPurge(draft, incident, now, actor, documentCount);
        report.purged.push(incident.id);
      }
      return report;
    });
  }

  collectionLength(sourceId: string): number {
    return (this.store.read().collections[sourceId] ?? []).length;
  }

  private publicSource(draft: StoreData, source: ConnectionProfile) {
    const incidents = draft.incidents.filter((incident) => incident.sourceId === source.id && !incident.purgedAt);
    return {
      id: source.id,
      displayName: source.displayName,
      alias: sourceAlias(source),
      system: source.system,
      environment: source.environment,
      databaseName: source.databaseName,
      collectionName: source.collectionName,
      adapterKind: source.adapterKind,
      secretMasked: source.secretMasked,
      hasSecret: Boolean(source.secretRef || source.secretCiphertext),
      status: source.status,
      statusBasis: source.statusBasis,
      lastCheckedAt: source.lastCheckedAt,
      staleAfterMinutes: source.staleAfterMinutes,
      detachedAt: source.detachedAt,
      schemaMapId: source.schemaMapId,
      openCount: incidents.filter((incident) => incident.status === "open").length,
      resolvedCount: incidents.filter((incident) => incident.status === "resolved").length,
    };
  }

  private summary(draft: StoreData, incident: Incident) {
    return {
      id: incident.id,
      sourceId: incident.sourceId,
      fingerprint: incident.fingerprint,
      severity: incident.severity,
      message: incident.message,
      occurrences: incident.sourceDocumentIds.length,
      firstSeenAt: incident.firstSeenAt,
      lastSeenAt: incident.lastSeenAt,
      status: incident.status,
      resolvedAt: incident.resolvedAt,
      purgeDueAt: incident.purgeDueAt,
      purgeBlockReason: incident.purgeBlockReason,
      resolutionVersion: incident.resolutionVersion,
      snapshot: incident.snapshot,
      rewardAwarded: draft.ledger.some((entry) => entry.incidentId === incident.id),
      alias: sourceAlias(incident.snapshot),
    };
  }

  private detail(draft: StoreData, incident: Incident) {
    const audits = draft.audit.filter((event) => event.incidentId === incident.id).slice(-8).reverse();
    return {
      ...this.summary(draft, incident),
      stackRedacted: incident.stackRedacted,
      context: incident.context,
      notes: incident.notes,
      resolvedBy: incident.resolvedBy,
      codeChanged: false as const,
      retentionBasis: "resolvedAt+48h" as const,
      documentCount: incident.sourceDocumentIds.length,
      audit: audits.map((event) => ({ at: event.at, actor: event.actor, action: event.action, detail: event.detail })),
    };
  }
}

function awardOnce(draft: StoreData, incident: Incident, actor: string, now: string): boolean {
  if (draft.ledger.some((entry) => entry.incidentId === incident.id)) return false;
  draft.ledger.push({
    incidentId: incident.id,
    sourceId: incident.sourceId,
    fingerprint: incident.fingerprint,
    severity: incident.severity,
    points: POINTS[incident.severity],
    awardedAt: now,
    actor,
  });
  return true;
}

function addDeadletter(draft: StoreData, incident: Incident, reason: string, at: string, attempts: number): void {
  draft.deadletters.push({
    id: uid("dead"),
    incidentId: incident.id,
    sourceId: incident.sourceId,
    reason: sanitizeErrorText(reason).slice(0, 180),
    attempts,
    at,
  });
  pushAudit(draft, {
    actor: "retention-worker",
    action: "retention.deadletter",
    incidentId: incident.id,
    sourceId: incident.sourceId,
    detail: `Purge parked: ${reason}. Source documents were not deleted.`,
  }, at);
}

function failAttempt(
  draft: StoreData,
  incident: Incident,
  reason: string,
  nowMs: number,
  report: {
    retried: { incidentId: string; reason: string; attempts: number }[];
    deadlettered: { incidentId: string; reason: string }[];
  },
): void {
  const safe = sanitizeErrorText(reason).slice(0, 180);
  const existing = draft.retries.find((item) => item.incidentId === incident.id);
  const attempts = (existing?.attempts ?? 0) + 1;
  if (attempts >= RETENTION_MAX_ATTEMPTS) {
    incident.purgeBlockReason = safe;
    addDeadletter(draft, incident, safe, new Date(nowMs).toISOString(), attempts);
    draft.retries = draft.retries.filter((item) => item.incidentId !== incident.id);
    report.deadlettered.push({ incidentId: incident.id, reason: safe });
    return;
  }
  const delay = Math.min(60_000 * 2 ** (attempts - 1), 60 * 60 * 1000);
  const nextAttemptAt = new Date(nowMs + delay).toISOString();
  if (existing) {
    existing.attempts = attempts;
    existing.nextAttemptAt = nextAttemptAt;
    existing.lastError = safe;
  } else {
    draft.retries.push({ incidentId: incident.id, attempts, nextAttemptAt, lastError: safe });
  }
  report.retried.push({ incidentId: incident.id, reason: safe, attempts });
}

function finishPurge(draft: StoreData, incident: Incident, now: string, actor: string, documentCount: number): void {
  draft.receipts.push({
    id: uid("rcpt"),
    incidentId: incident.id,
    sourceId: incident.sourceId,
    fingerprint: incident.fingerprint,
    severity: incident.severity,
    documentCount,
    resolvedAt: incident.resolvedAt as string,
    purgeDueAt: incident.purgeDueAt as string,
    purgedAt: now,
    resolutionVersion: incident.resolutionVersion,
  });
  draft.retries = draft.retries.filter((item) => item.incidentId !== incident.id);
  pushAudit(draft, {
    actor,
    action: "incident.purged",
    incidentId: incident.id,
    sourceId: incident.sourceId,
    detail: `Deleted ${documentCount} document(s) from ${incident.snapshot.databaseName}.${COLLECTION_NAME}. Payload was not archived.`,
  }, now);
  const index = draft.incidents.findIndex((item) => item.id === incident.id);
  if (index >= 0) draft.incidents.splice(index, 1);
}

function requireLiveIncident(draft: StoreData, id: string): Incident {
  const incident = draft.incidents.find((item) => item.id === id);
  if (!incident) {
    if (draft.receipts.some((receipt) => receipt.incidentId === id)) {
      throw new HttpError(410, "purged", "This error was deleted from its source collection. The reward ledger entry remains.");
    }
    throw new HttpError(404, "not_found", "Incident not found.");
  }
  return incident;
}

function requireActiveSource(draft: StoreData, id: string): ConnectionProfile {
  const source = draft.sources.find((item) => item.id === id);
  if (!source || source.detachedAt) throw new HttpError(404, "not_found", "Source not found.");
  return source;
}

function requireLabel(value: string, label: string): string {
  const clean = value.trim().replace(/\s+/g, " ");
  if (clean.length < 2 || clean.length > 48) {
    throw new HttpError(400, "invalid_label", `${label} must be 2–48 characters.`);
  }
  return sanitizeErrorText(clean);
}

function requireDatabaseName(value: string): string {
  const clean = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,62}$/.test(clean)) {
    throw new HttpError(400, "invalid_database", "Database name must start with a letter and use letters, numbers, _ or -.");
  }
  return clean;
}

function requireCollectionName(value: string): string {
  const clean = value.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,120}$/.test(clean)) {
    throw new HttpError(
      400,
      "invalid_collection",
      "Collection/table name must start with a letter or underscore and use letters, numbers, or underscores.",
    );
  }
  return clean;
}

function requireEnvironment(value: string): EnvironmentName {
  if (value !== "production" && value !== "staging" && value !== "development") {
    throw new HttpError(400, "invalid_environment", "Environment must be production, staging, or development.");
  }
  return value;
}

function compareIncidents(a: Incident, b: Incident, sort: "recent" | "severity" | "occurrences" | "purge"): number {
  if (sort === "severity") {
    const rank = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (rank !== 0) return rank;
  }
  if (sort === "occurrences") {
    const diff = b.sourceDocumentIds.length - a.sourceDocumentIds.length;
    if (diff !== 0) return diff;
  }
  if (sort === "purge") {
    const ad = a.purgeDueAt ? Date.parse(a.purgeDueAt) : Number.POSITIVE_INFINITY;
    const bd = b.purgeDueAt ? Date.parse(b.purgeDueAt) : Number.POSITIVE_INFINITY;
    if (ad !== bd) return ad - bd;
  }
  return Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt);
}

function buildTrend(incidents: Incident[], nowMs: number): { day: string; count: number }[] {
  const startToday = Date.parse(`${utcDay(nowMs)}T00:00:00.000Z`);
  const days: { day: string; count: number }[] = [];
  for (let i = 6; i >= 0; i -= 1) {
    const day = utcDay(startToday - i * 24 * 60 * 60 * 1000);
    days.push({
      day,
      count: incidents.filter((incident) => utcDay(incident.firstSeenAt) === day).length,
    });
  }
  return days;
}

function oldest(values: (string | null)[]): string | null {
  const parsed = values.filter((value): value is string => Boolean(value)).map((value) => Date.parse(value));
  if (parsed.length === 0) return null;
  return new Date(Math.min(...parsed)).toISOString();
}

export function assertReceiptHasNoPayload(receipt: StoreData["receipts"][number]): void {
  const forbidden = ["message", "stack", "stackRedacted", "context", "notes", "body", "secret", "uri"];
  for (const key of forbidden) {
    if (key in receipt) throw new Error(`Receipt must not contain ${key}.`);
  }
}

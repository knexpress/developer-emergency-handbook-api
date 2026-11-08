import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { randomBytes } from "node:crypto";
import { buildSeed } from "../demo/seed.js";
import { decryptString } from "../domain/security.js";
import type { Clock, StoreData } from "../domain/types.js";
import { createApp } from "../http/app.js";
import { FileStore, makeClock, MemoryStore, type Store } from "../store/store.js";
import { HandbookService, HttpError } from "./handbook.js";

const WALL = Date.parse("2026-06-01T12:00:00.000Z");
const MINUTE = 60 * 1000;

function demoService(store: Store = new MemoryStore(buildSeed(WALL)), wall = WALL) {
  const clock: Clock = makeClock(store, () => wall);
  const externalCalls: { databaseName: string; sourceDocumentId: string; uri: string }[] = [];
  const service = new HandbookService(store, clock, {
    mode: "demo",
    retentionIntervalMs: 60_000,
    allowPrivateNetworks: false,
    mongodbEnabled: false,
    postgresEnabled: false,
    deleteExternal: async (args) => {
      externalCalls.push(args);
      return "deleted";
    },
  });
  return { store, service, externalCalls };
}

describe("demo seed", () => {
  it("loads illustrative systems and a separate reward ledger", async () => {
    const { service } = demoService();
    const sources = await service.listSources();
    assert.equal(sources.length, 5);
    assert.ok(sources.every((source) => source.collectionName === "Backend_errors"));
    assert.equal(sources.find((source) => source.id === "src_catalog_prod")?.adapterKind, "postgres");
    assert.ok(sources.filter((source) => source.adapterKind === "mongodb").length >= 1);
    assert.equal(JSON.stringify(sources).includes("mongodb://"), false);
    assert.equal(JSON.stringify(sources).includes("ref_demo_ledger_prod"), false);
    const rewards = await service.rewards();
    assert.equal(rewards.errorsSolved, 6);
    assert.equal(rewards.points, 145);
    assert.equal(rewards.streak, 3);
    assert.equal(rewards.badges.find((badge) => badge.id === "steady-hand")?.earned, true);
    assert.equal(rewards.badges.find((badge) => badge.id === "night-watch")?.earned, false);
    const health = Object.fromEntries(sources.map((source) => [source.id, source.status]));
    assert.deepEqual(health, {
      src_ledger_prod: "connected",
      src_ledger_stage: "connected",
      src_dispatch_prod: "stale",
      src_identity_prod: "disconnected",
      src_catalog_prod: "connected",
    });
  });
});

describe("resolve, reopen, and rewards", () => {
  it("awards once across duplicate taps, races, and a later reopen", async () => {
    const { store, service } = demoService();
    const before = store.read().ledger.length;
    const [first, second] = await Promise.all([
      service.resolveIncident("inc_capture", "operator-a"),
      service.resolveIncident("inc_capture", "operator-b"),
    ]);
    assert.equal([first, second].filter((result) => result.rewardCreated).length, 1);
    assert.equal(store.read().ledger.filter((entry) => entry.incidentId === "inc_capture").length, 1);
    assert.equal(store.read().ledger.length, before + 1);
    const due = store.read().incidents.find((incident) => incident.id === "inc_capture")?.purgeDueAt;
    await service.advanceMinutes(90, "demo-operator");
    const duplicate = await service.resolveIncident("inc_capture", "demo-operator");
    assert.equal(duplicate.idempotent, true);
    assert.equal(duplicate.rewardCreated, false);
    assert.equal(duplicate.incident.purgeDueAt, due);
    assert.equal(duplicate.codeChanged, false);

    await service.reopenIncident("inc_capture", "demo-operator");
    const reopened = store.read().incidents.find((incident) => incident.id === "inc_capture");
    assert.equal(reopened?.status, "open");
    assert.equal(reopened?.purgeDueAt, null);
    const resolvedAgain = await service.resolveIncident("inc_capture", "demo-operator");
    assert.equal(resolvedAgain.rewardCreated, false);
    assert.notEqual(resolvedAgain.incident.purgeDueAt, due);
    assert.equal(store.read().ledger.filter((entry) => entry.incidentId === "inc_capture").length, 1);
    const rewards = await service.rewards();
    assert.equal(rewards.errorsSolved, before + 1);
  });

  it("refuses to move a deletion onto the currently selected source", async () => {
    const { service } = demoService();
    await assert.rejects(
      () => service.resolveIncident("inc_capture", "demo-operator", { sourceId: "src_catalog_prod" }),
      (error: unknown) => error instanceof HttpError && error.code === "source_mismatch",
    );
  });
});

describe("retention worker", () => {
  it("keeps a document at 47h 59m and deletes it at 48h from the original source only", async () => {
    const { store, service, externalCalls } = demoService();
    await store.transaction((draft) => {
      draft.collections.src_ledger_stage?.push({
        sourceDocumentId: "inc_capture_doc_1",
        sourceId: "src_ledger_stage",
        collectionName: "Backend_errors",
        databaseName: "payments_ledger",
        body: { _id: "inc_capture_doc_1", marker: "other-source" },
      });
    });
    await service.resolveIncident("inc_capture", "demo-operator");
    await service.advanceMinutes(47 * 60 + 59, "demo-operator");
    const early = await service.runRetention();
    assert.equal(early.purged.includes("inc_capture"), false);
    assert.equal(countDocs(store.read(), "src_ledger_prod", "inc_capture"), 14);

    await service.advanceMinutes(1, "demo-operator");
    const due = await service.runRetention();
    assert.equal(due.purged.includes("inc_capture"), true);
    assert.equal(countDocs(store.read(), "src_ledger_prod", "inc_capture"), 0);
    assert.equal(
      store.read().collections.src_ledger_stage?.some((doc) => doc.body.marker === "other-source"),
      true,
    );
    assert.equal(externalCalls.length, 0);
    const receipt = store.read().receipts.find((item) => item.incidentId === "inc_capture");
    assert.ok(receipt);
    assert.equal("message" in receipt, false);
    assert.equal("stackRedacted" in receipt, false);
    assert.equal(JSON.stringify(store.read()).includes("Charge capture failed after authorization hold"), false);
    const rewards = await service.rewards();
    assert.equal(rewards.ledger.some((entry) => entry.incidentId === "inc_capture" && entry.purged), true);
    assert.equal(rewards.errorsSolved, 7);
  });

  it("never deletes an unresolved error and cancels purge on reopen", async () => {
    const { store, service } = demoService();
    await service.advanceMinutes(14 * 24 * 60, "demo-operator");
    await service.runRetention();
    assert.equal(countDocs(store.read(), "src_ledger_prod", "inc_replay"), 1);
    assert.equal(store.read().incidents.some((incident) => incident.id === "inc_replay" && incident.status === "open"), true);

    const { store: store2, service: service2 } = demoService();
    await service2.resolveIncident("inc_route", "demo-operator");
    await service2.advanceMinutes(48 * 60, "demo-operator");
    await service2.reopenIncident("inc_route", "demo-operator");
    await service2.runRetention();
    assert.equal(countDocs(store2.read(), "src_dispatch_prod", "inc_route"), 9);
    assert.equal(store2.read().incidents.find((incident) => incident.id === "inc_route")?.purgeDueAt, null);
  });

  it("retries a disconnected source and dead-letters without deleting", async () => {
    const { store, service } = demoService();
    await service.resolveIncident("inc_token", "demo-operator");
    await service.advanceMinutes(48 * 60, "demo-operator");
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const report = await service.runRetention();
      assert.equal(report.retried.some((item) => item.incidentId === "inc_token"), true);
      assert.equal(countDocs(store.read(), "src_identity_prod", "inc_token"), 21);
      await service.advanceMinutes(120, "demo-operator");
    }
    const parked = await service.runRetention();
    assert.equal(parked.deadlettered.some((item) => item.incidentId === "inc_token"), true);
    assert.equal(countDocs(store.read(), "src_identity_prod", "inc_token"), 21);
    assert.equal(store.read().ledger.some((entry) => entry.incidentId === "inc_token"), true);
  });

  it("stops a purge when the incident is reopened before the next document", async () => {
    const { store, service } = demoService();
    await service.advanceMinutes(48 * 60, "demo-operator");
    const report = await service.runRetention("retention-worker", {
      beforeEachDelete(draft, incidentId, docId) {
        if (incidentId !== "inc_fx_round" || !docId.endsWith("_2")) return;
        const incident = draft.incidents.find((item) => item.id === incidentId);
        if (!incident) return;
        incident.status = "open";
        incident.purgeDueAt = null;
        incident.resolvedAt = null;
        incident.resolutionVersion += 1;
      },
    });
    assert.equal(report.skipped.some((item) => item.incidentId === "inc_fx_round" && item.reason === "recheck_failed"), true);
    assert.equal(store.read().receipts.some((receipt) => receipt.incidentId === "inc_fx_round"), false);
    const left = store.read().collections.src_ledger_prod?.filter((doc) => doc.sourceDocumentId.startsWith("inc_fx_round")) ?? [];
    assert.deepEqual(left.map((doc) => doc.sourceDocumentId), ["inc_fx_round_doc_2"]);
  });

  it("bounds a pass to 25 deletes", async () => {
    const store = new MemoryStore();
    const { service } = demoService(store);
    await service.createSource({
      displayName: "Batch Lab",
      system: "Batch Lab",
      environment: "development",
      databaseName: "batch_lab",
      secretRef: "ref_demo_batch_lab",
    }, "demo-operator");
    const sourceId = (await service.listSources()).find((source) => source.databaseName === "batch_lab")?.id;
    assert.ok(sourceId);
    for (let n = 0; n < 30; n += 1) {
      const created = await service.recordOccurrence({
        sourceId,
        message: `Synthetic batch error ${n}`,
        severity: "low",
        stack: `Error: Synthetic batch error ${n}\n    at Lab.run (src/lab.ts:${n}:1)`,
      }, "demo-operator");
      await service.resolveIncident(created.incident.id, "demo-operator");
    }
    await service.advanceMinutes(48 * 60, "demo-operator");
    const report = await service.runRetention();
    assert.equal(report.considered, 25);
    assert.equal(report.waitingBeyondBatch, 5);
    assert.equal(report.purged.length, 25);
  });
});

describe("profiles", () => {
  it("detaches a profile without dropping the database or collection", async () => {
    const { store, service } = demoService();
    const before = structuredClone(store.read().collections.src_ledger_prod);
    const result = await service.detachSource("src_ledger_prod", "demo-operator");
    assert.equal(result.databaseDropped, false);
    assert.equal(result.collectionDropped, false);
    assert.equal(result.documentsDeleted, 0);
    assert.equal(result.collectionName, "Backend_errors");
    assert.deepEqual(store.read().collections.src_ledger_prod, before);
    const detached = store.read().sources.find((source) => source.id === "src_ledger_prod");
    assert.ok(detached?.detachedAt);
    assert.equal(detached?.databaseName, "payments_ledger");
    assert.equal((await service.listSources()).some((source) => source.id === "src_ledger_prod"), false);
    await service.advanceMinutes(48 * 60, "demo-operator");
    await service.runRetention();
    assert.deepEqual(store.read().collections.src_ledger_prod, before);
  });

  it("keeps purge aimed at the snapshot after the profile is renamed", async () => {
    const { store, service } = demoService();
    await service.resolveIncident("inc_price", "demo-operator");
    await service.updateSource("src_catalog_prod", { databaseName: "catalog_renamed" }, "demo-operator");
    await service.advanceMinutes(48 * 60, "demo-operator");
    await service.runRetention();
    assert.equal(countDocs(store.read(), "src_catalog_prod", "inc_price"), 0);
    const receipt = store.read().receipts.find((item) => item.incidentId === "inc_price");
    assert.equal(receipt?.sourceId, "src_catalog_prod");
  });

  it("opens a new incident when a fingerprint returns after resolution", async () => {
    const { store, service } = demoService();
    const resolved = await service.resolveIncident("inc_price", "demo-operator");
    const due = resolved.incident.purgeDueAt;
    const recurrence = await service.recordOccurrence({
      sourceId: "src_catalog_prod",
      message: resolved.incident.message,
      severity: "low",
      stack: resolved.incident.stackRedacted,
      fingerprint: resolved.incident.fingerprint,
    }, "demo-operator");
    assert.equal(recurrence.kind, "created");
    assert.notEqual(recurrence.incident.id, "inc_price");
    assert.equal(store.read().incidents.find((incident) => incident.id === "inc_price")?.purgeDueAt, due);
    assert.equal(store.read().incidents.find((incident) => incident.id === "inc_price")?.status, "resolved");
  });
});

describe("persistence and http", () => {
  it("keeps the ledger and clock after a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "deh-"));
    const path = join(dir, "state.json");
    const firstStore = new FileStore(path);
    await firstStore.transaction((draft) => {
      Object.assign(draft, buildSeed(WALL));
    });
    const first = new HandbookService(firstStore, makeClock(firstStore, () => WALL), {
      mode: "demo",
      retentionIntervalMs: 60_000,
      allowPrivateNetworks: false,
      mongodbEnabled: false,
      postgresEnabled: false,
    });
    await first.resolveIncident("inc_capture", "demo-operator");
    await first.advanceMinutes(48 * 60, "demo-operator");
    await first.runRetention();
    const reloaded = new FileStore(path);
    assert.equal(reloaded.read().ledger.some((entry) => entry.incidentId === "inc_capture"), true);
    assert.equal(countDocs(reloaded.read(), "src_ledger_prod", "inc_capture"), 0);
    assert.ok(reloaded.read().clockOffsetMs >= 48 * 60 * MINUTE);
    assert.equal(JSON.stringify(reloaded.read()).includes("mongodb://"), false);
  });

  it("rejects raw uris in demo and hides production secrets", async () => {
    const { service, store } = demoService();
    const app = createApp(service, { mode: "demo" });
    const rejected = await app.request("/api/v1/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        displayName: "Billing",
        system: "Billing",
        environment: "staging",
        databaseName: "billing_demo",
        uri: "mongodb://user:s3cret-value@10.0.0.8/billing_demo",
      }),
    });
    assert.equal(rejected.status, 400);
    const rejectedBody = await rejected.text();
    assert.equal(rejectedBody.includes("s3cret-value"), false);

    const created = await app.request("/api/v1/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        displayName: "Billing",
        system: "Billing",
        environment: "staging",
        databaseName: "billing_demo",
        secretRef: "ref_demo_billing_stage",
      }),
    });
    assert.equal(created.status, 201);
    const createdText = await created.text();
    assert.equal(createdText.includes("ref_demo_billing_stage"), false);
    assert.equal(createdText.includes("mongodb://"), false);

    const key = randomBytes(32);
    const prodStore = new MemoryStore();
    const prod = new HandbookService(prodStore, makeClock(prodStore, () => WALL), {
      mode: "production",
      retentionIntervalMs: 60_000,
      allowPrivateNetworks: true,
      mongodbEnabled: true,
      postgresEnabled: true,
      masterKey: key,
      verifyLiveConnection: false,
      deleteExternal: async () => "deleted",
    });
    const prodApp = createApp(prod, { mode: "production", adminToken: "test-admin-token" });
    const denied = await prodApp.request("/api/v1/rewards");
    assert.equal(denied.status, 401);
    const uri = "mongodb://handbook-user:s3cret-value@db.internal.example:27017/payments_ledger";
    const ok = await prodApp.request("/api/v1/sources", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer test-admin-token",
      },
      body: JSON.stringify({
        displayName: "Ledger API",
        system: "Ledger API",
        environment: "production",
        databaseName: "payments_ledger",
        uri,
      }),
    });
    assert.equal(ok.status, 201);
    const okText = await ok.text();
    assert.equal(okText.includes("s3cret-value"), false);
    assert.equal(okText.includes("handbook-user"), false);
    const saved = prodStore.read().sources[0];
    assert.ok(saved?.secretCiphertext);
    assert.equal(saved?.secretCiphertext?.includes("s3cret-value"), false);
    assert.equal(decryptString(saved?.secretCiphertext ?? "", key), uri);
    assert.equal(store.read().sources.some((source) => source.databaseName === "billing_demo"), true);
  });

  it("creates and purges postgres demo profiles like mongodb", async () => {
    const { service, store } = demoService();
    const created = await service.createSource(
      {
        displayName: "Billing PG",
        system: "Billing API",
        environment: "staging",
        databaseName: "billing_pg",
        adapterKind: "postgres",
        secretRef: "ref_demo_billing_pg",
      },
      "demo-operator",
    );
    assert.equal(created.adapterKind, "postgres");
    assert.equal(created.status, "connected");
    assert.equal(created.schemaMapId, "postgres-backend-errors-v1");
    const tested = await service.testSource(created.id, "demo-operator");
    assert.equal(tested.ok, true);
    assert.match(tested.message, /postgres/i);

    const catalog = store.read().incidents.find((incident) => incident.id === "inc_price");
    assert.ok(catalog);
    await service.resolveIncident("inc_price", "demo-operator");
    await service.advanceMinutes(48 * 60, "demo-operator");
    const report = await service.runRetention();
    assert.equal(report.purged.includes("inc_price"), true);
    assert.equal(countDocs(store.read(), "src_catalog_prod", "inc_price"), 0);
  });

  it("routes production deletes by adapter and respects enable flags", async () => {
    const key = randomBytes(32);
    const calls: { adapterKind: string; sourceDocumentId: string }[] = [];
    const store = new MemoryStore();
    const service = new HandbookService(store, makeClock(store, () => WALL), {
      mode: "production",
      retentionIntervalMs: 60_000,
      allowPrivateNetworks: true,
      mongodbEnabled: false,
      postgresEnabled: true,
      masterKey: key,
      verifyLiveConnection: false,
      deleteExternal: async (args) => {
        calls.push({ adapterKind: args.adapterKind, sourceDocumentId: args.sourceDocumentId });
        return "deleted";
      },
    });
    const source = await service.createSource(
      {
        displayName: "Catalog PG",
        system: "Catalog",
        environment: "production",
        databaseName: "catalog_edge",
        adapterKind: "postgres",
        uri: "postgres://handbook:s3cret@db.internal.example:5432/catalog_edge",
      },
      "gateway-admin",
    );
    await store.transaction((draft) => {
      draft.incidents.push({
        id: "inc_pg_live",
        sourceId: source.id,
        sourceDocumentIds: ["pg_doc_1"],
        fingerprint: "abcdef1234567890",
        severity: "low",
        message: "Synthetic postgres purge",
        stackRedacted: "Error: Synthetic postgres purge",
        context: {},
        firstSeenAt: new Date(WALL).toISOString(),
        lastSeenAt: new Date(WALL).toISOString(),
        status: "resolved",
        resolvedAt: new Date(WALL - 48 * 60 * MINUTE).toISOString(),
        resolvedBy: "gateway-admin",
        purgeDueAt: new Date(WALL).toISOString(),
        resolutionVersion: 1,
        notes: "",
        purgedAt: null,
        purgeBlockReason: null,
        snapshot: {
          displayName: "Catalog PG",
          system: "Catalog",
          environment: "production",
          databaseName: "catalog_edge",
          collectionName: "Backend_errors",
        },
      });
      const live = draft.sources.find((item) => item.id === source.id);
      if (live) live.status = "connected";
    });
    const report = await service.runRetention();
    assert.equal(report.purged.includes("inc_pg_live"), true);
    assert.deepEqual(calls, [{ adapterKind: "postgres", sourceDocumentId: "pg_doc_1" }]);

    const blockedStore = new MemoryStore();
    const disabled = new HandbookService(blockedStore, makeClock(blockedStore, () => WALL), {
      mode: "production",
      retentionIntervalMs: 60_000,
      allowPrivateNetworks: true,
      mongodbEnabled: false,
      postgresEnabled: false,
      masterKey: key,
      verifyLiveConnection: false,
    });
    const blocked = await disabled.createSource(
      {
        displayName: "Blocked PG",
        system: "Catalog",
        environment: "production",
        databaseName: "catalog_edge",
        adapterKind: "postgres",
        uri: "postgresql://handbook:s3cret@db.internal.example:5432/catalog_edge",
      },
      "gateway-admin",
    );
    await blockedStore.transaction((draft) => {
      draft.incidents.push({
        id: "inc_pg_blocked",
        sourceId: blocked.id,
        sourceDocumentIds: ["pg_doc_2"],
        fingerprint: "abcdef1234567891",
        severity: "low",
        message: "Blocked",
        stackRedacted: "Error: Blocked",
        context: {},
        firstSeenAt: new Date(WALL).toISOString(),
        lastSeenAt: new Date(WALL).toISOString(),
        status: "resolved",
        resolvedAt: new Date(WALL - 48 * 60 * MINUTE).toISOString(),
        resolvedBy: "gateway-admin",
        purgeDueAt: new Date(WALL).toISOString(),
        resolutionVersion: 1,
        notes: "",
        purgedAt: null,
        purgeBlockReason: null,
        snapshot: {
          displayName: "Blocked PG",
          system: "Catalog",
          environment: "production",
          databaseName: "catalog_edge",
          collectionName: "Backend_errors",
        },
      });
      const live = draft.sources.find((item) => item.id === blocked.id);
      if (live) live.status = "connected";
    });
    const disabledReport = await disabled.runRetention();
    assert.equal(
      disabledReport.retried.some((item) => item.reason === "adapter_disabled") ||
        disabledReport.deadlettered.some((item) => item.reason === "adapter_disabled"),
      true,
    );
  });
});

function countDocs(state: StoreData, sourceId: string, prefix: string): number {
  return (state.collections[sourceId] ?? []).filter((doc) => doc.sourceDocumentId.startsWith(prefix)).length;
}

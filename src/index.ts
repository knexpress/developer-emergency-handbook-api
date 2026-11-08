import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { serve } from "@hono/node-server";
import { createApp } from "./http/app.js";
import { masterKeyFromBase64 } from "./domain/security.js";
import type { GatewayMode } from "./domain/types.js";
import { HandbookService } from "./service/handbook.js";
import { FileStore, makeClock } from "./store/store.js";
import { startRetentionWorker } from "./worker/retentionWorker.js";

loadEnvFile(resolve(dirname(fileURLToPath(import.meta.url)), "../.env"));

const mode: GatewayMode =
  process.env.DEH_MODE === "demo"
    ? "demo"
    : process.env.DEH_MODE === "production"
      ? "production"
      : "live";
const host = process.env.DEH_HOST ?? "0.0.0.0";
// Render (and most hosts) inject PORT. Prefer that, then DEH_PORT, then local default.
const port = Number(process.env.PORT ?? process.env.DEH_PORT ?? 43124);
const retentionIntervalMs = Number(process.env.DEH_RETENTION_INTERVAL_MS ?? 60_000);
const syncIntervalMs = Number(process.env.DEH_SYNC_INTERVAL_MS ?? 60_000);
const dataPath = resolve(process.env.DEH_DATA_PATH ?? "./data/gateway-state.json");

if (!Number.isFinite(port) || port <= 0) {
  console.error("DEH_PORT is invalid.");
  process.exit(1);
}

let masterKey: Buffer | undefined;
let adminToken: string | undefined;
if (mode === "production") {
  if (!process.env.DEH_ADMIN_TOKEN) {
    console.error("DEH_ADMIN_TOKEN is required in production. There is no default token.");
    process.exit(1);
  }
  if (!process.env.DEH_MASTER_KEY) {
    console.error("DEH_MASTER_KEY is required in production.");
    process.exit(1);
  }
  adminToken = process.env.DEH_ADMIN_TOKEN;
  masterKey = masterKeyFromBase64(process.env.DEH_MASTER_KEY);
} else if (mode === "live") {
  masterKey = loadOrCreateLiveMasterKey(resolve(dirname(dataPath), "live-master.key"));
}

// Discover + sync are always available in live/production.
// Remote document purge stays opt-in so attaching a DB never deletes source data by accident.
if (mode !== "demo") {
  if (process.env.DEH_ENABLE_MONGODB !== "1") process.env.DEH_ENABLE_MONGODB = "0";
  if (process.env.DEH_ENABLE_POSTGRES !== "1") process.env.DEH_ENABLE_POSTGRES = "0";
}

const store = new FileStore(dataPath);
const service = new HandbookService(store, makeClock(store), {
  mode,
  retentionIntervalMs,
  allowPrivateNetworks: process.env.DEH_ALLOW_PRIVATE_DB !== "false",
  mongodbEnabled: process.env.DEH_ENABLE_MONGODB === "1",
  postgresEnabled: process.env.DEH_ENABLE_POSTGRES === "1",
  masterKey,
});

await service.ensureDemoSeed();
const app = createApp(service, { mode, adminToken });
startRetentionWorker(service, retentionIntervalMs);

if (mode !== "demo" && Number.isFinite(syncIntervalMs) && syncIntervalMs > 0) {
  const syncTimer = setInterval(() => {
    void service.syncAll("sync-worker").catch((error: unknown) => {
      console.error(`sync pass failed: ${error instanceof Error ? error.message : "sync failed"}`);
    });
  }, syncIntervalMs);
  if (typeof syncTimer.unref === "function") syncTimer.unref();
}

serve({ fetch: app.fetch, hostname: host, port }, () => {
  if (mode === "demo") {
    console.log(`Developer Emergency Handbook gateway (demo) on http://${host}:${port}`);
    console.log("No external database calls unless DEH_SEED_DEMO=1 with local seed.");
  } else if (mode === "live") {
    console.log(`Developer Emergency Handbook gateway (live) on http://${host}:${port}`);
    console.log("Add a database URI from the app Settings. URIs are encrypted on this gateway.");
  } else {
    console.log(`Developer Emergency Handbook gateway (production) on http://${host}:${port}`);
  }
});

function loadEnvFile(path: string): void {
  if (!existsSync(path)) return;
  const text = readFileSync(path, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

function loadOrCreateLiveMasterKey(path: string): Buffer {
  mkdirSync(dirname(path), { recursive: true });
  if (process.env.DEH_MASTER_KEY) {
    return masterKeyFromBase64(process.env.DEH_MASTER_KEY);
  }
  if (existsSync(path)) {
    const raw = readFileSync(path, "utf8").trim();
    return masterKeyFromBase64(raw);
  }
  const key = randomBytes(32);
  writeFileSync(path, key.toString("base64"), { encoding: "utf8", mode: 0o600 });
  console.log(`Generated live master key at ${path}`);
  return key;
}

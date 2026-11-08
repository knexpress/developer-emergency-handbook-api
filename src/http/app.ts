import { Hono } from "hono";
import { cors } from "hono/cors";
import { sanitizeErrorText, tokensMatch } from "../domain/security.js";
import type { Severity } from "../domain/types.js";
import { HttpError, type HandbookService } from "../service/handbook.js";

export interface AppOptions {
  mode: "demo" | "live" | "production";
  adminToken?: string;
}

function actorFor(mode: AppOptions["mode"]): string {
  return mode === "demo" ? "demo-operator" : mode === "live" ? "live-operator" : "gateway-admin";
}

export function createApp(service: HandbookService, options: AppOptions) {
  const app = new Hono();
  app.use("*", cors());

  app.onError((error, c) => {
    if (error instanceof HttpError) {
      return c.json(
        { error: { code: error.code, message: sanitizeErrorText(error.message) } },
        error.status as 400,
      );
    }
    console.error(sanitizeErrorText(error instanceof Error ? error.message : "request failed"));
    return c.json({ error: { code: "internal", message: "The gateway could not complete that request." } }, 500);
  });

  app.use("/api/v1/*", async (c, next) => {
    if (options.mode !== "production") {
      await next();
      return;
    }
    if (c.req.path === "/api/v1/health") {
      await next();
      return;
    }
    const header = c.req.header("authorization") ?? "";
    const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
    if (!options.adminToken || !token || !tokensMatch(token, options.adminToken)) {
      return c.json({ error: { code: "unauthorized", message: "Admin authentication is required." } }, 401);
    }
    await next();
  });

  app.get("/", (c) =>
    c.json({
      app: "Developer Emergency Handbook",
      api: "/api/v1/meta",
      mode: options.mode,
    }),
  );

  app.get("/api/v1/health", (c) => c.json({ ok: true, mode: options.mode }));
  app.get("/api/v1/meta", async (c) => c.json(await service.meta()));
  app.get("/api/v1/sources", async (c) => c.json({ sources: await service.listSources() }));
  app.get("/api/v1/sources/detached", async (c) => c.json({ sources: await service.listDetached() }));

  app.post("/api/v1/sources/discover", async (c) => {
    const body = await readJson(c);
    return c.json(
      await service.discover({
        uri: stringField(body, "uri"),
        databaseName: optionalString(body, "databaseName"),
      }),
    );
  });

  app.post("/api/v1/sources", async (c) => {
    const body = await readJson(c);
    const source = await service.createSource(
      {
        displayName: stringField(body, "displayName"),
        system: optionalString(body, "system"),
        environment: (optionalString(body, "environment") as "production" | undefined) ?? "production",
        databaseName: stringField(body, "databaseName"),
        collectionName: optionalString(body, "collectionName"),
        adapterKind: optionalString(body, "adapterKind") as "mongodb" | "postgres" | undefined,
        secretRef: optionalString(body, "secretRef"),
        uri: optionalString(body, "uri"),
        sync: body.sync === false ? false : true,
      },
      actorFor(options.mode),
    );
    return c.json({ source }, 201);
  });

  app.post("/api/v1/sources/:id/sync", async (c) => {
    return c.json(await service.syncSource(c.req.param("id"), actorFor(options.mode)));
  });

  app.post("/api/v1/sync", async (c) => c.json(await service.syncAll(actorFor(options.mode))));

  app.patch("/api/v1/sources/:id", async (c) => {
    const body = await readJson(c);
    const source = await service.updateSource(
      c.req.param("id"),
      {
        displayName: optionalString(body, "displayName"),
        system: optionalString(body, "system"),
        environment: optionalString(body, "environment") as "production" | undefined,
        databaseName: optionalString(body, "databaseName"),
      },
      actorFor(options.mode),
    );
    return c.json({ source });
  });

  app.delete("/api/v1/sources/:id", async (c) => {
    const result = await service.detachSource(c.req.param("id"), actorFor(options.mode));
    return c.json(result);
  });

  app.post("/api/v1/sources/:id/test", async (c) => {
    return c.json(await service.testSource(c.req.param("id"), actorFor(options.mode)));
  });

  app.post("/api/v1/refresh", async (c) => c.json(await service.refreshHealth(actorFor(options.mode))));

  app.get("/api/v1/dashboard", async (c) => {
    const sourceId = c.req.query("sourceId");
    return c.json(await service.dashboard(sourceId));
  });

  app.get("/api/v1/incidents", async (c) => {
    const severity = c.req.query("severity");
    const status = c.req.query("status");
    const sort = c.req.query("sort");
    const purge = c.req.query("purge");
    const incidents = await service.listIncidents({
      sourceId: c.req.query("sourceId"),
      q: c.req.query("q"),
      status: status === "open" || status === "resolved" || status === "all" ? status : "all",
      severity: isSeverity(severity) || severity === "all" ? (severity as Severity | "all") : "all",
      sort: sort === "severity" || sort === "occurrences" || sort === "purge" || sort === "recent" ? sort : "recent",
      purge: purge === "pending" || purge === "blocked" ? purge : "any",
    });
    return c.json({
      dataOrigin: options.mode === "demo" ? "illustrative-demo-seed" : "live-sources",
      incidents,
    });
  });

  app.get("/api/v1/incidents/:id", async (c) => c.json({ incident: await service.getIncident(c.req.param("id")) }));

  app.post("/api/v1/incidents/:id/resolve", async (c) => {
    const body = await readJson(c);
    const result = await service.resolveIncident(c.req.param("id"), actorFor(options.mode), claim(body));
    return c.json(result);
  });

  app.post("/api/v1/incidents/:id/reopen", async (c) => {
    const body = await readJson(c);
    const result = await service.reopenIncident(c.req.param("id"), actorFor(options.mode), claim(body));
    return c.json(result);
  });

  app.patch("/api/v1/incidents/:id/notes", async (c) => {
    const body = await readJson(c);
    const incident = await service.setNotes(c.req.param("id"), stringField(body, "notes"), actorFor(options.mode));
    return c.json({ incident });
  });

  app.post("/api/v1/incidents/:id/recurrence", async (c) => {
    const current = await service.getIncident(c.req.param("id"));
    const result = await service.recordOccurrence(
      {
        sourceId: current.sourceId,
        message: current.message,
        severity: current.severity,
        stack: current.stackRedacted,
        context: current.context,
        fingerprint: current.fingerprint,
      },
      actorFor(options.mode),
    );
    return c.json({
      simulated: true,
      networkCall: false,
      kind: result.kind,
      incident: result.incident,
      note: "Simulated inside the demo gateway. The source database was not contacted. A resolved incident keeps its own purge schedule.",
    });
  });

  app.get("/api/v1/rewards", async (c) => c.json(await service.rewards()));

  app.post("/api/v1/demo/advance", async (c) => {
    const body = await readJson(c);
    const minutes = typeof body.minutes === "number" ? body.minutes : Number.NaN;
    return c.json(await service.advanceMinutes(minutes, actorFor(options.mode)));
  });

  app.post("/api/v1/demo/retention", async (c) => c.json(await service.runRetention("retention-worker")));
  app.post("/api/v1/demo/reset", async (c) => c.json(await service.resetDemo(actorFor(options.mode))));

  return app;
}

function isSeverity(value: string | undefined): value is Severity {
  return value === "critical" || value === "high" || value === "medium" || value === "low";
}

async function readJson(c: { req: { json: () => Promise<unknown> } }): Promise<Record<string, unknown>> {
  try {
    const body = await c.req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return {};
    return body as Record<string, unknown>;
  } catch {
    return {};
  }
}

function stringField(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string") throw new HttpError(400, "invalid_body", `${key} is required.`);
  return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw new HttpError(400, "invalid_body", `${key} must be a string.`);
  return value;
}

function claim(body: Record<string, unknown>): { expectedVersion?: number; sourceId?: string } {
  const expectedVersion = body.expectedVersion;
  const sourceId = body.sourceId;
  return {
    expectedVersion: typeof expectedVersion === "number" ? expectedVersion : undefined,
    sourceId: typeof sourceId === "string" ? sourceId : undefined,
  };
}

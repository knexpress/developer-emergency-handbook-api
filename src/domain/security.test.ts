import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { mapBackendError, MONGODB_BACKEND_ERRORS_V1, SAMPLE_MONGODB_BACKEND_ERROR } from "./schema.js";
import {
  assertDemoSecretRef,
  buildMongoDeleteFilter,
  buildPostgresDeleteParams,
  decryptString,
  encryptString,
  maskDatabaseUri,
  sanitizeErrorText,
  tokensMatch,
  validateDatabaseTarget,
} from "./security.js";
import { deleteMongoDocument, deletePostgresDocument } from "../adapters/collections.js";

describe("redaction and schema mapping", () => {
  it("strips uris, emails, and secret assignments", () => {
    const dirty = "failed mongodb://app:s3cret@10.0.0.8/payments_ledger Authorization: Bearer abc.def contact oncall@example.com password=hunter";
    const clean = sanitizeErrorText(dirty);
    assert.equal(clean.includes("s3cret"), false);
    assert.equal(clean.includes("mongodb://"), false);
    assert.equal(clean.includes("oncall@example.com"), false);
    assert.equal(clean.includes("hunter"), false);
    assert.equal(clean.includes("abc.def"), false);
  });

  it("maps a Backend_errors document and drops sensitive context", () => {
    const mapped = mapBackendError(SAMPLE_MONGODB_BACKEND_ERROR, MONGODB_BACKEND_ERRORS_V1, "2026-06-01T00:00:00.000Z");
    assert.equal(mapped.severity, "high");
    assert.equal(mapped.message, "Charge capture failed after authorization hold");
    assert.equal(mapped.fingerprint, "c7e1a9f0b3d24e18");
    assert.equal(mapped.occurrenceCount, 4);
    assert.equal(mapped.context.requestId, "req_demo_18f3");
    assert.equal("password" in mapped.context, false);
    assert.equal(mapped.context.note?.includes("oncall@example.com"), false);
    assert.equal(mapped.context.note?.includes("[redacted-email]"), true);
  });
});

describe("connection secrets", () => {
  it("accepts only fake demo references", () => {
    assert.equal(assertDemoSecretRef("ref_demo_billing_prod"), "ref_demo_billing_prod");
    assert.throws(() => assertDemoSecretRef("mongodb://user:pass@db.example/payments"));
    assert.throws(() => assertDemoSecretRef("postgres://user:pass@db/app"));
    assert.throws(() => assertDemoSecretRef("ref_demo_has spaces"));
  });

  it("encrypts with the master key and masks the uri", () => {
    const key = randomBytes(32);
    const uri = "mongodb://handbook-user:s3cret-value@db.example:27017/payments_ledger";
    const cipher = encryptString(uri, key);
    assert.equal(cipher.includes("s3cret-value"), false);
    assert.equal(decryptString(cipher, key), uri);
    const masked = maskDatabaseUri(uri);
    assert.equal(masked.includes("s3cret-value"), false);
    assert.equal(masked.includes("handbook-user"), false);
    assert.equal(masked.includes("db.example"), true);
    assert.equal(
      maskDatabaseUri("postgres://handbook-user:s3cret-value@db.example:5432/catalog_edge"),
      "postgres://••••@db.example/catalog_edge",
    );
  });

  it("rejects metadata and unexpected schemes, and allows private hosts only when opted in", () => {
    assert.equal(validateDatabaseTarget("http://169.254.169.254/latest", { allowPrivateNetworks: true }).ok, false);
    assert.equal(validateDatabaseTarget("mongodb://169.254.169.254/admin", { allowPrivateNetworks: true }).ok, false);
    assert.equal(validateDatabaseTarget("mongodb://metadata.google.internal/admin", { allowPrivateNetworks: true }).ok, false);
    assert.equal(validateDatabaseTarget("mongodb://10.0.0.8/payments_ledger", { allowPrivateNetworks: false }).ok, false);
    assert.equal(validateDatabaseTarget("mongodb://10.0.0.8/payments_ledger", { allowPrivateNetworks: true }).ok, true);
    assert.equal(validateDatabaseTarget("mongodb+srv://db.example/payments_ledger", { allowPrivateNetworks: false }).ok, true);
    assert.equal(validateDatabaseTarget("postgres://10.0.0.8/catalog_edge", { allowPrivateNetworks: true }).ok, true);
    assert.equal(validateDatabaseTarget("postgresql://db.example/catalog_edge", { allowPrivateNetworks: false }).ok, true);
    assert.equal(validateDatabaseTarget("mysql://db.example/catalog_edge", { allowPrivateNetworks: true }).ok, false);
  });

  it("compares tokens without accepting a hardcoded default", () => {
    assert.equal(tokensMatch("correct-token", "correct-token"), true);
    assert.equal(tokensMatch("nope", "correct-token"), false);
    assert.equal(tokensMatch("", "correct-token"), false);
  });

  it("keeps delete filters to a single id and refuses to connect when disabled", async () => {
    assert.deepEqual(buildMongoDeleteFilter("doc_1"), { _id: "doc_1" });
    assert.deepEqual(buildPostgresDeleteParams("doc_1"), {
      sql: 'DELETE FROM "Backend_errors" WHERE id = $1',
      values: ["doc_1"],
    });
    const previousMongo = process.env.DEH_ENABLE_MONGODB;
    const previousPg = process.env.DEH_ENABLE_POSTGRES;
    delete process.env.DEH_ENABLE_MONGODB;
    delete process.env.DEH_ENABLE_POSTGRES;
    await assert.rejects(
      () => deleteMongoDocument({ uri: "mongodb://user:s3cret@10.0.0.8/db", databaseName: "db", sourceDocumentId: "1" }),
      /disabled/,
    );
    await assert.rejects(
      () =>
        deletePostgresDocument({
          uri: "postgres://user:s3cret@10.0.0.8/db",
          databaseName: "db",
          sourceDocumentId: "1",
        }),
      /disabled/,
    );
    if (previousMongo === undefined) delete process.env.DEH_ENABLE_MONGODB;
    else process.env.DEH_ENABLE_MONGODB = previousMongo;
    if (previousPg === undefined) delete process.env.DEH_ENABLE_POSTGRES;
    else process.env.DEH_ENABLE_POSTGRES = previousPg;
  });
});

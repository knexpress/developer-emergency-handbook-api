import { MongoClient } from "mongodb";
import pg from "pg";
import { validateDatabaseTarget } from "../domain/security.js";
import type { AdapterKind } from "../domain/types.js";

const { Client } = pg;

export function adapterKindFromUri(uri: string): AdapterKind {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new Error("The database URI could not be parsed.");
  }
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (scheme === "mongodb" || scheme === "mongodb+srv") return "mongodb";
  if (scheme === "postgres" || scheme === "postgresql") return "postgres";
  throw new Error("Only mongodb, mongodb+srv, postgres, and postgresql URIs are supported.");
}

export function databaseNameFromUri(uri: string): string | null {
  try {
    const path = new URL(uri).pathname.replace(/^\//, "").split("/")[0] ?? "";
    return path ? decodeURIComponent(path) : null;
  } catch {
    return null;
  }
}

export interface DiscoverResult {
  adapterKind: AdapterKind;
  host: string;
  databaseName: string;
  databases: string[];
  collections: string[];
  ok: true;
}

export async function discoverDatabase(
  uri: string,
  options: { allowPrivateNetworks: boolean; databaseName?: string },
): Promise<DiscoverResult> {
  const verdict = validateDatabaseTarget(uri, { allowPrivateNetworks: options.allowPrivateNetworks });
  if (!verdict.ok) throw new Error(verdict.reason ?? "Target rejected.");
  const adapterKind = adapterKindFromUri(uri);
  if (adapterKind === "mongodb") return discoverMongo(uri, options.databaseName);
  return discoverPostgres(uri, options.databaseName);
}

async function discoverMongo(uri: string, preferredDb?: string): Promise<DiscoverResult> {
  // Read-only: connect, list databases/collections. Never insert/update/delete.
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 12000 });
  try {
    await client.connect();
    const fromUri = databaseNameFromUri(uri);
    let databases: string[] = [];
    try {
      const listed = await client.db().admin().listDatabases({ nameOnly: true });
      databases = listed.databases
        .map((db) => db.name)
        .filter((name) => !["admin", "local", "config"].includes(name))
        .sort();
    } catch {
      // Atlas users often lack listDatabases; fall back to the URI path or a manual pick later.
      if (fromUri) databases = [fromUri];
    }
    const databaseName =
      preferredDb && (databases.length === 0 || databases.includes(preferredDb))
        ? preferredDb
        : fromUri && (databases.length === 0 || databases.includes(fromUri))
          ? fromUri
          : databases[0] ?? fromUri;
    if (!databaseName) {
      throw new Error(
        "Connected, but no database name was found. Put the database in the URI path (…mongodb.net/myDb) or create one in Atlas first.",
      );
    }
    if (!databases.includes(databaseName)) databases = [...databases, databaseName].sort();
    const collections = (
      await client
        .db(databaseName)
        .listCollections({}, { nameOnly: true })
        .toArray()
    )
      .map((item) => item.name)
      .filter((name) => !name.startsWith("system."))
      .sort();
    const host = new URL(uri).hostname;
    return { adapterKind: "mongodb", host, databaseName, databases, collections, ok: true };
  } finally {
    await client.close().catch(() => undefined);
  }
}

async function discoverPostgres(uri: string, preferredDb?: string): Promise<DiscoverResult> {
  const client = new Client({ connectionString: uri, connectionTimeoutMillis: 6000 });
  try {
    await client.connect();
    const dbResult = await client.query<{ datname: string }>(
      "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
    );
    const databases = dbResult.rows.map((row) => row.datname);
    const fromUri = databaseNameFromUri(uri);
    const databaseName =
      preferredDb && databases.includes(preferredDb)
        ? preferredDb
        : fromUri && databases.includes(fromUri)
          ? fromUri
          : databases[0] ?? fromUri ?? "postgres";

    // Collections/tables are listed from the current connection database.
    const tableResult = await client.query<{ name: string }>(
      `SELECT tablename AS name FROM pg_catalog.pg_tables
       WHERE schemaname = 'public'
       UNION
       SELECT viewname AS name FROM pg_catalog.pg_views
       WHERE schemaname = 'public'
       ORDER BY name`,
    );
    const collections = tableResult.rows.map((row) => row.name);
    const host = new URL(uri).hostname;
    return { adapterKind: "postgres", host, databaseName, databases, collections, ok: true };
  } finally {
    await client.end();
  }
}

export interface FetchedErrorDoc {
  sourceDocumentId: string;
  body: Record<string, unknown>;
}

export async function fetchErrorDocuments(args: {
  uri: string;
  adapterKind: AdapterKind;
  databaseName: string;
  collectionName: string;
  limit?: number;
}): Promise<FetchedErrorDoc[]> {
  const limit = Math.min(Math.max(args.limit ?? 200, 1), 1000);
  if (args.adapterKind === "mongodb") return fetchMongoDocuments(args.uri, args.databaseName, args.collectionName, limit);
  return fetchPostgresDocuments(args.uri, args.collectionName, limit);
}

async function fetchMongoDocuments(
  uri: string,
  databaseName: string,
  collectionName: string,
  limit: number,
): Promise<FetchedErrorDoc[]> {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 6000 });
  try {
    await client.connect();
    const docs = await client
      .db(databaseName)
      .collection(collectionName)
      .find({})
      .sort({ ts: -1, _id: -1 })
      .limit(limit)
      .toArray();
    return docs.map((doc) => {
      const id = doc._id != null ? String(doc._id) : JSON.stringify(doc).slice(0, 40);
      const body = { ...doc, _id: id } as Record<string, unknown>;
      return { sourceDocumentId: id, body };
    });
  } finally {
    await client.close();
  }
}

async function fetchPostgresDocuments(
  uri: string,
  collectionName: string,
  limit: number,
): Promise<FetchedErrorDoc[]> {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(collectionName)) {
    throw new Error("Collection/table name is invalid.");
  }
  const client = new Client({ connectionString: uri, connectionTimeoutMillis: 6000 });
  try {
    await client.connect();
    const result = await client.query(`SELECT * FROM "${collectionName}" ORDER BY 1 DESC LIMIT $1`, [limit]);
    return result.rows.map((row, index) => {
      const body = row as Record<string, unknown>;
      const id = body.id != null ? String(body.id) : body._id != null ? String(body._id) : `row_${index}`;
      return { sourceDocumentId: id, body: { ...body, id } };
    });
  } finally {
    await client.end();
  }
}

export async function testLiveConnection(args: {
  uri: string;
  adapterKind: AdapterKind;
  databaseName: string;
  collectionName: string;
}): Promise<{ ok: true; message: string }> {
  const discovered = await discoverDatabase(args.uri, {
    allowPrivateNetworks: true,
    databaseName: args.databaseName,
  });
  if (!discovered.collections.includes(args.collectionName)) {
    throw new Error(`Collection or table "${args.collectionName}" was not found in ${args.databaseName}.`);
  }
  const docs = await fetchErrorDocuments({
    uri: args.uri,
    adapterKind: args.adapterKind,
    databaseName: args.databaseName,
    collectionName: args.collectionName,
    limit: 1,
  });
  return {
    ok: true,
    message: `Connected to ${discovered.host}/${args.databaseName}.${args.collectionName}. Sampled ${docs.length} document(s).`,
  };
}

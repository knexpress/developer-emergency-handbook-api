import { COLLECTION_NAME, type SourceDocument, type StoreData } from "../domain/types.js";
import { buildMongoDeleteFilter, buildPostgresDeleteParams } from "../domain/security.js";
import { MongoClient } from "mongodb";
import pg from "pg";

const { Client } = pg;

export interface DeleteRequest {
  sourceId: string;
  databaseName: string;
  collectionName: string;
  sourceDocumentId: string;
}

/**
 * Removes one document from one source's error collection in the demo store.
 * There is no drop, deleteMany, or cross-source path.
 */
export function deleteDemoDocument(draft: StoreData, request: DeleteRequest): "deleted" | "not_found" {
  const docs = draft.collections[request.sourceId] ?? [];
  const index = docs.findIndex(
    (doc) =>
      doc.sourceDocumentId === request.sourceDocumentId &&
      doc.sourceId === request.sourceId &&
      doc.databaseName === request.databaseName &&
      doc.collectionName === request.collectionName,
  );
  if (index < 0) return "not_found";
  docs.splice(index, 1);
  draft.collections[request.sourceId] = docs;
  return "deleted";
}

export function insertDemoDocument(draft: StoreData, doc: SourceDocument): void {
  const docs = draft.collections[doc.sourceId] ?? [];
  docs.push(doc);
  draft.collections[doc.sourceId] = docs;
}

export async function deleteMongoDocument(args: {
  uri: string;
  databaseName: string;
  collectionName?: string;
  sourceDocumentId: string;
}): Promise<"deleted" | "not_found"> {
  if (process.env.DEH_ENABLE_MONGODB !== "1") {
    throw new Error("MongoDB adapter is disabled. Refusing to open a client.");
  }
  const collectionName = args.collectionName || COLLECTION_NAME;
  const client = new MongoClient(args.uri, { serverSelectionTimeoutMS: 4000 });
  try {
    await client.connect();
    const result = await client
      .db(args.databaseName)
      .collection(collectionName)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .deleteOne(buildMongoDeleteFilter(args.sourceDocumentId) as any);
    return result.deletedCount && result.deletedCount > 0 ? "deleted" : "not_found";
  } finally {
    await client.close();
  }
}

export async function deletePostgresDocument(args: {
  uri: string;
  databaseName: string;
  collectionName?: string;
  sourceDocumentId: string;
}): Promise<"deleted" | "not_found"> {
  if (process.env.DEH_ENABLE_POSTGRES !== "1") {
    throw new Error("Postgres adapter is disabled. Refusing to open a client.");
  }
  void args.databaseName;
  const collectionName = args.collectionName || COLLECTION_NAME;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(collectionName)) {
    throw new Error("Collection/table name is invalid.");
  }
  const client = new Client({ connectionString: args.uri, connectionTimeoutMillis: 4000 });
  try {
    await client.connect();
    const { values } = buildPostgresDeleteParams(args.sourceDocumentId);
    const sql = `DELETE FROM "${collectionName}" WHERE id = $1`;
    const result = await client.query(sql, values);
    return result.rowCount && result.rowCount > 0 ? "deleted" : "not_found";
  } finally {
    await client.end();
  }
}

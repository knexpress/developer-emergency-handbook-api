import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Clock, StoreData } from "../domain/types.js";

export function emptyState(): StoreData {
  return {
    clockOffsetMs: 0,
    sources: [],
    incidents: [],
    ledger: [],
    receipts: [],
    deadletters: [],
    retries: [],
    audit: [],
    collections: {},
  };
}

export interface Store {
  read(): StoreData;
  transaction<T>(fn: (draft: StoreData) => T | Promise<T>): Promise<T>;
}

export class MemoryStore implements Store {
  protected data: StoreData;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(initial: StoreData = emptyState()) {
    this.data = initial;
  }

  read(): StoreData {
    return structuredClone(this.data);
  }

  transaction<T>(fn: (draft: StoreData) => T | Promise<T>): Promise<T> {
    const run = this.chain.then(async () => {
      const snapshot = structuredClone(this.data);
      try {
        return await fn(this.data);
      } catch (error) {
        this.data = snapshot;
        throw error;
      }
    });
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

export class FileStore extends MemoryStore {
  constructor(private readonly filePath: string) {
    super(emptyState());
    this.data = this.load();
  }

  override async transaction<T>(fn: (draft: StoreData) => T | Promise<T>): Promise<T> {
    const result = await super.transaction(fn);
    this.persist();
    return result;
  }

  private load(): StoreData {
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, "utf8")) as StoreData;
      if (!parsed || !Array.isArray(parsed.sources) || !Array.isArray(parsed.incidents)) {
        throw new Error("Demo state file is missing required fields.");
      }
      return parsed;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return emptyState();
      throw error;
    }
  }

  private persist(): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    renameSync(tmp, this.filePath);
  }
}

export function makeClock(store: Store, wall: () => number = Date.now): Clock {
  return {
    nowMs: () => wall() + store.read().clockOffsetMs,
    iso() {
      return new Date(this.nowMs()).toISOString();
    },
  };
}

import { sanitizeErrorText } from "../domain/security.js";
import type { HandbookService } from "../service/handbook.js";

/** Runs in the gateway process. The mobile app does not own this timer. */
export function startRetentionWorker(service: HandbookService, intervalMs: number): () => void {
  const timer = setInterval(() => {
    void service.runRetention("retention-worker").catch((error: unknown) => {
      const message = error instanceof Error ? error.message : "retention failed";
      console.error(`retention pass failed: ${sanitizeErrorText(message)}`);
    });
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  return () => clearInterval(timer);
}

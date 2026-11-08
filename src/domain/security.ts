import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

const URI_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/\S+/gi;
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const BEARER_PATTERN = /bearer\s+\S+/gi;
const SECRET_ASSIGN_PATTERN = /(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+/gi;
const SENSITIVE_KEY = /password|passwd|secret|token|authorization|connection|uri|credential|api[-_]?key/i;

export function sanitizeErrorText(input: string): string {
  return input
    .replace(BEARER_PATTERN, "Bearer [redacted]")
    .replace(URI_PATTERN, "[redacted-uri]")
    .replace(EMAIL_PATTERN, "[redacted-email]")
    .replace(SECRET_ASSIGN_PATTERN, "$1=[redacted]");
}

export function fingerprintFrom(message: string, stack: string): string {
  const frame = stack
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("at ")) ?? "";
  return createHash("sha256").update(`${message}\n${frame}`).digest("hex").slice(0, 16);
}

export function safeContext(input: Record<string, unknown>, limit = 12): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (Object.keys(out).length >= limit) break;
    if (SENSITIVE_KEY.test(key)) continue;
    if (typeof value === "string") {
      const clean = sanitizeErrorText(value).slice(0, 180);
      if (clean) out[key] = clean;
    } else if (typeof value === "number" || typeof value === "boolean") {
      out[key] = String(value);
    }
  }
  return out;
}

export function assertDemoSecretRef(input: string): string {
  const trimmed = input.trim();
  if (
    trimmed.includes("://") ||
    trimmed.includes("@") ||
    /mongodb|postgres|password|secret/i.test(trimmed)
  ) {
    throw new Error(
      "Demo mode does not accept connection URIs or passwords. Use a fake reference such as ref_demo_billing_prod.",
    );
  }
  if (!/^ref_demo_[a-z0-9_]{3,48}$/.test(trimmed)) {
    throw new Error(
      "Use a fake reference shaped like ref_demo_billing_prod. This demo does not store a real URI.",
    );
  }
  return trimmed;
}

export function maskSecretRef(ref: string): string {
  if (ref.length <= 12) return "ref_demo••••";
  return `${ref.slice(0, 8)}••••${ref.slice(-4)}`;
}

export function tokensMatch(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    // Compare equal-length hashes so the timing does not reveal the expected length.
    const ah = createHash("sha256").update(a).digest();
    const bh = createHash("sha256").update(b).digest();
    timingSafeEqual(ah, bh);
    return false;
  }
  return timingSafeEqual(a, b);
}

export function masterKeyFromBase64(raw: string): Buffer {
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("DEH_MASTER_KEY must be 32 bytes, base64-encoded.");
  }
  return key;
}

export function encryptString(plain: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${data.toString("base64")}`;
}

export function decryptString(payload: string, key: Buffer): string {
  const [ivB64, tagB64, dataB64] = payload.split(".");
  if (!ivB64 || !tagB64 || !dataB64) throw new Error("Ciphertext is malformed.");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const plain = Buffer.concat([decipher.update(Buffer.from(dataB64, "base64")), decipher.final()]);
  return plain.toString("utf8");
}

const BLOCKED_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.google.com",
]);

function ipv4Parts(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => Number(part));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

export function isLinkLocalHost(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (name.startsWith("fe80:") || name.startsWith("169.254.")) return true;
  const v4 = ipv4Parts(name);
  if (!v4) return false;
  return v4[0] === 169 && v4[1] === 254;
}

export function isPrivateOrLoopbackHost(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (name === "localhost" || name.endsWith(".local") || name === "::1" || name === "0.0.0.0") return true;
  const v4 = ipv4Parts(name);
  if (!v4) return name === "::1";
  const [a, b] = v4;
  if (a === 10 || a === 127) return true;
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

export interface TargetVerdict {
  ok: boolean;
  reason?: string;
  host?: string;
}

/**
 * String-level gate for a future test-connection call. It does not resolve DNS
 * (a lookup would itself be a network side effect). Link-local and metadata
 * hosts are always rejected. Private hosts are allowed only when the operator
 * opts in for a self-hosted database. This is not a complete SSRF defense.
 */
export function validateDatabaseTarget(uri: string, options: { allowPrivateNetworks: boolean }): TargetVerdict {
  if (uri.length > 2000 || /[\r\n\0]/.test(uri)) {
    return { ok: false, reason: "The target URI was rejected." };
  }
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return { ok: false, reason: "The target URI could not be parsed." };
  }
  const scheme = url.protocol.replace(":", "").toLowerCase();
  const allowed = new Set(["mongodb", "mongodb+srv", "postgres", "postgresql"]);
  if (!allowed.has(scheme)) {
    return {
      ok: false,
      reason: "Only mongodb, mongodb+srv, postgres, and postgresql schemes are accepted.",
    };
  }
  const host = url.hostname.toLowerCase();
  if (!host) return { ok: false, reason: "The target host is missing." };
  if (BLOCKED_HOSTS.has(host) || host.endsWith(".metadata.google.internal")) {
    return { ok: false, reason: "Metadata service hosts are blocked." };
  }
  if (isLinkLocalHost(host)) {
    return { ok: false, reason: "Link-local and cloud metadata addresses are blocked." };
  }
  if (!options.allowPrivateNetworks && isPrivateOrLoopbackHost(host)) {
    return {
      ok: false,
      reason: "Private network targets are disabled. Set DEH_ALLOW_PRIVATE_DB=true only for a database inside your own network.",
    };
  }
  return { ok: true, host };
}

export function maskDatabaseUri(uri: string): string {
  try {
    const url = new URL(uri);
    const scheme = url.protocol.replace(":", "");
    const db = url.pathname.replace(/^\//, "").split("/")[0] || "database";
    return `${scheme}://••••@${url.hostname}/${db}`;
  } catch {
    return "••••";
  }
}

/** @deprecated Prefer maskDatabaseUri — kept for existing call sites. */
export const maskMongoUri = maskDatabaseUri;

export function buildMongoDeleteFilter(sourceDocumentId: string): { _id: string } {
  return { _id: sourceDocumentId };
}

export function buildPostgresDeleteParams(sourceDocumentId: string): {
  sql: string;
  values: [string];
} {
  return {
    sql: 'DELETE FROM "Backend_errors" WHERE id = $1',
    values: [sourceDocumentId],
  };
}

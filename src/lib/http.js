import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, "../public");

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()"
};

export function sendJson(response, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload, null, 2);

  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    ...SECURITY_HEADERS,
    ...extraHeaders
  });
  response.end(body);
}

export function sendEmpty(response, statusCode, extraHeaders = {}) {
  response.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    ...extraHeaders
  });
  response.end();
}

export async function readJsonBody(request, maxBytes = 65536) {
  const chunks = [];
  let received = 0;

  for await (const chunk of request) {
    received += chunk.length;
    if (received > maxBytes) {
      const error = new Error("Request body too large");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) {
    return {};
  }

  const raw = Buffer.concat(chunks).toString("utf8");

  try {
    return JSON.parse(raw);
  } catch {
    const error = new Error("Request body must be valid JSON");
    error.statusCode = 400;
    throw error;
  }
}

export function getBearerToken(request) {
  const authorization = request.headers.authorization;

  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice("Bearer ".length);
}

export async function sendStaticAsset(response, relativePath) {
  const fullPath = path.join(PUBLIC_DIR, relativePath);
  const file = await readFile(fullPath);
  const extension = path.extname(relativePath);
  const contentType = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8"
  }[extension] ?? "application/octet-stream";

  response.writeHead(200, {
    "content-type": contentType,
    "content-length": file.length,
    ...SECURITY_HEADERS
  });
  response.end(file);
}

export function applyCors(request, response, allowedOrigins) {
  const origin = request.headers.origin;
  const allowAny = allowedOrigins.includes("*");

  if (allowAny) {
    response.setHeader("access-control-allow-origin", "*");
  } else if (origin && allowedOrigins.includes(origin)) {
    response.setHeader("access-control-allow-origin", origin);
    response.setHeader("vary", "origin");
  }

  response.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  response.setHeader("access-control-allow-headers", "content-type,authorization");
}

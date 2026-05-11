import { randomBytes } from "node:crypto";

const COOKIE_NAME = "knock_session";

export function buildSessionCookie(sessionId, config) {
  const parts = [
    `${COOKIE_NAME}=${sessionId}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax"
  ];

  if (config.cookieDomain) {
    parts.push(`Domain=${config.cookieDomain}`);
  }

  return parts.join("; ");
}

export function buildSessionClearCookie(config) {
  const parts = [
    `${COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  ];

  if (config.cookieDomain) {
    parts.push(`Domain=${config.cookieDomain}`);
  }

  return parts.join("; ");
}

export function parseSessionCookie(request) {
  const cookie = request.headers.cookie;
  if (!cookie) return null;

  const match = cookie.match(new RegExp(`(?:^|\\s)${COOKIE_NAME}=([^;]+)`));
  return match ? match[1].trim() : null;
}

export function createSessionId() {
  return randomBytes(16).toString("hex");
}

const SAME_ORIGIN_BASE = "http://knock.local";
const INVALID_CALLBACK_PATTERN = /[\u0000-\u001F\u007F\\]/;

export function sanitizeCallbackPath(value, fallback = "/") {
  if (typeof value !== "string") {
    return fallback;
  }

  const trimmed = value.trim();
  if (!trimmed || !trimmed.startsWith("/") || trimmed.startsWith("//")) {
    return fallback;
  }

  if (INVALID_CALLBACK_PATTERN.test(trimmed)) {
    return fallback;
  }

  try {
    const url = new URL(trimmed, SAME_ORIGIN_BASE);
    if (url.origin !== SAME_ORIGIN_BASE) {
      return fallback;
    }
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return fallback;
  }
}

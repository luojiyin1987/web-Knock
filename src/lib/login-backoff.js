/**
 * Login backoff service.
 * Implements exponential backoff per IP to mitigate brute-force attacks.
 * Each failure doubles the lockout delay (max 60s).
 * A successful login clears the backoff state for that IP.
 */

const backoffStore = new Map(); // ip -> { count, blockedUntil }

const MAX_DELAY_MS = 60000;

export function checkLoginBackoff(ip) {
  const record = backoffStore.get(ip);
  if (record) {
    const now = Date.now();
    if (now < record.blockedUntil) {
      const remainingMs = record.blockedUntil - now;
      return {
        blocked: true,
        remainingMs,
        remainingSeconds: Math.ceil(remainingMs / 1000),
        failureCount: record.count
      };
    }
  }
  return { blocked: false, failureCount: record?.count ?? 0 };
}

export function recordLoginFailure(ip) {
  const existing = backoffStore.get(ip);
  const count = (existing?.count ?? 0) + 1;
  // Exponential: 1s, 2s, 4s, 8s, 16s, 32s, 60s...
  const delay = Math.min(1000 * Math.pow(2, count - 1), MAX_DELAY_MS);
  const blockedUntil = Date.now() + delay;

  backoffStore.set(ip, { count, blockedUntil });

  return { count, delayMs: delay, blockedUntil };
}

export function clearLoginBackoff(ip) {
  backoffStore.delete(ip);
}

/** For testing: peek internal state */
export function _getBackoffState(ip) {
  return backoffStore.get(ip) ?? null;
}

/** For testing: reset all state */
export function _resetBackoffState() {
  backoffStore.clear();
}

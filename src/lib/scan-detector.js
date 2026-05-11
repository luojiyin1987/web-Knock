/**
 * Scan detector.
 * Detects brute-force scanning patterns by tracking failed login attempts
 * within a rolling time window. If an IP exceeds the threshold, it is
 * flagged as a scanner, which callers can use to escalate response.
 */

const failureWindows = new Map(); // ip -> [timestamp, ...]

const WINDOW_MS = 60000; // 60 seconds
const THRESHOLD = 5;     // 5 failures within window = scanning

export function recordScanFailure(ip) {
  const now = Date.now();
  let timestamps = failureWindows.get(ip) || [];
  // Keep only failures within the window
  timestamps = timestamps.filter((t) => now - t < WINDOW_MS);
  timestamps.push(now);
  failureWindows.set(ip, timestamps);

  return {
    failureCount: timestamps.length,
    isScanning: timestamps.length >= THRESHOLD
  };
}

export function getScanStatus(ip) {
  const now = Date.now();
  const timestamps = (failureWindows.get(ip) || []).filter(
    (t) => now - t < WINDOW_MS
  );
  return {
    failureCount: timestamps.length,
    isScanning: timestamps.length >= THRESHOLD
  };
}

export function clearScanFailures(ip) {
  failureWindows.delete(ip);
}

/** For testing: peek internal state */
export function _getScanState(ip) {
  const now = Date.now();
  return (failureWindows.get(ip) || []).filter((t) => now - t < WINDOW_MS);
}

/** For testing: reset all state */
export function _resetScanState() {
  failureWindows.clear();
}

/**
 * Backward-compatible password API.
 * Delegates to the plugin-based password-algorithms module.
 */

import { createPasswordRecord as createRecord, verifyPassword as verify } from "./password-algorithms.js";

export async function createPasswordRecord(password, algorithm = "scrypt") {
  return createRecord(algorithm, password);
}

export async function verifyPassword(password, passwordRecord) {
  return verify(password, passwordRecord);
}

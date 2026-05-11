import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const KEY_LENGTH = 64;

export function createPasswordRecord(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, KEY_LENGTH).toString("hex");

  return {
    algorithm: "scrypt",
    salt,
    hash
  };
}

export function verifyPassword(password, passwordRecord) {
  if (!passwordRecord?.salt || !passwordRecord?.hash) {
    return false;
  }

  const candidate = scryptSync(password, passwordRecord.salt, KEY_LENGTH);
  const expected = Buffer.from(passwordRecord.hash, "hex");

  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(candidate, expected);
}

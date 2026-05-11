import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const KEY_LENGTH = 64;
const scryptAsync = promisify(scrypt);

export async function createPasswordRecord(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = (await scryptAsync(password, salt, KEY_LENGTH)).toString("hex");

  return {
    algorithm: "scrypt",
    salt,
    hash
  };
}

export async function verifyPassword(password, passwordRecord) {
  if (!passwordRecord?.salt || !passwordRecord?.hash) {
    return false;
  }

  const candidate = await scryptAsync(password, passwordRecord.salt, KEY_LENGTH);
  const expected = Buffer.from(passwordRecord.hash, "hex");

  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(candidate, expected);
}

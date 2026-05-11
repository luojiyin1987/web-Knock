import { randomBytes, scrypt, pbkdf2, createHmac, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const pbkdf2Async = promisify(pbkdf2);

const SCRYPT_KEY_LENGTH = 64;
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_LENGTH = 64;

const algorithms = new Map();

export function registerAlgorithm(name, { create, verify }) {
  algorithms.set(name, { create, verify });
}

export async function createPasswordRecord(algorithm, password) {
  const impl = algorithms.get(algorithm);
  if (!impl) {
    throw new Error(`Unknown password algorithm: ${algorithm}`);
  }
  return { algorithm, ...(await impl.create(password)) };
}

export async function verifyPassword(password, passwordRecord) {
  if (!passwordRecord?.algorithm) {
    return false;
  }
  const impl = algorithms.get(passwordRecord.algorithm);
  if (!impl) {
    return false;
  }
  return impl.verify(password, passwordRecord);
}

export function listAlgorithms() {
  return Array.from(algorithms.keys());
}

// ─── Built-in algorithms ───

registerAlgorithm("scrypt", {
  async create(password) {
    const salt = randomBytes(16).toString("hex");
    const hash = (await scryptAsync(password, salt, SCRYPT_KEY_LENGTH)).toString("hex");
    return { salt, hash };
  },
  async verify(password, record) {
    if (!record?.salt || !record?.hash) return false;
    const candidate = await scryptAsync(password, record.salt, SCRYPT_KEY_LENGTH);
    const expected = Buffer.from(record.hash, "hex");
    if (candidate.length !== expected.length) return false;
    return timingSafeEqual(candidate, expected);
  }
});

registerAlgorithm("pbkdf2", {
  async create(password) {
    const salt = randomBytes(16).toString("hex");
    const hash = (await pbkdf2Async(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH, "sha512")).toString("hex");
    return { salt, hash };
  },
  async verify(password, record) {
    if (!record?.salt || !record?.hash) return false;
    const candidate = await pbkdf2Async(password, record.salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH, "sha512");
    const expected = Buffer.from(record.hash, "hex");
    if (candidate.length !== expected.length) return false;
    return timingSafeEqual(candidate, expected);
  }
});

registerAlgorithm("hmac-sha512", {
  async create(password) {
    const salt = randomBytes(32).toString("hex");
    const hash = createHmac("sha512", salt).update(password).digest("hex");
    return { salt, hash };
  },
  async verify(password, record) {
    if (!record?.salt || !record?.hash) return false;
    const candidate = createHmac("sha512", record.salt).update(password).digest();
    const expected = Buffer.from(record.hash, "hex");
    if (candidate.length !== expected.length) return false;
    return timingSafeEqual(candidate, expected);
  }
});

registerAlgorithm("plaintext", {
  async create(password) {
    return { hash: password };
  },
  async verify(password, record) {
    return record?.hash === password;
  }
});

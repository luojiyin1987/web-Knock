import { randomBytes } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

function secretToUint8(secret) {
  return new TextEncoder().encode(secret);
}

export function createTokenId() {
  return randomBytes(12).toString("hex");
}

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export async function signAccessToken(claims, secret) {
  const key = secretToUint8(secret);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(claims.iat)
    .setExpirationTime(claims.exp)
    .sign(key);
}

export async function verifyAccessToken(token, secret) {
  if (!token || typeof token !== "string") {
    return null;
  }

  try {
    const key = secretToUint8(secret);
    const { payload } = await jwtVerify(token, key, {
      clockTolerance: 5
    });
    return payload;
  } catch {
    return null;
  }
}

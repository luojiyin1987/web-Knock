import { createHmac, randomBytes } from "node:crypto";

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value) {
  return Buffer.from(value, "base64url").toString();
}

function signSegment(input, secret) {
  return createHmac("sha256", secret).update(input).digest("base64url");
}

export function createTokenId() {
  return randomBytes(12).toString("hex");
}

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export function signAccessToken(claims, secret) {
  const header = encodeBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = encodeBase64Url(JSON.stringify(claims));
  const signature = signSegment(`${header}.${payload}`, secret);

  return `${header}.${payload}.${signature}`;
}

export function verifyAccessToken(token, secret) {
  if (!token || typeof token !== "string") {
    return null;
  }

  const segments = token.split(".");

  if (segments.length !== 3) {
    return null;
  }

  const [header, payload, signature] = segments;
  const expected = signSegment(`${header}.${payload}`, secret);

  if (signature !== expected) {
    return null;
  }

  try {
    const claims = JSON.parse(decodeBase64Url(payload));
    const now = Math.floor(Date.now() / 1000);

    if (!claims.exp || now >= claims.exp) {
      return null;
    }

    return claims;
  } catch {
    return null;
  }
}

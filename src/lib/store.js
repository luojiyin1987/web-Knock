import { createHash } from "node:crypto";
import { createOpaqueToken, createTokenId, signAccessToken, verifyAccessToken } from "./tokens.js";

function digestToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function createAuthStore(config) {
  const clients = new Map(config.clients.map((client) => [client.id, client]));
  const users = new Map(config.users.map((user) => [user.username, user]));
  const refreshTokens = new Map();
  const revokedAccessTokens = new Map();
  const sessions = new Map();

  function getClient(clientId) {
    return clients.get(clientId) ?? null;
  }

  function validateClient(clientId, clientSecret) {
    const client = getClient(clientId);
    if (!client || client.secret !== clientSecret) {
      return null;
    }
    return client;
  }

  function getUserByUsername(username) {
    return users.get(username) ?? null;
  }

  function purgeExpiredRevocations() {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, expiresAt] of revokedAccessTokens.entries()) {
      if (now >= expiresAt) {
        revokedAccessTokens.delete(jti);
      }
    }
  }

  function purgeExpiredSessions() {
    const now = Math.floor(Date.now() / 1000);
    for (const [sid, session] of sessions.entries()) {
      if (now >= session.expiresAt) {
        sessions.delete(sid);
      }
    }
  }

  function createSession({ client, user, scope }) {
    purgeExpiredSessions();
    const now = Math.floor(Date.now() / 1000);
    const sessionId = createOpaqueToken();
    sessions.set(sessionId, {
      userId: user.id,
      username: user.username,
      displayName: user.displayName,
      roles: user.roles,
      clientId: client.id,
      scope,
      createdAt: now,
      expiresAt: now + (config.sessionTtlSeconds || 86400)
    });
    return sessionId;
  }

  function verifySession(sessionId) {
    purgeExpiredSessions();
    const session = sessions.get(sessionId);
    if (!session) return null;
    const now = Math.floor(Date.now() / 1000);
    if (now >= session.expiresAt) {
      sessions.delete(sessionId);
      return null;
    }
    return {
      iss: config.issuer,
      sub: session.userId,
      aud: session.clientId,
      client_id: session.clientId,
      preferred_username: session.username,
      name: session.displayName,
      roles: session.roles,
      scope: session.scope
    };
  }

  function destroySession(sessionId) {
    return sessions.delete(sessionId);
  }

  async function issueTokens({ client, user, requestedScopes = [] }) {
    purgeExpiredRevocations();

    const now = Math.floor(Date.now() / 1000);
    const scope =
      requestedScopes.length > 0
        ? requestedScopes.filter((item) => client.scopes.includes(item))
        : client.scopes;
    const accessJti = createTokenId();
    const refreshToken = createOpaqueToken();
    const refreshTokenId = digestToken(refreshToken);
    const accessToken = await signAccessToken(
      {
        iss: config.issuer,
        sub: user.id,
        aud: client.id,
        client_id: client.id,
        preferred_username: user.username,
        name: user.displayName,
        roles: user.roles,
        scope,
        typ: "access",
        jti: accessJti,
        iat: now,
        exp: now + config.accessTtlSeconds
      },
      config.tokenSecret
    );

    refreshTokens.set(refreshTokenId, {
      tokenId: refreshTokenId,
      clientId: client.id,
      userId: user.id,
      username: user.username,
      scope,
      expiresAt: now + config.refreshTtlSeconds
    });

    return {
      accessToken,
      refreshToken,
      tokenType: "Bearer",
      expiresIn: config.accessTtlSeconds,
      scope,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        roles: user.roles
      }
    };
  }

  async function verifyToken(token) {
    purgeExpiredRevocations();
    const claims = await verifyAccessToken(token, config.tokenSecret);

    if (!claims) {
      return null;
    }

    if (claims.jti && revokedAccessTokens.has(claims.jti)) {
      return null;
    }

    return claims;
  }

  async function rotateRefreshToken({ client, refreshToken }) {
    const now = Math.floor(Date.now() / 1000);
    const tokenId = digestToken(refreshToken);
    const existing = refreshTokens.get(tokenId);

    if (!existing || existing.clientId !== client.id || now >= existing.expiresAt) {
      return null;
    }

    refreshTokens.delete(tokenId);
    const user = Array.from(users.values()).find((candidate) => candidate.id === existing.userId);

    if (!user) {
      return null;
    }

    return issueTokens({
      client,
      user,
      requestedScopes: existing.scope
    });
  }

  function revokeRefreshToken(refreshToken) {
    if (!refreshToken) {
      return false;
    }
    return refreshTokens.delete(digestToken(refreshToken));
  }

  async function revokeAccessToken(token) {
    const claims = await verifyAccessToken(token, config.tokenSecret);

    if (!claims?.jti || !claims.exp) {
      return false;
    }

    revokedAccessTokens.set(claims.jti, claims.exp);
    return true;
  }

  return {
    getClient,
    getUserByUsername,
    issueTokens,
    validateClient,
    verifyToken,
    rotateRefreshToken,
    revokeRefreshToken,
    revokeAccessToken,
    createSession,
    verifySession,
    destroySession
  };
}

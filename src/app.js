import http from "node:http";
import { z } from "zod";
import { loadConfig } from "./config.js";
import {
  sendJson,
  sendEmpty,
  readJsonBody,
  getBearerToken,
  sendStaticAsset,
  applyCors
} from "./lib/http.js";
import { createPasswordRecord, verifyPassword } from "./lib/passwords.js";
import { createAuthStore } from "./lib/store.js";
import {
  loginSchema,
  refreshSchema,
  introspectSchema,
  logoutSchema
} from "./lib/validators.js";
import { getClientIp, normalizeIp } from "./lib/ip-utils.js";
import { checkLoginBackoff, recordLoginFailure, clearLoginBackoff } from "./lib/login-backoff.js";

async function normalizeUsers(rawUsers, algorithm) {
  return Promise.all(
    rawUsers.map(async (user) => {
      if (user.passwordRecord) return user;
      if (!user.password) {
        throw new Error(`User ${user.username} is missing password or passwordRecord`);
      }
      return { ...user, passwordRecord: await createPasswordRecord(user.password, algorithm) };
    })
  );
}

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    roles: user.roles
  };
}

function sanitizeClient(client) {
  return {
    id: client.id,
    name: client.name,
    scopes: client.scopes
  };
}

async function handleLogin(authStore, request, body, config) {
  const clientIp = normalizeIp(getClientIp(request, { trustProxy: config.trustProxy }));

  // 1. Check exponential backoff
  const backoff = checkLoginBackoff(clientIp);
  if (backoff.blocked) {
    return {
      status: 429,
      body: {
        error: "login_backoff",
        message: `Too many failed attempts. Retry after ${backoff.remainingSeconds}s.`
      }
    };
  }

  const parsed = loginSchema.parse(body);
  const client = authStore.validateClient(parsed.clientId, parsed.clientSecret);
  if (!client) {
    recordLoginFailure(clientIp);
    return {
      status: 401,
      body: { error: "invalid_client", message: "Client credentials are invalid." }
    };
  }

  const user = authStore.getUserByUsername(parsed.username);
  if (!user || !(await verifyPassword(parsed.password ?? "", user.passwordRecord))) {
    recordLoginFailure(clientIp);
    return {
      status: 401,
      body: { error: "invalid_credentials", message: "Username or password is invalid." }
    };
  }

  // Successful login: clear security state for this IP
  clearLoginBackoff(clientIp);

  const tokens = await authStore.issueTokens({
    client,
    user,
    requestedScopes: Array.isArray(parsed.scope) ? parsed.scope : []
  });

  return { status: 200, body: tokens };
}

async function handleRefresh(authStore, body) {
  const parsed = refreshSchema.parse(body);
  const client = authStore.validateClient(parsed.clientId, parsed.clientSecret);
  if (!client) {
    return {
      status: 401,
      body: { error: "invalid_client", message: "Client credentials are invalid." }
    };
  }

  const nextTokens = await authStore.rotateRefreshToken({
    client,
    refreshToken: parsed.refreshToken
  });

  if (!nextTokens) {
    return {
      status: 401,
      body: { error: "invalid_refresh_token", message: "Refresh token is invalid or expired." }
    };
  }

  return { status: 200, body: nextTokens };
}

async function handleIntrospect(authStore, body) {
  const parsed = introspectSchema.parse(body);
  const client = authStore.validateClient(parsed.clientId, parsed.clientSecret);
  if (!client) {
    return {
      status: 401,
      body: { error: "invalid_client", message: "Client credentials are invalid." }
    };
  }

  const claims = await authStore.verifyToken(parsed.token);
  if (!claims) {
    return { status: 200, body: { active: false } };
  }

  return {
    status: 200,
    body: {
      active: true,
      iss: claims.iss,
      sub: claims.sub,
      aud: claims.aud,
      exp: claims.exp,
      iat: claims.iat,
      client_id: claims.client_id,
      username: claims.preferred_username,
      name: claims.name,
      roles: claims.roles,
      scope: claims.scope
    }
  };
}

async function handleSession(authStore, request) {
  const token = getBearerToken(request);
  const claims = await authStore.verifyToken(token);
  if (!claims) {
    return {
      status: 401,
      body: { error: "invalid_token", message: "Access token is invalid or expired." }
    };
  }

  return {
    status: 200,
    body: {
      authenticated: true,
      session: {
        user: {
          id: claims.sub,
          username: claims.preferred_username,
          displayName: claims.name,
          roles: claims.roles
        },
        clientId: claims.client_id,
        scope: claims.scope,
        expiresAt: claims.exp
      }
    }
  };
}

async function handleLogout(authStore, request, body) {
  const parsed = logoutSchema.parse(body);
  const bearerToken = getBearerToken(request);
  const accessToken = parsed.accessToken ?? bearerToken;

  if (!parsed.refreshToken && !accessToken) {
    return {
      status: 400,
      body: {
        error: "validation_error",
        message: "Either refreshToken, accessToken, or Authorization Bearer token must be provided."
      }
    };
  }

  const refreshRevoked = authStore.revokeRefreshToken(parsed.refreshToken);
  const accessRevoked = await authStore.revokeAccessToken(accessToken);

  return { status: 200, body: { revoked: refreshRevoked || accessRevoked } };
}

export async function createKnockServer(overrides = {}) {
  const baseConfig = loadConfig();
  const config = {
    ...baseConfig,
    ...overrides,
    clients: overrides.clients ?? baseConfig.clients,
    users: await normalizeUsers(overrides.users ?? baseConfig.users, baseConfig.passwordAlgorithm),
    allowedOrigins: overrides.allowedOrigins ?? baseConfig.allowedOrigins
  };
  const authStore = createAuthStore(config);

  const routes = [
    {
      method: "GET",
      path: "/healthz",
      handler: async () => ({
        status: 200,
        body: { status: "ok", issuer: config.issuer, now: new Date().toISOString() }
      })
    },
    { method: "GET", path: "/", handler: async () => ({ static: "index.html" }) },
    { method: "GET", path: "/styles.css", handler: async () => ({ static: "styles.css" }) },
    { method: "GET", path: "/app.js", handler: async () => ({ static: "app.js" }) },
    {
      method: "POST",
      path: "/v1/auth/login",
      handler: async (req, body) => handleLogin(authStore, req, body, config)
    },
    {
      method: "POST",
      path: "/v1/auth/refresh",
      handler: async (_req, body) => handleRefresh(authStore, body)
    },
    {
      method: "POST",
      path: "/v1/auth/introspect",
      handler: async (_req, body) => handleIntrospect(authStore, body)
    },
    {
      method: "GET",
      path: "/v1/auth/session",
      handler: async (req) => handleSession(authStore, req)
    },
    {
      method: "POST",
      path: "/v1/auth/logout",
      handler: async (req, body) => handleLogout(authStore, req, body)
    }
  ];

  const server = http.createServer(async (request, response) => {
    try {
      applyCors(request, response, config.allowedOrigins);

      if (request.method === "OPTIONS") {
        sendEmpty(response, 204);
        return;
      }

      const url = new URL(
        request.url,
        `http://${request.headers.host ?? "localhost"}`
      );

      const route = routes.find(
        (r) => r.method === request.method && r.path === url.pathname
      );

      if (!route) {
        sendJson(response, 404, {
          error: "not_found",
          message: `No route for ${request.method} ${url.pathname}`
        });
        return;
      }

      let body = {};
      if (request.method === "POST") {
        body = await readJsonBody(request);
      }

      const result = await route.handler(request, body);

      if (result.static) {
        await sendStaticAsset(response, result.static);
      } else {
        sendJson(response, result.status, result.body);
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        const issues = error.issues || error.errors || [];
        sendJson(response, 400, {
          error: "validation_error",
          message: issues.map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")
        });
        return;
      }

      if (error.statusCode) {
        sendJson(response, error.statusCode, {
          error: "bad_request",
          message: error.message
        });
        return;
      }

      console.error("Internal error:", error);
      sendJson(response, 500, {
        error: "internal_error",
        message: error.message
      });
    }
  });

  return {
    server,
    config,
    demo: {
      clients: config.clients.map(sanitizeClient),
      users: config.users.map(sanitizeUser)
    }
  };
}

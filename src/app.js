import http from "node:http";
import { loadConfig } from "./config.js";
import { sendJson, sendEmpty, readJsonBody, getBearerToken, sendStaticAsset, applyCors } from "./lib/http.js";
import { createPasswordRecord, verifyPassword } from "./lib/passwords.js";
import { createAuthStore } from "./lib/store.js";

function normalizeUsers(rawUsers) {
  return rawUsers.map((user) => {
    if (user.passwordRecord) {
      return user;
    }

    if (!user.password) {
      throw new Error(`User ${user.username} is missing password or passwordRecord`);
    }

    return {
      ...user,
      passwordRecord: createPasswordRecord(user.password)
    };
  });
}

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    roles: user.roles
  };
}

export function createKnockServer(overrides = {}) {
  const baseConfig = loadConfig();
  const config = {
    ...baseConfig,
    ...overrides,
    clients: overrides.clients ?? baseConfig.clients,
    users: normalizeUsers(overrides.users ?? baseConfig.users),
    allowedOrigins: overrides.allowedOrigins ?? baseConfig.allowedOrigins
  };
  const authStore = createAuthStore(config);

  const server = http.createServer(async (request, response) => {
    try {
      applyCors(request, response, config.allowedOrigins);

      if (request.method === "OPTIONS") {
        sendEmpty(response, 204);
        return;
      }

      const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);

      if (request.method === "GET" && url.pathname === "/healthz") {
        sendJson(response, 200, {
          status: "ok",
          issuer: config.issuer,
          now: new Date().toISOString()
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/") {
        await sendStaticAsset(response, "index.html");
        return;
      }

      if (request.method === "GET" && url.pathname === "/styles.css") {
        await sendStaticAsset(response, "styles.css");
        return;
      }

      if (request.method === "GET" && url.pathname === "/app.js") {
        await sendStaticAsset(response, "app.js");
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/auth/login") {
        const body = await readJsonBody(request);
        const client = authStore.validateClient(body.clientId, body.clientSecret);

        if (!client) {
          sendJson(response, 401, { error: "invalid_client", message: "Client credentials are invalid." });
          return;
        }

        const user = authStore.getUserByUsername(body.username);

        if (!user || !verifyPassword(body.password ?? "", user.passwordRecord)) {
          sendJson(response, 401, { error: "invalid_credentials", message: "Username or password is invalid." });
          return;
        }

        const tokens = authStore.issueTokens({
          client,
          user,
          requestedScopes: Array.isArray(body.scope) ? body.scope : []
        });

        sendJson(response, 200, tokens);
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/auth/refresh") {
        const body = await readJsonBody(request);
        const client = authStore.validateClient(body.clientId, body.clientSecret);

        if (!client) {
          sendJson(response, 401, { error: "invalid_client", message: "Client credentials are invalid." });
          return;
        }

        const nextTokens = authStore.rotateRefreshToken({
          client,
          refreshToken: body.refreshToken
        });

        if (!nextTokens) {
          sendJson(response, 401, { error: "invalid_refresh_token", message: "Refresh token is invalid or expired." });
          return;
        }

        sendJson(response, 200, nextTokens);
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/auth/introspect") {
        const body = await readJsonBody(request);
        const client = authStore.validateClient(body.clientId, body.clientSecret);

        if (!client) {
          sendJson(response, 401, { error: "invalid_client", message: "Client credentials are invalid." });
          return;
        }

        const claims = authStore.verifyToken(body.token);

        if (!claims) {
          sendJson(response, 200, { active: false });
          return;
        }

        sendJson(response, 200, {
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
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/v1/auth/session") {
        const token = getBearerToken(request);
        const claims = authStore.verifyToken(token);

        if (!claims) {
          sendJson(response, 401, { error: "invalid_token", message: "Access token is invalid or expired." });
          return;
        }

        sendJson(response, 200, {
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
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/auth/logout") {
        const body = await readJsonBody(request);
        const bearerToken = getBearerToken(request);

        const refreshRevoked = authStore.revokeRefreshToken(body.refreshToken);
        const accessRevoked = authStore.revokeAccessToken(body.accessToken ?? bearerToken);

        sendJson(response, 200, {
          revoked: refreshRevoked || accessRevoked
        });
        return;
      }

      sendJson(response, 404, {
        error: "not_found",
        message: `No route for ${request.method} ${url.pathname}`
      });
    } catch (error) {
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
      clients: config.clients.map(({ id, name, secret }) => ({ id, name, secret })),
      users: config.users.map(sanitizeUser)
    }
  };
}

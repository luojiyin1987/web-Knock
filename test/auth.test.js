import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createKnockServer } from "../src/app.js";

async function startTestServer() {
  const { server } = createKnockServer({
    port: 0,
    issuer: "knock.test",
    tokenSecret: "test-secret",
    clients: [
      {
        id: "dashboard-web",
        secret: "dashboard-secret",
        name: "Dashboard Web",
        scopes: ["profile", "introspect"]
      },
      {
        id: "internal-api",
        secret: "internal-secret",
        name: "Internal API",
        scopes: ["introspect"]
      }
    ],
    users: [
      {
        id: "user-alice",
        username: "alice",
        password: "knock-knock",
        displayName: "Alice Chen",
        roles: ["admin"]
      }
    ]
  });

  server.listen(0);
  await once(server, "listening");
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    server,
    baseUrl
  };
}

test("login, session, refresh, introspect, and logout flow works", async () => {
  const { server, baseUrl } = await startTestServer();

  try {
    const loginResponse = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });

    assert.equal(loginResponse.status, 200);
    const loginPayload = await loginResponse.json();
    assert.ok(loginPayload.accessToken);
    assert.ok(loginPayload.refreshToken);
    assert.equal(loginPayload.user.username, "alice");

    const sessionResponse = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: {
        authorization: `Bearer ${loginPayload.accessToken}`
      }
    });

    assert.equal(sessionResponse.status, 200);
    const sessionPayload = await sessionResponse.json();
    assert.equal(sessionPayload.session.user.username, "alice");

    const introspectResponse = await fetch(`${baseUrl}/v1/auth/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "internal-api",
        clientSecret: "internal-secret",
        token: loginPayload.accessToken
      })
    });

    assert.equal(introspectResponse.status, 200);
    const introspectPayload = await introspectResponse.json();
    assert.equal(introspectPayload.active, true);
    assert.equal(introspectPayload.username, "alice");

    const refreshResponse = await fetch(`${baseUrl}/v1/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        refreshToken: loginPayload.refreshToken
      })
    });

    assert.equal(refreshResponse.status, 200);
    const refreshPayload = await refreshResponse.json();
    assert.ok(refreshPayload.accessToken);
    assert.notEqual(refreshPayload.refreshToken, loginPayload.refreshToken);

    const logoutResponse = await fetch(`${baseUrl}/v1/auth/logout`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${refreshPayload.accessToken}`
      },
      body: JSON.stringify({
        refreshToken: refreshPayload.refreshToken
      })
    });

    assert.equal(logoutResponse.status, 200);
    const logoutPayload = await logoutResponse.json();
    assert.equal(logoutPayload.revoked, true);

    const revokedSessionResponse = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: {
        authorization: `Bearer ${refreshPayload.accessToken}`
      }
    });

    assert.equal(revokedSessionResponse.status, 401);
  } finally {
    server.close();
  }
});

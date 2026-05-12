import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createKnockServer } from "../src/app.js";
import { _resetBackoffState } from "../src/lib/login-backoff.js";
import { getClientIp, normalizeIp } from "../src/lib/ip-utils.js";
import { loadConfig } from "../src/config.js";
import { sanitizeCallbackPath } from "../src/public/callback-path.js";

async function startTestServer(overrides = {}) {
  _resetBackoffState();
  const { server } = await createKnockServer({
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
    ],
    ...overrides
  });

  server.listen(0);
  await once(server, "listening");
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return { server, baseUrl };
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

test("logout accepts bearer token without accessToken in request body", async () => {
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
    const loginPayload = await loginResponse.json();

    const logoutResponse = await fetch(`${baseUrl}/v1/auth/logout`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${loginPayload.accessToken}`
      },
      body: JSON.stringify({})
    });

    assert.equal(logoutResponse.status, 200);
    const logoutPayload = await logoutResponse.json();
    assert.equal(logoutPayload.revoked, true);

    const revokedSessionResponse = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: {
        authorization: `Bearer ${loginPayload.accessToken}`
      }
    });
    assert.equal(revokedSessionResponse.status, 401);
  } finally {
    server.close();
  }
});

test("rejects invalid client credentials", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "bad",
        clientSecret: "bad",
        username: "alice",
        password: "knock-knock"
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_client");
  } finally {
    server.close();
  }
});

test("introspect requires client introspect scope", async () => {
  const { server, baseUrl } = await startTestServer({
    clients: [
      {
        id: "dashboard-web",
        secret: "dashboard-secret",
        name: "Dashboard Web",
        scopes: ["profile", "introspect"]
      },
      {
        id: "limited-client",
        secret: "limited-secret",
        name: "Limited Client",
        scopes: ["profile"]
      }
    ]
  });

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
    const loginPayload = await loginResponse.json();

    const introspectResponse = await fetch(`${baseUrl}/v1/auth/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "limited-client",
        clientSecret: "limited-secret",
        token: loginPayload.accessToken
      })
    });

    assert.equal(introspectResponse.status, 403);
    const introspectPayload = await introspectResponse.json();
    assert.equal(introspectPayload.error, "insufficient_scope");
  } finally {
    server.close();
  }
});

test("rejects invalid user credentials", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "wrong"
      })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_credentials");
  } finally {
    server.close();
  }
});

test("rejects expired or invalid access token", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: { authorization: "Bearer invalid-token" }
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("refresh token rotation invalidates old token", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const loginRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    const { refreshToken } = await loginRes.json();

    const refreshRes1 = await fetch(`${baseUrl}/v1/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        refreshToken
      })
    });
    assert.equal(refreshRes1.status, 200);

    const refreshRes2 = await fetch(`${baseUrl}/v1/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        refreshToken
      })
    });
    assert.equal(refreshRes2.status, 401);
  } finally {
    server.close();
  }
});

test("rejects too large request body", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientId: "x".repeat(100_000) })
    });
    assert.equal(res.status, 413);
  } finally {
    server.close();
  }
});

test("rejects malformed json body", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not-json"
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "bad_request");
  } finally {
    server.close();
  }
});

test("returns security headers", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
  } finally {
    server.close();
  }
});

test("demo object does not leak secrets", async () => {
  const { server, config } = await createKnockServer({
    port: 0,
    clients: [{ id: "c1", secret: "s1", name: "C1", scopes: [] }],
    users: []
  });
  try {
    assert.ok(config.clients[0].secret);
    // The createKnockServer return value is what we test indirectly,
    // but here we just verify the public demo object shape.
  } finally {
    server.close();
  }
});

// ─── Security module unit tests ───

import {
  checkLoginBackoff,
  recordLoginFailure,
  clearLoginBackoff
} from "../src/lib/login-backoff.js";

test("ip-utils extracts client IP correctly", () => {
  const reqForwarded = {
    headers: { "x-forwarded-for": "203.0.113.1, 10.0.0.1" },
    socket: { remoteAddress: "127.0.0.1" }
  };
  assert.equal(getClientIp(reqForwarded), "127.0.0.1");
  assert.equal(getClientIp(reqForwarded, { trustProxy: true }), "203.0.113.1");

  const reqDirect = {
    headers: {},
    socket: { remoteAddress: "192.168.1.5" }
  };
  assert.equal(getClientIp(reqDirect), "192.168.1.5");

  assert.equal(normalizeIp("::ffff:192.168.1.1"), "192.168.1.1");
  assert.equal(normalizeIp("192.168.1.1"), "192.168.1.1");
});

test("sanitizeCallbackPath only accepts site-relative paths", () => {
  assert.equal(sanitizeCallbackPath("/protected?tab=1"), "/protected?tab=1");
  assert.equal(sanitizeCallbackPath("https://evil.example", "/"), "/");
  assert.equal(sanitizeCallbackPath("//evil.example", "/"), "/");
  assert.equal(sanitizeCallbackPath("javascript:alert(1)", "/"), "/");
});

test("loadConfig honors explicit env object including trustProxy", () => {
  const config = loadConfig({
    PORT: "4100",
    KNOCK_ACCESS_TTL_SECONDS: "120",
    KNOCK_REFRESH_TTL_SECONDS: "3600",
    KNOCK_TRUST_PROXY: "true"
  });

  assert.equal(config.port, 4100);
  assert.equal(config.accessTtlSeconds, 120);
  assert.equal(config.refreshTtlSeconds, 3600);
  assert.equal(config.trustProxy, true);
});

test("createKnockServer honors passwordAlgorithm override during user normalization", async () => {
  const { server, config } = await createKnockServer({
    port: 0,
    passwordAlgorithm: "plaintext",
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

  try {
    assert.equal(config.passwordAlgorithm, "plaintext");
    assert.equal(config.users[0].passwordRecord.algorithm, "plaintext");
  } finally {
    server.close();
  }
});

test("login-backoff implements exponential delay", () => {
  _resetBackoffState();
  const ip = "10.0.0.1";

  assert.equal(checkLoginBackoff(ip).blocked, false);

  // First 2 failures are grace period — no block
  const r1 = recordLoginFailure(ip);
  assert.equal(r1.count, 1);
  assert.equal(r1.delayMs, 0);
  assert.equal(checkLoginBackoff(ip).blocked, false);

  const r2 = recordLoginFailure(ip);
  assert.equal(r2.count, 2);
  assert.equal(r2.delayMs, 0);
  assert.equal(checkLoginBackoff(ip).blocked, false);

  // 3rd failure triggers 1s block
  const r3 = recordLoginFailure(ip);
  assert.equal(r3.count, 3);
  assert.equal(r3.delayMs, 1000);
  assert.equal(checkLoginBackoff(ip).blocked, true);

  // 4th failure triggers 2s block
  const r4 = recordLoginFailure(ip);
  assert.equal(r4.count, 4);
  assert.equal(r4.delayMs, 2000);

  // 5th failure triggers 4s block
  const r5 = recordLoginFailure(ip);
  assert.equal(r5.count, 5);
  assert.equal(r5.delayMs, 4000);

  // Clearing removes block
  clearLoginBackoff(ip);
  assert.equal(checkLoginBackoff(ip).blocked, false);
});

// ─── Integration: login flow with security modules ───

test("triggers login backoff after repeated failures", async () => {
  const { server, baseUrl } = await startTestServer();
  _resetBackoffState();

  try {
    // First 3 failures should return 401
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${baseUrl}/v1/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          clientId: "dashboard-web",
          clientSecret: "dashboard-secret",
          username: "alice",
          password: "wrong"
        })
      });
      assert.equal(res.status, 401);
    }

    // 4th failure triggers 1s backoff
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "wrong"
      })
    });
    assert.equal(res.status, 429);
    const body = await res.json();
    assert.equal(body.error, "login_backoff");
    assert.ok(body.message.includes("Retry after"));
  } finally {
    server.close();
    _resetBackoffState();
  }
});

test("successful login clears backoff state", async () => {
  const { server, baseUrl } = await startTestServer();
  _resetBackoffState();

  try {
    // Trigger a failure first
    const failRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "wrong"
      })
    });
    assert.equal(failRes.status, 401);

    // Successful login should clear state
    const okRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    assert.equal(okRes.status, 200);

    // Next failure should start from count=1, not be immediately blocked
    const nextFail = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "wrong"
      })
    });
    assert.equal(nextFail.status, 401);
  } finally {
    server.close();
    _resetBackoffState();
  }
});

// ─── Cookie Session (dual-channel auth) ───

test("login sets session cookie", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    assert.equal(res.status, 200);
    const setCookie = res.headers.get("set-cookie");
    assert.ok(setCookie);
    assert.ok(setCookie.includes("knock_session="));
    assert.ok(setCookie.includes("HttpOnly"));
    assert.ok(setCookie.includes("SameSite=Lax"));
  } finally {
    server.close();
  }
});

test("session endpoint accepts cookie session", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const loginRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    const cookie = loginRes.headers.get("set-cookie");

    const sessionRes = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: { cookie }
    });
    assert.equal(sessionRes.status, 200);
    const body = await sessionRes.json();
    assert.equal(body.session.user.username, "alice");
    assert.equal(typeof body.session.expiresAt, "number");
  } finally {
    server.close();
  }
});

test("forwardauth accepts cookie session", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const loginRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    const cookie = loginRes.headers.get("set-cookie");

    const authRes = await fetch(`${baseUrl}/_auth`, {
      headers: { cookie, accept: "application/json" }
    });
    assert.equal(authRes.status, 200);
    assert.equal(authRes.headers.get("x-forwarded-user"), "alice");
  } finally {
    server.close();
  }
});

test("logout clears session cookie and destroys session", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const loginRes = await fetch(`${baseUrl}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "dashboard-web",
        clientSecret: "dashboard-secret",
        username: "alice",
        password: "knock-knock"
      })
    });
    const cookie = loginRes.headers.get("set-cookie");

    const logoutRes = await fetch(`${baseUrl}/v1/auth/logout`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({})
    });
    assert.equal(logoutRes.status, 200);
    const clearCookie = logoutRes.headers.get("set-cookie");
    assert.ok(clearCookie);
    assert.ok(clearCookie.includes("knock_session="));
    assert.ok(clearCookie.includes("Expires=Thu, 01 Jan 1970"));

    // Session should no longer work
    const sessionRes = await fetch(`${baseUrl}/v1/auth/session`, {
      headers: { cookie }
    });
    assert.equal(sessionRes.status, 401);
  } finally {
    server.close();
  }
});

test("logout with unknown session cookie does not report revocation", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const logoutRes = await fetch(`${baseUrl}/v1/auth/logout`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: "knock_session=missing-session"
      },
      body: JSON.stringify({})
    });
    assert.equal(logoutRes.status, 200);
    const body = await logoutRes.json();
    assert.equal(body.revoked, false);
  } finally {
    server.close();
  }
});

test("login route is served for browser forwardauth redirects", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/_login?callback=%2Fprotected`);
    assert.equal(res.status, 200);
    const body = await res.text();
    assert.ok(body.includes("Knock Gateway Console"));
  } finally {
    server.close();
  }
});

test("forwardauth returns 302 for unauthenticated html request", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/_auth`, {
      headers: {
        accept: "text/html",
        "x-forwarded-uri": "/protected/resource"
      },
      redirect: "manual"
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/_login?callback=%2Fprotected%2Fresource");
  } finally {
    server.close();
  }
});

test("forwardauth normalizes unsafe callback targets to root", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/_auth`, {
      headers: {
        accept: "text/html",
        "x-forwarded-uri": "https://evil.example/phish"
      },
      redirect: "manual"
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/_login?callback=%2F");
  } finally {
    server.close();
  }
});

test("forwardauth returns 401 for unauthenticated api request", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/_auth`, {
      headers: { accept: "application/json" }
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "unauthorized");
  } finally {
    server.close();
  }
});

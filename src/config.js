const DEFAULT_CLIENTS = [
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
];

const DEFAULT_USERS = [
  {
    id: "user-alice",
    username: "alice",
    password: "knock-knock",
    displayName: "Alice Chen",
    roles: ["admin"]
  },
  {
    id: "user-bob",
    username: "bob",
    password: "open-the-door",
    displayName: "Bob Li",
    roles: ["viewer"]
  }
];

function parseJsonEnv(env, name, fallback) {
  const raw = env[name];

  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${name} must be valid JSON: ${error.message}`);
  }
}

function parseNumber(env, name, fallback) {
  const raw = env[name];

  if (!raw) {
    return fallback;
  }

  const value = Number(raw);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number`);
  }

  return value;
}

function parseBoolean(env, name, fallback) {
  const raw = env[name];

  if (raw === undefined) {
    return fallback;
  }

  if (raw === "true") {
    return true;
  }

  if (raw === "false") {
    return false;
  }

  throw new Error(`${name} must be "true" or "false"`);
}

export function loadConfig(env = process.env) {
  const clients = parseJsonEnv(env, "KNOCK_CLIENTS", DEFAULT_CLIENTS);
  const users = parseJsonEnv(env, "KNOCK_USERS", DEFAULT_USERS);
  const allowedOrigins = parseJsonEnv(env, "KNOCK_ALLOWED_ORIGINS", ["*"]);

  return {
    port: parseNumber(env, "PORT", 3000),
    issuer: env.KNOCK_ISSUER ?? "knock.local",
    tokenSecret: env.KNOCK_TOKEN_SECRET ?? "dev-knock-secret-change-me",
    accessTtlSeconds: parseNumber(env, "KNOCK_ACCESS_TTL_SECONDS", 900),
    refreshTtlSeconds: parseNumber(env, "KNOCK_REFRESH_TTL_SECONDS", 604800),
    sessionTtlSeconds: parseNumber(env, "KNOCK_SESSION_TTL_SECONDS", 86400),
    trustProxy: parseBoolean(env, "KNOCK_TRUST_PROXY", false),
    passwordAlgorithm: env.KNOCK_PASSWORD_ALGORITHM ?? "scrypt",
    cookieDomain: env.KNOCK_COOKIE_DOMAIN || undefined,
    clients,
    users,
    allowedOrigins
  };
}

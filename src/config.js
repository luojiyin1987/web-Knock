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

function parseNumber(name, fallback) {
  const raw = process.env[name];

  if (!raw) {
    return fallback;
  }

  const value = Number(raw);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number`);
  }

  return value;
}

export function loadConfig(env = process.env) {
  const clients = parseJsonEnv(env, "KNOCK_CLIENTS", DEFAULT_CLIENTS);
  const users = parseJsonEnv(env, "KNOCK_USERS", DEFAULT_USERS);
  const allowedOrigins = parseJsonEnv(env, "KNOCK_ALLOWED_ORIGINS", ["*"]);

  return {
    port: parseNumber("PORT", 3000),
    issuer: env.KNOCK_ISSUER ?? "knock.local",
    tokenSecret: env.KNOCK_TOKEN_SECRET ?? "dev-knock-secret-change-me",
    accessTtlSeconds: parseNumber("KNOCK_ACCESS_TTL_SECONDS", 900),
    refreshTtlSeconds: parseNumber("KNOCK_REFRESH_TTL_SECONDS", 604800),
    clients,
    users,
    allowedOrigins
  };
}

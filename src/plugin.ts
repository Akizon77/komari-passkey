import {
  definePlugin,
  jsonResponse,
  server,
  type PluginRequest,
  type PluginResponse,
} from "@komari-monitor/plugin-sdk";
import { injectedBody, injectedHead } from "./injected-ui";

declare const __dirname: string;
declare const __storageDir__: string;
declare const require: (name: string) => any;

const fs = require("node:fs") as any;
const path = require("node:path") as { join: (...parts: string[]) => string };
const { URL } = require("node:url") as { URL: any };
const webauthn = require(
  path.join(__dirname, "runtime", "webauthn-core.cjs"),
) as {
  dispatch: (
    pathname: string,
    payload: Record<string, unknown>,
  ) => Promise<Record<string, unknown>>;
};

type DatabaseValue = string | number | boolean | null;
type RouteResult = Record<string, unknown>;
type RuntimeDatabaseQueryResult = { Rows: unknown[][] };

type SecurityConfig = {
  rpID: string;
  rpName: string;
  origins: string[];
  allowHTTPOrigins: boolean;
  userVerification: string;
  residentKey: string;
  authenticatorAttachment: string;
  attestationType: string;
  allowSyncedCredentials: boolean;
  challengeTTLSeconds: number;
  timeoutMS: number;
  sessionTTLSeconds: number;
  cookieSecure: boolean;
  cookieSameSite: string;
  maxCredentials: number;
};

type KomariUser = {
  uuid: string;
  username: string;
};

type StoredCredential = {
  id: string;
  name: string;
  publicKey: string;
  counter: number;
  transports: string[];
  deviceType: string;
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
};

type StoredChallenge = {
  challenge: string;
  userUUID: string;
};

type PersistentCredential = StoredCredential & {
  userUUID: string;
};

type PersistentChallenge = StoredChallenge & {
  id: string;
  purpose: string;
  expiresAt: string;
};

type PasskeyStore = {
  version: 1;
  credentials: PersistentCredential[];
  challenges: PersistentChallenge[];
};

type RouteFailure = Error & {
  status: number;
  code: string;
};

let verifierAvailable = false;
const passkeyStorePath = path.join(__storageDir__, "passkeys.json");
const passkeyStoreTemporaryPath = path.join(
  __storageDir__,
  "passkeys.json.tmp",
);

function routeFailure(status: number, code: string): RouteFailure {
  const error = new Error(code) as RouteFailure;
  error.status = status;
  error.code = code;
  return error;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function configurationOrigins(value: string): string[] {
  return value
    .split(/[\n,\r]+/)
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

function requestOrigin(
  req: PluginRequest | undefined,
  allowQueryOrigin: boolean,
): string {
  if (!req) {
    return "";
  }
  const origin = stringValue(req.headers.origin).trim();
  if (origin || !allowQueryOrigin) {
    return origin;
  }
  return stringValue(req.query.origin).trim();
}

function inferredSecurityConfig(
  config: SecurityConfig,
  req: PluginRequest | undefined,
  allowQueryOrigin: boolean,
): SecurityConfig {
  if (config.rpID && config.origins.length > 0) {
    return config;
  }
  const origin = requestOrigin(req, allowQueryOrigin);
  if (!origin) {
    return config;
  }
  try {
    const parsed = new URL(origin);
    if (
      parsed.origin !== origin ||
      !parsed.hostname ||
      (!config.allowHTTPOrigins && parsed.protocol !== "https:")
    ) {
      return config;
    }
    return {
      ...config,
      rpID: parsed.hostname,
      origins: [parsed.origin],
    };
  } catch {
    return config;
  }
}

async function securityConfig(
  req?: PluginRequest,
  allowQueryOrigin = false,
): Promise<SecurityConfig> {
  const data = await server.getConfig<Record<string, unknown>>();
  return inferredSecurityConfig({
    rpID: stringValue(data.rp_id).trim(),
    rpName: stringValue(data.rp_name).trim() || "Komari",
    origins: configurationOrigins(stringValue(data.origins)),
    allowHTTPOrigins: booleanValue(data.allow_http_origins, false),
    userVerification: stringValue(data.user_verification) || "required",
    residentKey: stringValue(data.resident_key) || "required",
    authenticatorAttachment:
      stringValue(data.authenticator_attachment) || "platform",
    attestationType: stringValue(data.attestation_type) || "none",
    allowSyncedCredentials: booleanValue(data.allow_synced_credentials, false),
    challengeTTLSeconds: numberValue(data.challenge_ttl_seconds, 120),
    timeoutMS: numberValue(data.webauthn_timeout_ms, 60000),
    sessionTTLSeconds: numberValue(data.session_ttl_seconds, 43200),
    cookieSecure: booleanValue(data.cookie_secure, true),
    cookieSameSite: stringValue(data.cookie_same_site) || "strict",
    maxCredentials: numberValue(data.max_credentials, 5),
  }, req, allowQueryOrigin);
}

function isConfigured(config: SecurityConfig): boolean {
  if (!config.rpID || config.origins.length === 0) {
    return false;
  }
  return (
    config.allowHTTPOrigins ||
    config.origins.every((origin) => origin.startsWith("https://"))
  );
}

async function configuredSecurityConfig(req: PluginRequest): Promise<SecurityConfig> {
  const config = await securityConfig(req);
  if (!isConfigured(config)) {
    throw routeFailure(409, "configuration_required");
  }
  return config;
}

function serviceConfiguration(config: SecurityConfig): Record<string, unknown> {
  return {
    rpID: config.rpID,
    rpName: config.rpName,
    origins: config.origins,
    userVerification: config.userVerification,
    residentKey: config.residentKey,
    authenticatorAttachment: config.authenticatorAttachment,
    attestationType: config.attestationType,
    timeoutMs: config.timeoutMS,
    allowSyncedCredentials: config.allowSyncedCredentials,
  };
}

async function callVerifier(
  pathname: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  try {
    return await webauthn.dispatch(pathname, payload);
  } catch (error) {
    console.error("[komari-passkey] WebAuthn verification failed:", error);
    throw routeFailure(400, "verification_failed");
  }
}

async function checkVerifier(): Promise<boolean> {
  try {
    await callVerifier("/health", {});
    return true;
  } catch {
    return false;
  }
}

async function dbQuery(
  sql: string,
  args: DatabaseValue[] = [],
  limit = 100,
): Promise<unknown[][]> {
  const result = (await server.call("admin:dbQuery", {
    database: "main",
    sql,
    args,
    limit,
  })) as unknown as RuntimeDatabaseQueryResult;
  return result.Rows as unknown[][];
}

async function dbExec(sql: string, args: DatabaseValue[] = []) {
  await server.call("admin:dbExec", {
    database: "main",
    sql,
    args,
  });
}

async function onlyUser(): Promise<KomariUser> {
  const rows = await dbQuery("SELECT uuid, username FROM users LIMIT 1", [], 1);
  if (rows.length === 0) {
    throw routeFailure(500, "user_unavailable");
  }
  return {
    uuid: stringValue(rows[0][0]),
    username: stringValue(rows[0][1]),
  };
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map(stringValue).filter((item) => item.length > 0)
    : [];
}

function emptyPasskeyStore(): PasskeyStore {
  return {
    version: 1,
    credentials: [],
    challenges: [],
  };
}

function readPasskeyStore(): PasskeyStore {
  if (!fs.existsSync(passkeyStorePath)) {
    return emptyPasskeyStore();
  }
  return JSON.parse(
    stringValue(fs.readFileSync(passkeyStorePath, "utf8")),
  ) as PasskeyStore;
}

function writePasskeyStore(store: PasskeyStore) {
  fs.writeFileSync(passkeyStoreTemporaryPath, JSON.stringify(store), "utf8");
  fs.renameSync(passkeyStoreTemporaryPath, passkeyStorePath);
}

function responseStoredCredential(
  value: PersistentCredential,
): StoredCredential {
  return {
    id: value.id,
    name: value.name,
    publicKey: value.publicKey,
    counter: value.counter,
    transports: value.transports,
    deviceType: value.deviceType,
    backedUp: value.backedUp,
    createdAt: value.createdAt,
    lastUsedAt: value.lastUsedAt,
  };
}

async function credentialsFor(userUUID: string): Promise<StoredCredential[]> {
  return readPasskeyStore()
    .credentials.filter((credential) => credential.userUUID === userUUID)
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .map(responseStoredCredential);
}

async function credentialByID(
  userUUID: string,
  credentialID: string,
): Promise<StoredCredential | null> {
  const credential = readPasskeyStore().credentials.find(
    (item) => item.userUUID === userUUID && item.id === credentialID,
  );
  return credential ? responseStoredCredential(credential) : null;
}

function nowISOString(): string {
  return new Date().toISOString();
}

function expiresAt(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function cleanExpiredChallenges(store: PasskeyStore, now: string) {
  store.challenges = store.challenges.filter(
    (challenge) => challenge.expiresAt > now,
  );
}

async function saveChallenge(
  purpose: string,
  challengeID: string,
  challenge: string,
  userUUID: string,
  config: SecurityConfig,
) {
  const store = readPasskeyStore();
  cleanExpiredChallenges(store, nowISOString());
  store.challenges.push({
    id: challengeID,
    purpose,
    challenge,
    userUUID,
    expiresAt: expiresAt(config.challengeTTLSeconds),
  });
  writePasskeyStore(store);
}

async function takeChallenge(
  challengeID: string,
  purpose: string,
): Promise<StoredChallenge> {
  const store = readPasskeyStore();
  cleanExpiredChallenges(store, nowISOString());
  const index = store.challenges.findIndex(
    (challenge) =>
      challenge.id === challengeID && challenge.purpose === purpose,
  );
  if (index < 0) {
    writePasskeyStore(store);
    throw routeFailure(400, "challenge_expired");
  }
  const challenge = store.challenges.splice(index, 1)[0];
  writePasskeyStore(store);
  return {
    challenge: challenge.challenge,
    userUUID: challenge.userUUID,
  };
}

function userFromRequest(req: PluginRequest): KomariUser {
  const principal = req.context.principal;
  const uuid = stringValue(principal?.user_uuid);
  if (principal?.type !== "user" || !uuid) {
    throw routeFailure(401, "authentication_required");
  }
  return {
    uuid,
    username: "",
  };
}

function jsonBody(req: PluginRequest): Record<string, unknown> {
  try {
    return objectValue(JSON.parse(req.body || "{}"));
  } catch {
    throw routeFailure(400, "invalid_request");
  }
}

function responseCredential(value: StoredCredential): Record<string, unknown> {
  return {
    id: value.id,
    name: value.name,
    device_type: value.deviceType,
    backed_up: value.backedUp,
    created_at: value.createdAt,
    last_used_at: value.lastUsedAt,
  };
}

function cookieSameSite(value: string): string {
  switch (value) {
    case "lax":
      return "Lax";
    case "none":
      return "None";
    default:
      return "Strict";
  }
}

async function createNativeSession(
  userUUID: string,
  sessionToken: string,
  req: PluginRequest,
  config: SecurityConfig,
) {
  const now = nowISOString();
  await dbExec(
    "INSERT INTO sessions (uuid, session, user_agent, ip, login_method, latest_online, latest_user_agent, latest_ip, expires, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      userUUID,
      sessionToken,
      stringValue(req.context.user_agent),
      stringValue(req.context.remote_ip),
      "Passkey",
      now,
      "",
      "",
      expiresAt(config.sessionTTLSeconds),
      now,
    ],
  );
}

function notifyPasskeyLogin(req: PluginRequest) {
  void server
    .call("admin:getSettings")
    .then((settings) => {
      if (objectValue(settings).login_notification !== true) {
        return;
      }
      return server.call("admin:sendNotification", {
        event: {
          event: "Login",
          time: nowISOString(),
          message:
            "通行密钥：" +
            stringValue(req.context.remote_ip) +
            "\n" +
            stringValue(req.context.user_agent),
          emoji: "🔑",
        },
      });
    })
    .catch(() => {});
}

function sessionCookie(sessionToken: string, config: SecurityConfig): string {
  const parts = [
    "session_token=" + sessionToken,
    "Path=/",
    "Max-Age=" + config.sessionTTLSeconds,
    "HttpOnly",
    "SameSite=" + cookieSameSite(config.cookieSameSite),
  ];
  if (config.cookieSecure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function route(
  handler: (req: PluginRequest, res: PluginResponse) => Promise<RouteResult>,
) {
  return async (req: PluginRequest, res: PluginResponse) => {
    try {
      const result = await handler(req, res);
      res.setHeader("Cache-Control", "no-store");
      jsonResponse(res, { ok: true, ...result });
    } catch (error) {
      const failure = error as Partial<RouteFailure>;
      const status = typeof failure.status === "number" ? failure.status : 500;
      const code =
        typeof failure.code === "string" ? failure.code : "internal_error";
      console.error("[komari-passkey] Route failed:", code, String(error));
      res.setHeader("Cache-Control", "no-store");
      jsonResponse(res, { ok: false, code }, status);
    }
  };
}

function registerRoutes() {
  server.route(
    "GET",
    "/api/komari-passkey/status",
    route(async (req) => {
      const config = await securityConfig(req, true);
      if (!isConfigured(config)) {
        return {
          configured: false,
          enabled: false,
          service_available: verifierAvailable,
        };
      }
      const user = await onlyUser();
      const credentials = await credentialsFor(user.uuid);
      return {
        configured: true,
        enabled: credentials.length > 0 && verifierAvailable,
        service_available: verifierAvailable,
        credential_count: credentials.length,
      };
    }),
  );

  server.route(
    "GET",
    "/api/komari-passkey/credentials",
    route(async (req) => {
      const user = userFromRequest(req);
      const config = await securityConfig(req, true);
      const credentials = await credentialsFor(user.uuid);
      return {
        configured: isConfigured(config),
        service_available: verifierAvailable,
        credentials: credentials.map(responseCredential),
      };
    }),
  );

  server.route(
    "POST",
    "/api/komari-passkey/registration/options",
    route(async (req) => {
      const user = userFromRequest(req);
      const config = await configuredSecurityConfig(req);
      const account = await onlyUser();
      const existing = await credentialsFor(user.uuid);
      if (existing.length >= config.maxCredentials) {
        throw routeFailure(409, "credential_limit_reached");
      }
      const verifierResult = await callVerifier("/registration/options", {
        config: serviceConfiguration(config),
        user: account,
        credentials: existing.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
      });
      const challengeID = stringValue(verifierResult.challengeId);
      const options = objectValue(verifierResult.options);
      await saveChallenge(
        "registration",
        challengeID,
        stringValue(options.challenge),
        user.uuid,
        config,
      );
      return {
        challenge_id: challengeID,
        options,
      };
    }),
  );

  server.route(
    "POST",
    "/api/komari-passkey/registration/verify",
    route(async (req) => {
      const user = userFromRequest(req);
      const config = await configuredSecurityConfig(req);
      const body = jsonBody(req);
      const challenge = await takeChallenge(
        stringValue(body.challenge_id),
        "registration",
      );
      if (challenge.userUUID !== user.uuid) {
        throw routeFailure(400, "challenge_expired");
      }
      const existing = await credentialsFor(user.uuid);
      if (existing.length >= config.maxCredentials) {
        throw routeFailure(409, "credential_limit_reached");
      }
      const verifierResult = await callVerifier("/registration/verify", {
        config: serviceConfiguration(config),
        expectedChallenge: challenge.challenge,
        response: objectValue(body.response),
      });
      if (verifierResult.verified !== true) {
        throw routeFailure(400, stringValue(verifierResult.code) || "verification_failed");
      }
      const credential = objectValue(verifierResult.credential);
      const createdAt = nowISOString();
      const storedCredential: PersistentCredential = {
        id: stringValue(credential.id),
        userUUID: user.uuid,
        name: stringValue(body.name).trim() || "Passkey",
        publicKey: stringValue(credential.publicKey),
        counter: numberValue(credential.counter, 0),
        transports: stringArray(credential.transports),
        deviceType: stringValue(verifierResult.credentialDeviceType),
        backedUp: verifierResult.credentialBackedUp === true,
        createdAt,
        lastUsedAt: null,
      };
      const store = readPasskeyStore();
      store.credentials.push(storedCredential);
      writePasskeyStore(store);
      return {
        credential: responseCredential(
          responseStoredCredential(storedCredential),
        ),
      };
    }),
  );

  server.route(
    "POST",
    "/api/komari-passkey/credentials/delete",
    route(async (req) => {
      const user = userFromRequest(req);
      const body = jsonBody(req);
      const store = readPasskeyStore();
      store.credentials = store.credentials.filter(
        (credential) =>
          credential.userUUID !== user.uuid ||
          credential.id !== stringValue(body.credential_id),
      );
      writePasskeyStore(store);
      return {};
    }),
  );

  server.route(
    "POST",
    "/api/komari-passkey/authentication/options",
    route(async (req) => {
      const config = await configuredSecurityConfig(req);
      const user = await onlyUser();
      const existing = await credentialsFor(user.uuid);
      if (existing.length === 0) {
        throw routeFailure(404, "passkey_unavailable");
      }
      const verifierResult = await callVerifier("/authentication/options", {
        config: serviceConfiguration(config),
        credentials: existing.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
      });
      const challengeID = stringValue(verifierResult.challengeId);
      const options = objectValue(verifierResult.options);
      await saveChallenge(
        "authentication",
        challengeID,
        stringValue(options.challenge),
        user.uuid,
        config,
      );
      return {
        challenge_id: challengeID,
        options,
      };
    }),
  );

  server.route(
    "POST",
    "/api/komari-passkey/authentication/verify",
    route(async (req, res) => {
      const config = await configuredSecurityConfig(req);
      const body = jsonBody(req);
      const response = objectValue(body.response);
      const challenge = await takeChallenge(
        stringValue(body.challenge_id),
        "authentication",
      );
      const credential = await credentialByID(
        challenge.userUUID,
        stringValue(response.id),
      );
      if (!credential) {
        throw routeFailure(400, "verification_failed");
      }
      const verifierResult = await callVerifier("/authentication/verify", {
        config: serviceConfiguration(config),
        expectedChallenge: challenge.challenge,
        response,
        credential: {
          id: credential.id,
          publicKey: credential.publicKey,
          counter: credential.counter,
          transports: credential.transports,
        },
      });
      if (verifierResult.verified !== true) {
        throw routeFailure(400, stringValue(verifierResult.code) || "verification_failed");
      }
      const usedAt = nowISOString();
      const store = readPasskeyStore();
      store.credentials = store.credentials.map((stored) => {
        if (
          stored.userUUID !== challenge.userUUID ||
          stored.id !== credential.id
        ) {
          return stored;
        }
        return {
          ...stored,
          counter: numberValue(verifierResult.newCounter, credential.counter),
          deviceType: stringValue(verifierResult.credentialDeviceType),
          backedUp: verifierResult.credentialBackedUp === true,
          lastUsedAt: usedAt,
        };
      });
      writePasskeyStore(store);
      const sessionToken = stringValue(verifierResult.sessionToken);
      await createNativeSession(challenge.userUUID, sessionToken, req, config);
      notifyPasskeyLogin(req);
      res.setHeader("Set-Cookie", sessionCookie(sessionToken, config));
      return { logged_in: true };
    }),
  );
}

definePlugin({
  async load() {
    registerRoutes();
    server.injectHTML(injectedHead, injectedBody);
    verifierAvailable = await checkVerifier();
  },
});

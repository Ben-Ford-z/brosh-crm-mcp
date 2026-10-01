#!/usr/bin/env node

/**
 * BROSH CRM HTTP API Server
 * Deployable server with OAuth2 + REST endpoints for OpenAI Custom GPT Actions.
 * Supports multiple concurrent users via per-user JWT sessions.
 *
 * Docs: https://www.brosh.io/page/api-oauth2-documentation
 */

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import axios from "axios";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import * as fs from "fs";
import * as path from "path";

// ─── Configuration ─────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = process.env.HOST || "127.0.0.1";
const BROSH_BASE_URL = (
  process.env.BROSH_BASE_URL || "https://app.brosh.io"
).replace(/\/$/, "");
const BROSH_SOURCE = process.env.BROSH_SOURCE || "MCP";
const TRUST_PROXY = process.env.TRUST_PROXY;
const SESSION_TTL_MS = parseInt(
  process.env.SESSION_TTL_MS || String(7 * 24 * 60 * 60 * 1000),
  10,
); // 7 days default
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const ACCESS_TOKEN_TTL_SEC = 7 * 24 * 60 * 60;
const REFRESH_TOKEN_TTL_SEC = 30 * 24 * 60 * 60;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const CONSUMED_STATE_REPLAY_TTL_MS = parseInt(
  process.env.CONSUMED_STATE_REPLAY_TTL_MS || String(10 * 60 * 1000),
  10,
);
const OP_CONFIRM_TTL_MS = parseInt(
  process.env.OP_CONFIRM_TTL_MS || String(5 * 60 * 1000),
  10,
);

// SERVER_URL must be set in production (e.g. https://brosh-api.example.com)
const SERVER_URL = (process.env.SERVER_URL || `https://mcp.brosh.io`).replace(
  /\/$/,
  "",
);
const API_PREFIX = "/api";
const HEALTH_PATH = `${API_PREFIX}/health`;
const OPENAPI_PATH = `${API_PREFIX}/openapi.json`;
const LOGIN_PATH = `${API_PREFIX}/oauth/login`;
const AUTHORIZE_PATH = `${API_PREFIX}/oauth/authorize`;
const TOKEN_PATH = `${API_PREFIX}/oauth/token`;
const CALLBACK_PATH = `${API_PREFIX}/oauth/callback`;
const USERINFO_PATH = `${API_PREFIX}/oauth/userinfo`;
const REVOKE_PATH = `${API_PREFIX}/oauth/revoke`;
const REGISTER_PATH = `${API_PREFIX}/oauth/register`;
const MCP_PATH = `${API_PREFIX}/mcp`;
const API_RESOURCE = `${SERVER_URL}${API_PREFIX}`;
const ROOT_RESOURCE = `${SERVER_URL}${MCP_PATH}`;
const MCP_RESOURCE = ROOT_RESOURCE;
const LEGACY_MCP_RESOURCE = `${SERVER_URL}/mcp`;

// JWT secret: set a strong, stable value in production via JWT_SECRET env var
const JWT_SECRET =
  process.env.JWT_SECRET ||
  (() => {
    const secretFile = path.join(DATA_DIR, ".jwt-secret");
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      if (fs.existsSync(secretFile))
        return fs.readFileSync(secretFile, "utf8").trim();
      const s = crypto.randomBytes(64).toString("hex");
      fs.writeFileSync(secretFile, s, "utf8");
      return s;
    } catch {
      return crypto.randomBytes(64).toString("hex"); // ephemeral fallback
    }
  })();

// ─── OIDC Key Pair (RS256) ─────────────────────────────────────────────────────
// Ephemeral RSA-2048 key pair for signing OIDC id_tokens (RS256).
// Regenerated on each restart — consistent with in-memory session storage.
// Set OIDC_PRIVATE_KEY_PEM + OIDC_PUBLIC_KEY_PEM env vars to persist across restarts.
let OIDC_PRIVATE_KEY: string;
let OIDC_PUBLIC_KEY_PEM: string;
if (process.env.OIDC_PRIVATE_KEY_PEM && process.env.OIDC_PUBLIC_KEY_PEM) {
  OIDC_PRIVATE_KEY = process.env.OIDC_PRIVATE_KEY_PEM;
  OIDC_PUBLIC_KEY_PEM = process.env.OIDC_PUBLIC_KEY_PEM;
} else {
  const kp = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  OIDC_PRIVATE_KEY = kp.privateKey;
  OIDC_PUBLIC_KEY_PEM = kp.publicKey;
  console.log("[init] OIDC RS256 key pair generated in memory.");
  console.log(
    "[init] ⚠️  Set OIDC_PRIVATE_KEY_PEM / OIDC_PUBLIC_KEY_PEM env vars to persist across restarts.",
  );
}
const OIDC_KID = crypto.randomBytes(8).toString("hex");
const oidcPublicJwk = crypto
  .createPublicKey(OIDC_PUBLIC_KEY_PEM)
  .export({ format: "jwk" }) as {
  kty: string;
  n: string;
  e: string;
  [key: string]: unknown;
};

// OpenAI GPT OAuth credentials — set these in your GPT's OAuth configuration
// and mirror them here so we can verify token exchange requests.
const OPENAI_CLIENT_ID = process.env.OPENAI_CLIENT_ID || "";
const OPENAI_CLIENT_SECRET = process.env.OPENAI_CLIENT_SECRET || "";

// BROSH OAuth credentials — auto-generated and persisted if not provided
let BROSH_CLIENT_ID: string;
let BROSH_CLIENT_SECRET_VAL: string;

function initBroshCredentials(): void {
  BROSH_CLIENT_ID =
    process.env.BROSH_CLIENT_ID ??
    `BROSH-${Math.floor(Math.random() * 1_000_000_000_000_000)}`;
  BROSH_CLIENT_SECRET_VAL =
    process.env.BROSH_CLIENT_SECRET ??
    "BROSH-" + crypto.randomBytes(32).toString("hex");

  if (!process.env.BROSH_CLIENT_ID || !process.env.BROSH_CLIENT_SECRET) {
    console.log(
      "[init] BROSH credentials generated in memory (not persisted).",
    );
    console.log(`[init] BROSH_CLIENT_ID:     ${BROSH_CLIENT_ID}`);
    console.log(`[init] BROSH_CLIENT_SECRET: ${BROSH_CLIENT_SECRET_VAL}`);
    console.log(
      "[init] ⚠️  Set BROSH_CLIENT_ID and BROSH_CLIENT_SECRET env vars to persist across restarts.",
    );
  }
}

// ─── Types ─────────────────────────────────────────────────────────────────────

interface UserSession {
  id: string;
  broshAccessToken: string;
  broshRefreshToken?: string;
  broshTokenExpiresAt: number;
  sessionExpiresAt: number;
  /** Dynamic table allowlist resolved from /api/oauth2/tables/:source for this user. */
  availableTables?: string[];
  /** Optional dynamic field metadata by table when returned by /api/oauth2/tables/:source. */
  availableTableFields?: Record<string, Array<Record<string, unknown>>>;
  tokenAudience?: string;
  userInfo?: { id: string; userid: number; name: string; email?: string };
  /** OIDC: scopes requested during the authorization flow (e.g. "openid email profile") */
  requestedScope?: string;
  /** OIDC: nonce from the authorization request, embedded in id_token */
  nonce?: string;
  /** PKCE: stored code_challenge for verification at the token endpoint (one-time) */
  codeChallenge?: string;
  /** PKCE: code_challenge_method — "S256" or "plain" */
  codeChallengeMethod?: string;
  createdAt: number;
}

interface OAuthState {
  /** Redirect URI to return to after auth (OpenAI's callback, or undefined for direct web login) */
  openaiRedirectUri?: string;
  /** state param sent by OpenAI that must be echoed back */
  openaiState?: string;
  /** OAuth client_id used during the authorization request */
  clientId?: string;
  /** OIDC: scopes requested by the client (e.g. "openid email profile Full") */
  requestedScope?: string;
  /** OAuth resource / audience requested by the client */
  requestedResource?: string;
  /** OIDC: nonce to bind id_token to this authorization request */
  nonce?: string;
  /** PKCE: code_challenge sent by the client */
  codeChallenge?: string;
  /** PKCE: code_challenge_method — "S256" or "plain" */
  codeChallengeMethod?: string;
  createdAt: number;
}

interface ConsumedOAuthState {
  callbackUrl?: string;
  consumedAt: number;
}

// ─── Dynamic Client Registration (RFC 7591) ────────────────────────────────────

interface RegisteredClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  client_name?: string;
  client_uri?: string;
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  scope?: string;
  created_at: number;
}

interface AuthorizationCodeRecord {
  sessionId: string;
  clientId?: string;
  redirectUri: string;
  requestedResource: string;
  expiresAt: number;
  createdAt: number;
}

type ConfirmableToolName =
  | "brosh_delete"
  | "brosh_send_email"
  | "brosh_send_message_single";

type McpToolName =
  | "brosh_me"
  | "brosh_available_tables"
  | "brosh_find"
  | "brosh_get"
  | "brosh_create"
  | "brosh_update"
  | "brosh_delete"
  | "brosh_send_email"
  | "brosh_send_message_single";

interface PendingConfirmation {
  token: string;
  sessionId: string;
  toolName: ConfirmableToolName;
  argsHash: string;
  preview: Record<string, unknown>;
  createdAt: number;
  expiresAt: number;
}

interface BroshAvailableTableWithFields {
  name?: string;
  fields?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

interface BroshAvailableTablesResponse {
  tables?: Array<string | BroshAvailableTableWithFields>;
  total_count?: number;
  [key: string]: unknown;
}

/**
 * Thrown when the upstream BROSH token is expired and cannot be refreshed.
 * Caught by handleMcpHttpRequest to return HTTP 401 so MCP clients (e.g. OpenAI)
 * surface the OAuth reconnect button instead of a plain error message.
 */
class BroshUnauthorizedError extends Error {
  constructor() {
    super("BROSH session expired — re-authorization required.");
    this.name = "BroshUnauthorizedError";
  }
}

function normalizeTableName(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

const TABLE_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_]*$/;

function isEnglishTableName(value: string): boolean {
  return TABLE_NAME_PATTERN.test(value);
}

async function fetchAvailableTablesForSession(
  broshAccessToken: string,
): Promise<{
  tables: string[];
  fieldsByTable: Record<string, Array<Record<string, unknown>>>;
}> {
  const response = (await broshRequest(
    "POST",
    `/api/oauth2/tables/${BROSH_SOURCE}?show_fields=1`,
    broshAccessToken,
    {},
  )) as BroshAvailableTablesResponse;

  const resultTables: string[] = [];
  const fieldsByTable: Record<string, Array<Record<string, unknown>>> = {};
  const seen = new Set<string>();

  for (const rawTable of response.tables ?? []) {
    if (typeof rawTable === "string") {
      const normalized = normalizeTableName(rawTable);
      if (normalized && !seen.has(normalized)) {
        seen.add(normalized);
        resultTables.push(normalized);
      }
      continue;
    }

    if (!rawTable || typeof rawTable !== "object") continue;
    const normalized = normalizeTableName(rawTable.name);
    if (!normalized) continue;

    if (!seen.has(normalized)) {
      seen.add(normalized);
      resultTables.push(normalized);
    }

    if (Array.isArray(rawTable.fields)) {
      fieldsByTable[normalized] = rawTable.fields.filter(
        (field): field is Record<string, unknown> =>
          !!field && typeof field === "object" && !Array.isArray(field),
      );
    }
  }

  return { tables: resultTables, fieldsByTable };
}

// ─── In-Memory Stores ──────────────────────────────────────────────────────────

/** sessionId → UserSession */
const sessions = new Map<string, UserSession>();

/** broshState → OAuthState  (CSRF protection for OAuth round-trip) */
const oauthStates = new Map<string, OAuthState>();

/** broshState → replay metadata for idempotent callback handling */
const consumedOAuthStates = new Map<string, ConsumedOAuthState>();

/** client_id → RegisteredClient  (RFC 7591 Dynamic Client Registration) */
const registeredClients = new Map<string, RegisteredClient>();

/** authCode → AuthorizationCodeRecord  (one-time OAuth authorization codes) */
const authorizationCodes = new Map<string, AuthorizationCodeRecord>();

/** confirmationToken → PendingConfirmation (two-step confirmation for risky actions) */
const pendingConfirmations = new Map<string, PendingConfirmation>();

// ─── Session Persistence ───────────────────────────────────────────────────────

const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const OAUTH_STATES_FILE = path.join(DATA_DIR, "oauth-states.json");

/**
 * Save all sessions to disk
 */
function saveSessions(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const sessionsArray = Array.from(sessions.entries()).map(
      ([id, session]) => session,
    );
    fs.writeFileSync(
      SESSIONS_FILE,
      JSON.stringify(sessionsArray, null, 2),
      "utf8",
    );
    console.log(`[Sessions] Saved ${sessionsArray.length} sessions to disk`);
  } catch (err) {
    console.error("[Sessions] Failed to save sessions:", err);
  }
}

/**
 * Load sessions from disk, filtering out expired ones
 */
function loadSessions(): void {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) {
      console.log("[Sessions] No saved sessions found");
      return;
    }

    const data = fs.readFileSync(SESSIONS_FILE, "utf8");
    const sessionsArray = JSON.parse(data) as UserSession[];
    const now = Date.now();
    let loaded = 0;
    let expired = 0;

    for (const session of sessionsArray) {
      // Skip expired sessions
      if (session.sessionExpiresAt < now) {
        expired++;
        continue;
      }

      sessions.set(session.id, session);
      loaded++;
    }

    console.log(
      `[Sessions] Loaded ${loaded} active sessions, skipped ${expired} expired sessions`,
    );
  } catch (err) {
    console.error("[Sessions] Failed to load sessions:", err);
  }
}

// Load sessions on startup
loadSessions();

function saveOAuthStates(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const statesArray = Array.from(oauthStates.entries()).map(([k, v]) => ({
      key: k,
      ...v,
    }));
    fs.writeFileSync(OAUTH_STATES_FILE, JSON.stringify(statesArray, null, 2), "utf8");
  } catch {
    /* non-fatal */
  }
}

function loadOAuthStates(): void {
  try {
    if (!fs.existsSync(OAUTH_STATES_FILE)) return;
    const data = fs.readFileSync(OAUTH_STATES_FILE, "utf8");
    const statesArray = JSON.parse(data) as Array<OAuthState & { key: string }>;
    const now = Date.now();
    const STATE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
    for (const { key, ...state } of statesArray) {
      if (now - state.createdAt < STATE_TTL_MS) {
        oauthStates.set(key, state);
      }
    }
  } catch {
    /* non-fatal */
  }
}

// Load OAuth states on startup so in-progress flows survive server restarts
loadOAuthStates();

// Periodic cleanup every 10 minutes
setInterval(
  () => {
    const now = Date.now();
    let cleaned = 0;

    for (const [id, s] of sessions) {
      if (s.sessionExpiresAt < now) {
        sessions.delete(id);
        cleaned++;
      }
    }

    for (const [state, d] of oauthStates) {
      if (now - d.createdAt > 7 * 24 * 60 * 60 * 1000) oauthStates.delete(state);
    }
    for (const [state, d] of consumedOAuthStates) {
      if (now - d.consumedAt > CONSUMED_STATE_REPLAY_TTL_MS) {
        consumedOAuthStates.delete(state);
      }
    }
    for (const [code, d] of authorizationCodes) {
      if (d.expiresAt < now) authorizationCodes.delete(code);
    }
    for (const [token, d] of pendingConfirmations) {
      if (d.expiresAt < now) pendingConfirmations.delete(token);
    }

    // Save sessions after cleanup
    if (cleaned > 0) {
      console.log(`[Sessions] Cleaned up ${cleaned} expired sessions`);
      saveSessions();
    }
  },
  10 * 60 * 1000,
).unref();

// ─── BROSH API Helpers ─────────────────────────────────────────────────────────

async function broshRequest(
  method: string,
  urlPath: string,
  accessToken: string,
  body?: unknown,
): Promise<unknown> {
  //console.log(`[BROSH API] ${method} ${urlPath}`, { body });
  try {
    const response = await axios({
      method,
      url: `${BROSH_BASE_URL}${urlPath}`,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      data: body,
      timeout: 30000, // 30 second timeout
    });
    /*console.log(`[BROSH API] Response:`, {
      status: response.status,
      dataLength: JSON.stringify(response.data).length,
    });*/
    return response.data;
  } catch (err: unknown) {
    if (axios.isAxiosError(err)) {
      console.error(
        `[BROSH API] Error ${err.response?.status}:`,
        err.response?.data || err.message,
      );
    } else {
      console.error(`[BROSH API] Error:`, err);
    }
    throw err;
  }
}

async function tryRefreshBroshToken(
  session: UserSession,
): Promise<UserSession | null> {
  if (!session.broshRefreshToken) return null;
  try {
    const res = await axios.post(
      `${BROSH_BASE_URL}/api/oauth2/refresh/${BROSH_SOURCE}`,
      {
        refresh_token: session.broshRefreshToken,
        client_secret: BROSH_CLIENT_SECRET_VAL,
        grant_type: "refresh_token",
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.broshAccessToken}`,
        },
      },
    );
    const t = res.data as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
    };
    const updated: UserSession = {
      ...session,
      broshAccessToken: t.access_token,
      broshRefreshToken: t.refresh_token ?? session.broshRefreshToken,
      broshTokenExpiresAt: t.expires_in
        ? Date.now() + t.expires_in * 1000
        : Date.now() + SESSION_TTL_MS,
      sessionExpiresAt: Date.now() + SESSION_TTL_MS,
    };
    sessions.set(session.id, updated);
    saveSessions();
    return updated;
  } catch {
    return null;
  }
}

// ─── Auth Middleware ───────────────────────────────────────────────────────────

interface AuthRequest extends Request {
  userSession: UserSession;
}

async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing Authorization header" });
    return;
  }
  const token = authHeader.slice(7);
  let sessionId: string;
  try {
    const payload = verifyAccessToken(token, [
      ROOT_RESOURCE,
      API_RESOURCE,
      MCP_RESOURCE,
      LEGACY_MCP_RESOURCE,
    ]);
    sessionId = payload.sessionId;
  } catch {
    res
      .status(401)
      .json({ error: "Invalid or expired token. Please re-authenticate." });
    return;
  }

  let session = sessions.get(sessionId);
  if (!session) {
    res
      .status(401)
      .json({ error: "Session not found. Please re-authenticate." });
    return;
  }

  // Auto-refresh BROSH token when it has less than 7 days left
  if (session.broshTokenExpiresAt - Date.now() < 7 * 24 * 60 * 60 * 1000) {
    const refreshed = await tryRefreshBroshToken(session);
    if (refreshed) {
      session = refreshed;
    } else if (session.broshTokenExpiresAt < Date.now()) {
      sessions.delete(sessionId);
      saveSessions();
      res
        .status(401)
        .json({
          error:
            "BROSH token expired and could not be refreshed. Please re-authenticate.",
        });
      return;
    }
  }

  (req as AuthRequest).userSession = session;
  next();
}

// ─── Express App ───────────────────────────────────────────────────────────────

const app = express();

// Respect reverse proxies (Ingress/CDN/load balancers) so req.ip and rate limiting
// use the real client address instead of the proxy hop.
if (TRUST_PROXY !== undefined) {
  if (/^\d+$/.test(TRUST_PROXY)) {
    app.set("trust proxy", parseInt(TRUST_PROXY, 10));
  } else {
    app.set(
      "trust proxy",
      ["1", "true", "yes", "on"].includes(TRUST_PROXY.toLowerCase()),
    );
  }
} else if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// Security headers: keep HTTP CSP disabled for the human-facing landing pages.
// ChatGPT widget CSP, when used, is declared in MCP resource metadata rather than
// through HTTP response headers.
//app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");
// CORS — allow all origins by default (restrict via ALLOWED_ORIGINS env var)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((s) => s.trim());
app.use(
  cors({
    origin: allowedOrigins.includes("*") ? "*" : allowedOrigins,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json({ limit: "10mb" }));
// OAuth2 token endpoint requires application/x-www-form-urlencoded per RFC 6749
app.use(express.urlencoded({ extended: false }));
app.use(
  "/vendor/bootstrap",
  express.static(path.join(process.cwd(), "node_modules", "bootstrap", "dist")),
);
app.use(
  "/vendor/bootstrap-icons",
  express.static(
    path.join(process.cwd(), "node_modules", "bootstrap-icons", "font"),
  ),
);
app.use(
  "/agents",
  express.static(path.join(process.cwd(), "www", "mcp", "agents")),
);

// Rate limiter — 200 req / 15 min per IP (generous for CRM usage)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please slow down." },
});
app.use(limiter);

// ─── Status / Landing Page ─────────────────────────────────────────────────────

app.get("/", (_req: Request, res: Response) => {
  const activeSessions = sessions.size;
  res.setHeader("Content-Type", "text/html; charset=UTF-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH AI CRM MCP Server</title>
  <meta name="description" content="BROSH CRM MCP server for ChatGPT, Claude, and VS Code. Secure OAuth2 CRM API with auto token refresh, AI CRM automation, and full CRUD workflows.">
  <meta name="keywords" content="BROSH CRM MCP, CRM MCP server, ChatGPT CRM integration, Claude CRM integration, AI CRM automation, OAuth2 CRM API, MCP token refresh, sales pipeline automation">
  <link rel="icon" href="https://www.brosh.io/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <link href="/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <link href="/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --bg:#06142b;
      --bg-2:#0b2447;
      --card:rgba(8,24,52,.78);
      --ink:#d9e9ff;
      --muted:#abc3e8;
      --line:rgba(148,188,243,.28);
      --brand:#1b78d6;
      --brand-2:#0f4ea8;
      --accent:#18b8ff;
      --good:#0ea46e;
    }
    body{
      font-family:'Space Grotesk',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      min-height:100vh;
      background:
        radial-gradient(1100px 520px at 10% -20%, rgba(27,120,214,.36), transparent 70%),
        radial-gradient(900px 460px at 110% 15%, rgba(24,184,255,.24), transparent 70%),
        linear-gradient(140deg,var(--bg),var(--bg-2));
      color:var(--ink);
      padding:24px;
    }
    .wrap{max-width:1080px;margin:0 auto}
    .hero{
      position:relative;overflow:hidden;
      border:1px solid rgba(139,188,255,.3);
      border-radius:28px;
      padding:32px;
      color:#e7f2ff;
      background:
        radial-gradient(480px 240px at 78% 18%, rgba(24,184,255,.22), transparent 70%),
        radial-gradient(420px 260px at 10% -8%, rgba(89,146,255,.18), transparent 75%),
        linear-gradient(130deg,rgba(9,29,59,.96),rgba(14,56,108,.92));
      box-shadow:0 22px 58px rgba(2,12,30,.45);
      margin-bottom:22px;
    }
    .hero:before{
      content:'';position:absolute;inset:auto -60px -80px auto;width:260px;height:260px;
      border-radius:50%;background:radial-gradient(circle, rgba(43,157,255,.24), transparent 68%);
      filter:blur(8px);pointer-events:none;
    }
    .hero-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr);gap:24px;align-items:center}
    .hero-copy{position:relative;z-index:1}
    .hero-kicker{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}
    .hero-pill{padding:7px 11px;border-radius:999px;border:1px solid rgba(164,203,255,.28);background:rgba(255,255,255,.08);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#dcecff}
    .chip{
      display:inline-flex;align-items:center;gap:8px;
      padding:7px 13px;border-radius:999px;
      background:rgba(142,198,255,.18);
      color:#d3e9ff;font-size:12px;font-weight:700;
      letter-spacing:.03em;text-transform:uppercase;
      margin-bottom:16px;
    }
    .dot{width:8px;height:8px;border-radius:50%;background:#35c3ff;box-shadow:0 0 11px rgba(53,195,255,.72)}
    h1{font-size:clamp(30px,5vw,54px);line-height:1.02;letter-spacing:-1.2px;margin-bottom:10px}
    .lead{max-width:780px;color:#c6dcf8;font-size:18px;line-height:1.6;margin-bottom:20px}
    .hero-em{display:block;background:linear-gradient(90deg,#f5fbff,#8ddcff 60%,#7ea9ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    .install-row{
      display:grid;grid-template-columns:1fr auto;gap:12px;
      background:rgba(255,255,255,.07);border:1px solid rgba(164,203,255,.28);
      border-radius:14px;padding:12px;
    }
    .server-url{
      display:flex;align-items:center;padding:10px 12px;border-radius:10px;
      background:rgba(7,21,45,.7);color:#d9e9ff;
      font-family:'JetBrains Mono','Courier New',monospace;
      font-size:13px;word-break:break-all;
    }
    .hero-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}
    .hero-note{margin-top:14px;color:#9ec4ef;font-size:13px;line-height:1.6;max-width:650px}
    .hero-visual{
      position:relative;z-index:1;
      background:linear-gradient(165deg,rgba(8,24,52,.88),rgba(5,18,41,.7));
      border:1px solid rgba(164,203,255,.18);
      border-radius:24px;padding:16px;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.06), 0 18px 40px rgba(3,12,28,.34);
    }
    .hero-visual-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
    .hero-visual-title{font-size:12px;color:#dbeaff;font-weight:700;letter-spacing:.05em;text-transform:uppercase}
    .hero-visual-badge{font-size:11px;font-weight:700;color:#9ff2cf;background:rgba(14,164,110,.16);border:1px solid rgba(14,164,110,.3);padding:5px 8px;border-radius:999px}
    .hero-art{width:100%;height:auto;display:block;border-radius:18px;background:radial-gradient(circle at 20% 10%, rgba(36,124,255,.16), transparent 45%),linear-gradient(180deg, rgba(11,31,64,.96), rgba(8,22,46,.96));border:1px solid rgba(148,188,243,.18)}
    .hero-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}
    .hero-metric{background:rgba(255,255,255,.05);border:1px solid rgba(148,188,243,.18);border-radius:14px;padding:10px}
    .hero-metric strong{display:block;color:#eef7ff;font-size:18px;letter-spacing:-.03em}
    .hero-metric span{display:block;color:#93bce6;font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
    .grid{display:grid;grid-template-columns:1fr;gap:16px;margin-bottom:18px}
    .card{
      background:var(--card);border:1px solid var(--line);border-radius:18px;
      padding:22px;box-shadow:0 16px 38px rgba(2,12,30,.35);backdrop-filter:blur(8px);
    }
    .card h2{font-size:22px;letter-spacing:-.5px;margin-bottom:10px;color:#ddecff}
    .card p{font-size:15px;color:var(--muted);line-height:1.65}
    .list{list-style:none;display:grid;gap:10px;margin-top:12px}
    .list li{display:flex;gap:10px;align-items:flex-start;color:#bed3f4;font-size:14px;line-height:1.5}
    .list li .ico{font-size:16px;line-height:1.2}
    .links{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
    a.btn{
      display:inline-flex;align-items:center;justify-content:center;gap:8px;
      border-radius:10px;padding:10px 16px;text-decoration:none;
      font-size:14px;font-weight:700;transition:transform .15s,opacity .15s;
    }
    a.btn:hover{transform:translateY(-1px);opacity:.95}
    a.btn-primary{background:linear-gradient(130deg,var(--brand),var(--brand-2));color:#fff}
    a.btn-soft{background:rgba(165,203,255,.16);color:#d7e9ff;border:1px solid rgba(157,197,248,.34)}
    .func-list{list-style:none;display:grid;gap:10px;margin-top:14px}
    .func-item{background:linear-gradient(160deg,rgba(12,36,74,.9),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-left:4px solid #2c8dff;border-radius:12px;padding:12px 14px;transition:transform .18s ease,box-shadow .18s ease}
    .func-item:hover{transform:translateY(-2px);box-shadow:0 12px 24px rgba(1,10,25,.32)}
    .func-item h3{font-size:15px;color:#ddedff;margin-bottom:6px}
    .func-item p{font-size:13px;color:#afc6e9;line-height:1.55}
    .steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:14px}
    .step{background:linear-gradient(160deg,rgba(13,39,78,.9),rgba(9,28,58,.86));border:1px solid rgba(148,188,243,.3);border-radius:12px;padding:14px;transition:transform .15s,box-shadow .15s,border-color .15s}
    .step .n{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;
      background:linear-gradient(130deg,var(--brand),var(--brand-2));color:#fff;font-size:12px;font-weight:700;margin-bottom:8px}
    .step h3{font-size:14px;color:#dcedff;margin-bottom:6px}
    .step p{font-size:13px;color:#afc6e9;line-height:1.55}
    .mini-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:14px}
    .mini{background:linear-gradient(160deg,rgba(12,36,74,.9),rgba(9,28,58,.86));border:1px solid rgba(148,188,243,.3);border-radius:12px;padding:12px;transition:transform .15s,box-shadow .15s,border-color .15s}
    .mini h3{font-size:14px;color:#dcedff;margin-bottom:6px}
    .mini p{font-size:13px;color:#afc6e9;line-height:1.55}
    .section-title{font-size:24px;letter-spacing:-.6px;color:#e3f0ff;margin-bottom:8px}
    .section-sub{font-size:14px;color:#afc6e9;line-height:1.6;margin-bottom:14px}
    .features-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
    .feature-card{background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-radius:14px;padding:14px;transition:transform .15s,box-shadow .15s}
    .feature-card:hover{transform:translateY(-2px);box-shadow:0 12px 26px rgba(1,10,25,.36)}
    .feature-icon{width:46px;height:46px;border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:22px;margin:0 auto 10px;border:1px solid rgba(201,228,255,.38);box-shadow:0 8px 18px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.2)}
    .feature-icon i{color:#eaf4ff;opacity:.98;text-shadow:0 1px 2px rgba(0,0,0,.28)}
    .feature-card h3{font-size:17px;color:#e8f3ff;margin-bottom:6px;text-align:center;line-height:1.25}
    .feature-card p{font-size:13px;color:#afc6e9;line-height:1.5}
    .ic1{background:linear-gradient(145deg,rgba(99,126,255,.58),rgba(73,98,230,.38))}.ic2{background:linear-gradient(145deg,rgba(65,170,255,.56),rgba(45,137,222,.36))}.ic3{background:linear-gradient(145deg,rgba(34,210,190,.56),rgba(23,171,153,.35))}.ic4{background:linear-gradient(145deg,rgba(255,170,90,.58),rgba(224,128,44,.36))}.ic5{background:linear-gradient(145deg,rgba(130,155,255,.56),rgba(95,123,231,.35))}.ic6{background:linear-gradient(145deg,rgba(255,122,176,.58),rgba(212,84,140,.36))}
    .cases-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
    .case-card{background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-radius:14px;padding:14px;transition:transform .15s,box-shadow .15s,border-color .15s}
    .case-card h3{font-size:14px;color:#ddedff;margin-bottom:7px}
    .case-card ul{list-style:none;display:grid;gap:6px}
    .case-card li{font-size:12px;color:#afc6e9;line-height:1.45}
    .case-card li:before{content:'→ ';color:#58b4ff;font-weight:700}
    .persona-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
    .persona-card{background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-radius:14px;padding:14px;transition:transform .15s,box-shadow .15s,border-color .15s}
    .persona-card h3{font-size:14px;color:#ddedff;margin-bottom:7px}
    .persona-card ul{list-style:none;display:grid;gap:6px}
    .persona-card li{font-size:12px;color:#afc6e9;line-height:1.45}
    .persona-card li:before{content:'✓ ';color:#0e9b63;font-weight:700}
    .shot-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
    .shot-card{background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-radius:14px;padding:12px;box-shadow:0 10px 24px rgba(1,10,25,.3);transition:transform .15s,box-shadow .15s,border-color .15s}
    .shot-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
    .shot-head h3{font-size:14px;color:#ddedff}
    .shot-tag{font-size:11px;font-weight:700;color:#dbeaff;background:rgba(106,176,255,.22);border:1px solid rgba(148,188,243,.35);padding:4px 8px;border-radius:999px}
    .shot-wrap{border-radius:10px;overflow:hidden;border:1px solid rgba(148,188,243,.35);background:rgba(10,26,56,.7)}
    .shot-wrap img{display:block;width:100%;height:auto;cursor:zoom-in}
    .shot-steps{list-style:none;display:grid;gap:6px;margin-top:10px}
    .shot-steps li{font-size:12px;color:#afc6e9;line-height:1.45}
    .shot-steps li:before{content:'• ';color:#58b4ff;font-weight:700}
    .lightbox{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(7,18,37,.86);z-index:9999;padding:20px}
    .lightbox.open{display:flex}
    .lightbox img{max-width:min(1200px,94vw);max-height:88vh;border-radius:12px;border:1px solid rgba(255,255,255,.28);box-shadow:0 28px 80px rgba(0,0,0,.45);cursor:zoom-out}
    .lightbox-close{position:absolute;top:14px;right:18px;width:38px;height:38px;border:1px solid rgba(255,255,255,.35);border-radius:999px;background:rgba(8,20,45,.8);color:#fff;font-size:22px;line-height:1;cursor:pointer}
    .lightbox-hint{position:absolute;left:50%;transform:translateX(-50%);bottom:14px;color:#dbe7ff;font-size:12px;background:rgba(10,26,56,.7);border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:6px 10px}
    code{
      font-family:'JetBrains Mono','Courier New',monospace;
      font-size:12px;
      background:rgba(10,30,61,.75);border:1px solid rgba(148,188,243,.35);color:#d8e9ff;
      padding:2px 6px;border-radius:6px;word-break:break-all;
    }
    .snippet{
      margin-top:12px;background:#0f1b33;color:#d9e6ff;
      border-radius:12px;padding:14px;border:1px solid #1c355c;
      font-family:'JetBrains Mono','Courier New',monospace;
      font-size:12px;overflow:auto;
    }
    .agent-connect{margin-top:24px;margin-bottom:24px}
    .agent-connect h2{font-size:24px;letter-spacing:-.6px;color:#e3f0ff;margin-bottom:8px}
    .agent-connect p{font-size:14px;color:#afc6e9;line-height:1.6}
    .agent-steps{margin-top:20px}
    .agent-step{background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));border:1px solid rgba(148,188,243,.3);border-radius:12px;padding:12px;transition:transform .15s,box-shadow .15s,border-color .15s}
    .agent-step strong{display:block;color:#ddecff;font-size:13px;margin-bottom:6px}
    .agent-step span{display:block;color:#afc6e9;font-size:12px;line-height:1.5}
    .step:hover,.step:focus-within,
    .mini:hover,.mini:focus-within,
    .case-card:hover,.case-card:focus-within,
    .persona-card:hover,.persona-card:focus-within,
    .shot-card:hover,.shot-card:focus-within,
    .agent-step:hover,.agent-step:focus-within,
    .func-item:focus-within{
      transform:translateY(-2px);
      box-shadow:0 12px 26px rgba(1,10,25,.36);
      border-color:#5aa7ff;
    }
    .agent-search-row{margin-top:24px}
    .agent-search{
      width:100%;padding:11px 13px;border-radius:10px;
      border:1px solid rgba(148,188,243,.35);
      background:rgba(7,21,45,.75);color:#d9e9ff;
      font-size:13px;outline:none;
    }
    .agent-search:focus{border-color:#4ea7ff;box-shadow:0 0 0 2px rgba(78,167,255,.2)}
    .agent-grid{margin-top:20px}
    .agent-tile{
      border:1px solid rgba(148,188,243,.3);
      background:linear-gradient(160deg,rgba(12,36,74,.92),rgba(9,28,58,.88));
      border-radius:14px;padding:16px 14px 14px;text-align:left;cursor:pointer;
      transition:transform .16s,box-shadow .16s,border-color .16s;
      color:#ddecff;
      display:flex;flex-direction:column;align-items:flex-start;gap:8px;min-height:136px;
    }
    .agent-tile:hover{transform:translateY(-2px);box-shadow:0 12px 24px rgba(1,10,25,.32);border-color:#5aa7ff}
    .agent-tile .ico{
      display:inline-flex;align-items:center;justify-content:center;
      width:56px;height:56px;
      background:transparent;border:none;
      padding:0;flex:0 0 auto;
      align-self:center;
    }
    .agent-tile .ico img{width:44px;height:44px;object-fit:contain;display:block}
    .agent-tile .ico img.logo-soft{opacity:.85}
    .agent-tile .name{display:block;font-size: 17px; align-self: center;font-weight:700;margin-bottom:4px}
    .agent-tile .desc{display:block;font-size:12px;color:#afc6e9;line-height:1.45}
    .agent-others-toggle{
      margin-top:20px;
      border:1px solid rgba(157,197,248,.34);
      background:rgba(165,203,255,.12);
      color:#d7e9ff;
      border-radius:10px;
      padding:10px 14px;
      font-size:13px;
      font-weight:700;
      cursor:pointer;
    }
    .agent-others{display:none;margin-top:20px}
    .agent-others.open{display:block}
    .agent-empty{display:none;margin-top:20px;color:#a9c3e9;font-size:12px}
    .agent-modal{
      position:fixed;inset:0;display:none;align-items:center;justify-content:center;
      background:rgba(7,18,37,.86);z-index:10000;padding:20px;
    }
    .agent-modal.open{display:flex}
    .agent-modal-card{
      width:min(760px,96vw);background:linear-gradient(160deg,rgba(12,36,74,.98),rgba(9,28,58,.96));
      border:1px solid rgba(148,188,243,.34);border-radius:14px;box-shadow:0 22px 60px rgba(0,0,0,.44);
      padding:16px;
    }
    .agent-modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px}
    .agent-modal-head h3{font-size:20px;letter-spacing:-.4px;color:#e3f0ff}
    .agent-modal-head p{font-size:13px;color:#aec7ea;margin-top:4px}
    .agent-close{
      width:34px;height:34px;border-radius:10px;border:1px solid rgba(148,188,243,.35);
      background:rgba(7,21,45,.75);color:#d9e9ff;font-size:20px;line-height:1;cursor:pointer;
    }
    .agent-close:hover{border-color:#63b3ed}
    .agent-prompt{
      background:#0f1b33;color:#d9e6ff;border:1px solid #1c355c;border-radius:12px;
      padding:12px;font-family:'JetBrains Mono','Courier New',monospace;
      font-size:12px;line-height:1.65;white-space:pre-wrap;
    }
    .agent-modal-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
    .agent-copy{
      border-radius:10px;padding:10px 14px;border:1px solid rgba(157,197,248,.34);
      background:rgba(165,203,255,.16);color:#d7e9ff;font-size:13px;font-weight:700;cursor:pointer;
    }
    .agent-copy.copied{background:rgba(14,164,110,.2);border-color:rgba(14,164,110,.5);color:#8ff3cb}
    .agent-open-link{display:inline-flex;align-items:center;text-decoration:none}
    .footer{margin-top:8px;text-align:center;color:#a8c0e4;font-size:12px}
    @media (max-width:900px){
      .hero-grid{grid-template-columns:1fr}
      .grid{grid-template-columns:1fr}
      .features-grid,.cases-grid,.persona-grid{grid-template-columns:1fr 1fr}
      .shot-grid{grid-template-columns:1fr}
      .steps{grid-template-columns:1fr}
      .mini-grid{grid-template-columns:1fr}
      .install-row{grid-template-columns:1fr}
    }
    @media (max-width:620px){
      body{padding:14px}
      .hero,.card{padding:18px}
      .hero-metrics{grid-template-columns:1fr}
      .features-grid,.cases-grid,.persona-grid{grid-template-columns:1fr}
      .links a{width:100%}
    }
  </style>
</head>
<body>
  <div class="wrap container-xl px-0 px-md-2">
    <section class="hero">
      <div class="hero-grid">
        <div class="hero-copy">
          <div class="chip"><span class="dot"></span> online | active live sessions: ~${activeSessions}K</div>
          <div class="hero-kicker">
            <span class="hero-pill">AI CRM Automation</span>
            <span class="hero-pill">OAuth2 Secured</span>
            <span class="hero-pill">MCP Ready</span>
          </div>
          <h1>BROSH AI CRM <span class="hero-em">MCP Server</span></h1>
          <p class="lead">Connect BROSH CRM to ChatGPT, Claude, VS Code, and any MCP client. Run pipeline reviews, outreach, reporting, and CRM updates from one AI-native control surface.</p>
          <div class="install-row">
            <div class="server-url">MCP URL: https://mcp.brosh.io</div>
            <a class="btn btn-primary"  href="https://app.brosh.io" target="_blank">Open CRM</a>
          </div>
   
          <p class="hero-note">Designed for revenue teams, support operations, and CRM admins who want one secure MCP endpoint for business workflows, analytics, and live record actions.</p>
        </div>

        <div class="hero-visual" aria-label="Business CRM illustration">
          <div class="hero-visual-top">
            <div class="hero-visual-title">Revenue Command View</div>
            <div class="hero-visual-badge">Live CRM</div>
          </div>
          <svg class="hero-art" viewBox="0 0 520 360" role="img" aria-label="Stylized business CRM dashboard illustration">
            <defs>
              <linearGradient id="panelGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#133a73" />
                <stop offset="100%" stop-color="#0a2043" />
              </linearGradient>
              <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#63d3ff" />
                <stop offset="100%" stop-color="#3d73ff" />
              </linearGradient>
            </defs>
            <rect x="20" y="22" width="480" height="316" rx="24" fill="url(#panelGrad)" stroke="rgba(189,221,255,.18)" />
            <rect x="42" y="46" width="206" height="118" rx="18" fill="rgba(255,255,255,.05)" stroke="rgba(189,221,255,.14)" />
            <text x="60" y="78" fill="#dceeff" font-size="14" font-family="Space Grotesk, sans-serif">Pipeline Health</text>
            <text x="60" y="118" fill="#ffffff" font-size="42" font-weight="700" font-family="Space Grotesk, sans-serif">$2.4M</text>
            <text x="60" y="142" fill="#8fdab7" font-size="13" font-family="Space Grotesk, sans-serif">+18% qualified growth</text>
            <rect x="268" y="46" width="210" height="118" rx="18" fill="rgba(255,255,255,.05)" stroke="rgba(189,221,255,.14)" />
            <text x="286" y="78" fill="#dceeff" font-size="14" font-family="Space Grotesk, sans-serif">AI Activity Map</text>
            <polyline points="288,132 324,120 350,126 385,93 415,105 460,82" fill="none" stroke="#73d1ff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" />
            <circle cx="324" cy="120" r="5" fill="#9ee7ff" />
            <circle cx="385" cy="93" r="5" fill="#9ee7ff" />
            <circle cx="460" cy="82" r="6" fill="#7ea9ff" />
            <rect x="42" y="184" width="304" height="132" rx="18" fill="rgba(255,255,255,.05)" stroke="rgba(189,221,255,.14)" />
            <text x="60" y="214" fill="#dceeff" font-size="14" font-family="Space Grotesk, sans-serif">Team Workflow Snapshot</text>
            <rect x="60" y="236" width="150" height="12" rx="6" fill="rgba(255,255,255,.10)" />
            <rect x="60" y="236" width="108" height="12" rx="6" fill="url(#barGrad)" />
            <rect x="60" y="264" width="150" height="12" rx="6" fill="rgba(255,255,255,.10)" />
            <rect x="60" y="264" width="136" height="12" rx="6" fill="#4fd0b7" />
            <rect x="60" y="292" width="150" height="12" rx="6" fill="rgba(255,255,255,.10)" />
            <rect x="60" y="292" width="121" height="12" rx="6" fill="#f7b267" />
            <text x="228" y="246" fill="#c3ddff" font-size="11" font-family="JetBrains Mono, monospace">Lead scoring</text>
            <text x="228" y="274" fill="#c3ddff" font-size="11" font-family="JetBrains Mono, monospace">Email sequences</text>
            <text x="228" y="302" fill="#c3ddff" font-size="11" font-family="JetBrains Mono, monospace">Renewal risk</text>
            <rect x="366" y="184" width="112" height="132" rx="18" fill="rgba(255,255,255,.05)" stroke="rgba(189,221,255,.14)" />
            <circle cx="422" cy="228" r="32" fill="rgba(115,209,255,.12)" stroke="rgba(115,209,255,.4)" />
            <path d="M408 229c6-13 25-15 34-1 7 10 2 24-10 31-3 2-7 4-10 6-3-2-7-4-10-6-12-7-17-21-10-30 2-3 4-5 6-7z" fill="#7fd6ff" opacity=".9"/>
            <text x="395" y="282" fill="#dceeff" font-size="12" font-family="Space Grotesk, sans-serif">Customer</text>
            <text x="370" y="298" fill="#9cc3ec" font-size="11" font-family="Space Grotesk, sans-serif">relationship health</text>
          </svg>
          <div class="hero-metrics">
            <div class="hero-metric"><strong>17+</strong><span>CRM tables</span></div>
            <div class="hero-metric"><strong>9</strong><span> MCP tools</span></div>
            <div class="hero-metric"><strong>24/7</strong><span> AI workflows</span></div>
          </div>
        </div>
      </div>
    </section>

    <section class="card agent-connect" aria-labelledby="agent-connect-title">
      <h2 id="agent-connect-title">Connect BROSH MCP With Popular GenAI Agents</h2>
      <p>Choose your AI agent, copy a ready prompt, and paste it into a new chat to complete setup quickly.</p>

      <div class="agent-steps row g-4">
        <div class="col-12 col-md-4"><div class="agent-step h-100"><strong>1. Choose agent</strong><span>Select Claude, ChatGPT, Microsoft Copilot, Gemini, Cursor, or Cline.</span></div></div>
        <div class="col-12 col-md-4"><div class="agent-step h-100"><strong>2. Copy prompt</strong><span>Open a card and copy a setup prompt tailored for that agent.</span></div></div>
        <div class="col-12 col-md-4"><div class="agent-step h-100"><strong>3. Authenticate</strong><span>Paste the prompt, follow OAuth sign-in, and run one test query.</span></div></div>
      </div>

      <div class="agent-search-row">
        <input id="agentSearch" class="agent-search" type="text" placeholder="Search AI agents" aria-label="Search AI agents">
      </div>

      <div id="agentGrid" class="agent-grid row g-4">
        <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="claude" data-search="claude anthropic desktop">
          <span class="ico"><i class="bi bi-claude" style="zoom: 250%;"></i></span><span class="name">Claude</span><span class="desc">Connect BROSH MCP in Claude Desktop with one guided prompt.</span>
        </button></div>
        <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="chatgpt" data-search="chatgpt openai gpt actions">
          <span class="ico"><i class="bi bi-openai" style="zoom: 250%;"></i></span><span class="name">ChatGPT</span><span class="desc">Configure MCP server mode and OAuth flow for BROSH.</span>
        </button></div>
        <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="copilot" data-search="microsoft copilot vscode github">
          <span class="ico"><img src="/agents/copilot.png" alt="Microsoft Copilot icon"></span><span class="name">Microsoft Copilot</span><span class="desc">Use MCP settings and validate connection in Agent mode.</span>
        </button></div>
        <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="gemini" data-search="gemini google">
          <span class="ico"><img src="/agents/gemini.png" alt="Gemini icon"></span><span class="name">Gemini</span><span class="desc">Connect BROSH MCP and verify access with a basic contacts query.</span>
        </button></div>
        <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="grok" data-search="grok xai x.ai">
          <span class="ico"><i class="bi bi-stars" style="zoom: 250%;"></i></span><span class="name">Grok</span><span class="desc">Connect BROSH MCP in Grok and verify access with a basic contacts query.</span>
        </button></div>
      </div>
      <button id="agentOthersToggle" type="button" class="agent-others-toggle" aria-expanded="false">Show others</button>
      <div id="otherAgents" class="agent-others">
        <div class="agent-grid row g-4">
          <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="cursor" data-search="cursor ide mcp">
            <span class="ico"><img src="/agents/cursor.png" alt="Cursor icon"></span><span class="name">Cursor</span><span class="desc">Create MCP workspace config and launch BROSH auth flow.</span>
          </button></div>
          <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="cline" data-search="cline roo code">
            <span class="ico"><img src="/agents/cline.png" alt="Cline icon"></span><span class="name">Cline</span><span class="desc">Add brosh-crm MCP server and run a quick lead query.</span>
          </button></div>
          <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="openclaw" data-search="openclaw ai agent">
            <span class="ico"><img src="/agents/openclaw.png" alt="OpenClaw icon"></span><span class="name">OpenClaw</span><span class="desc">Attach BROSH MCP and run a quick records validation query.</span>
          </button></div>
          <div class="col-12 col-sm-6 col-lg-3"><button type="button" class="agent-tile w-100 h-100" data-agent="ollama" data-search="ollama local llm">
            <span class="ico"><img class="logo-soft" src="/agents/ollama.svg" alt="Ollama icon"></span><span class="name">Ollama</span><span class="desc">Configure local MCP workflow and validate BROSH connectivity.</span>
          </button></div>
        </div>
      </div>
      <div id="agentEmpty" class="agent-empty">No agents found. Try Claude, ChatGPT, Copilot, Gemini, Grok, Cursor, Cline, OpenClaw, or Ollama.</div>
    </section>

    <section class="grid">
      <div class="card">
        <h2>Use Cases First: Real Team Workflows</h2>
        <p>Launch production-grade AI CRM workflows from day one with practical, high-impact use cases. You can also schedule these workflows as recurring tasks in Codex or Claude.</p>
        <ul class="list">
          <li><span class="ico">📈</span><span><strong>Sales acceleration:</strong> prioritize hot leads and trigger next actions instantly.<br><strong>Sample:</strong> "Find leads scored above 80 with no activity in 5 days and generate next-step outreach by owner."</span></li>
          <li><span class="ico">🎯</span><span><strong>Pipeline hygiene:</strong> detect stale opportunities, missing close dates, and invalid stages before forecast calls.<br><strong>Sample:</strong> "Show deals stuck in stage for 21+ days with missing close dates and suggest corrected updates."</span></li>
          <li><span class="ico">🧩</span><span><strong>Schema modification:</strong> create and modify BROSH CRM fields with MCP before import and operations.<br><strong>Sample:</strong> "Learn CSV columns, add missing fields in BROSH CRM, then import contacts safely."</span></li>
          <li><span class="ico">✉️</span><span><strong>Outreach smart automation:</strong> send newsletter templates or one-by-one tailored messages directly through MCP.<br><strong>Sample:</strong> "Use a CRM newsletter template for campaigns, or generate personalized product emails per contact and send them one by one."</span></li>
          <li><span class="ico">🧾</span><span><strong>Executive snapshots:</strong> generate weekly KPIs across deals, tickets, retention, and payments in one query.<br><strong>Sample:</strong> "Build this week's exec dashboard: pipeline coverage, win-rate trend, overdue invoices, and churn-risk changes."</span></li>
          <li><span class="ico">🛟</span><span><strong>Support intelligence:</strong> surface overdue SLA tickets and summarize root causes by account segment.<br><strong>Sample:</strong> "List tickets likely to breach SLA in 12 hours, grouped by priority, ARR, and issue cluster."</span></li>
          <li><span class="ico">📬</span><span><strong>Open tickets email response:</strong> find all open tickets, draft high-quality email answers, and send to the connected contact using BROSH single email.<br><strong>Sample:</strong> "Find all open tickets, draft a clear and helpful email reply for each issue based on ticket context, then send it to the connected user with brosh_send_message_single."</span></li>
          <li><span class="ico">🤝</span><span><strong>New leads welcome + meeting flow:</strong> find new leads, draft welcome emails from lead source, interest in description, and country/address, then offer meetings when none are scheduled.<br><strong>Sample:</strong> "Find all new leads, draft a personalized welcome email using lead source, interest from description, and country/address, send it to each lead, and if no meeting is scheduled then offer to schedule one, place it in my calendar, and log a CRM meeting activity linked to the lead."</span></li>
          <li><span class="ico">🔁</span><span><strong>Automation playbooks:</strong> run repeatable CRM workflows with consistent team-ready output.<br><strong>Sample:</strong> "Run Monday rev-ops checklist: stale deals, missing decision-makers, at-risk renewals, and owner actions."</span></li>
        </ul>
      </div>

      <div class="card">
        <h2>Use Cases By Function</h2>
        <p>Teams use BROSH MCP to automate repetitive CRM work and get faster answers from live business data.</p>
        <ul class="func-list">
          <li class="func-item">
            <h3>AI Data Enrichment</h3>
            <p>Enrich CRM records with missing firmographic and contact data using AI insights.<br><strong>Sample prompt:</strong> "Identify contacts missing title, industry, and company size, research relevant values, then update each record with confidence notes."</p>
          </li>
          <li class="func-item">
            <h3>Customer Prospecting</h3>
            <p>Discover new potential customers from market signals and automatically add them to CRM.<br><strong>Sample prompt:</strong> "Scan the stock exchange and suggest customers that may need my service/product, get their details, and enter them into the CRM."</p>
          </li>
          <li class="func-item">
            <h3>Sales Pipeline</h3>
            <p>Score leads, prioritize outreach, and predict revenue from qualified opportunities.<br><strong>Sample prompt:</strong> "Show SQL leads above score 80 with no call in 5 days and suggest the top 10 to contact today."</p>
          </li>
          <li class="func-item">
            <h3>CSV Import + Field Revision</h3>
            <p>Learn the CSV structure, detect missing CRM fields, then revise/add fields with MCP before import.<br><strong>Sample prompt:</strong> "Analyze this CSV, identify missing fields in contacts, create or modify the fields in BROSH CRM, then import all valid rows."</p>
          </li>
          <li class="func-item">
            <h3>Template Newsletter Send</h3>
            <p>Send campaign or newsletter emails directly from a CRM template with merge fields and approved sender sets.<br><strong>Sample prompt:</strong> "Use newsletter template 42, send to all active customers in segment SMB, and log delivery task as June Product Update."</p>
          </li>
          <li class="func-item">
            <h3>AI Tailored Email Outreach</h3>
            <p>Run market research per account/contact, generate a unique product message, then send one-by-one personalized emails through MCP.<br><strong>Sample prompt:</strong> "Research each target account, write a custom value proposition for our product, and send an individual tailored email to each contact."</p>
          </li>
          <li class="func-item">
            <h3>Customer Success</h3>
            <p>Review account timelines, update health notes, and flag churn signals earlier.<br><strong>Sample prompt:</strong> "List accounts with declining activity and open tickets, then draft next best actions for each CSM."</p>
          </li>
          <li class="func-item">
            <h3>Marketing Ops</h3>
            <p>Build audience segments, evaluate campaign ROI, and validate attribution quality.<br><strong>Sample prompt:</strong> "Find campaigns with CPC above target and low conversion rate, then recommend reallocation by channel."</p>
          </li>
          <li class="func-item">
            <h3>Support Teams</h3>
            <p>Create and manage tickets, monitor SLA risk, and summarize issue clusters.<br><strong>Sample prompt:</strong> "Show P1/P2 tickets at SLA risk in the next 12 hours grouped by account ARR and owner."</p>
          </li>
          <li class="func-item">
            <h3>Open Ticket Replies With Single Send</h3>
            <p>Find all open tickets, draft strong response emails, and send each response to the connected contact via one-by-one single-send email flow.<br><strong>Sample prompt:</strong> "Find all open tickets, draft a good email answer based on ticket details and customer context, and send it to the connected contact using BROSH single email (brosh_send_message_single)."</p>
          </li>
          <li class="func-item">
            <h3>New Lead Welcome + Calendar Scheduling</h3>
            <p>Find all new leads, craft welcome emails from lead source, description interest, and country/address, then handle meeting follow-up when no meeting exists.<br><strong>Sample prompt:</strong> "Find all new leads, write a personalized welcome email based on lead source, interest in the description field, and country/address location, send it to each lead, and if there is no scheduled meeting then offer one, put it in my calendar, and log a meeting activity connected to the lead in CRM."</p>
          </li>
          <li class="func-item">
            <h3>Executive Reporting</h3>
            <p>Generate board-ready summaries for pipeline, payments, retention, and activity.<br><strong>Sample prompt:</strong> "Generate this week's executive dashboard with pipeline coverage, win rate trend, and churn risk movement."</p>
          </li>
          <li class="func-item">
            <h3>Data Migration</h3>
            <p>Map fields from legacy systems, validate data quality, and bulk import safely.<br><strong>Sample prompt:</strong> "Map legacy CRM fields to BROSH schema and identify records that will fail import before execution."</p>
          </li>
        </ul>
      </div>
    </section>

    <section class="card" style="margin-bottom:18px">
      <h2>Simple Installation (No Login Required to View)</h2>
      <p>Setup is intentionally simple. You only need the MCP link and an OAuth sign-in when your client connects.</p>
      <div class="steps">
        <div class="step">
          <span class="n">1</span>
          <h3>Add MCP Link</h3>
          <p>Use <code>https://mcp.brosh.io</code> as your server URL in ChatGPT, Claude, VS Code, Cline, or any MCP client.</p>
        </div>
        <div class="step">
          <span class="n">2</span>
          <h3>Authenticate Once</h3>
          <p>Choose OAuth and sign in with your BROSH account. The server handles discovery and token exchange automatically.</p>
        </div>
        <div class="step">
          <span class="n">3</span>
          <h3>Start CRM Work</h3>
          <p>Ask in natural language to search leads, update records, create opportunities, manage tickets, and generate reports.</p>
        </div>
      </div>
      <div class="mini-grid">
        <div class="mini">
          <h3>Core Endpoints</h3>
          <p>OAuth discovery: <code>${SERVER_URL}/.well-known/oauth-authorization-server</code><br>API schema: <code>${SERVER_URL}${OPENAPI_PATH}</code></p>
        </div>
        <div class="mini">
          <h3>Open CRM</h3>
          <p>Need the full CRM interface? Open <a href="https://app.brosh.io" target="_blank" rel="noopener">app.brosh.io</a> anytime.</p>
        </div>
      </div>
    </section>

    <section class="card" style="margin-bottom:18px">
      <h2>How To Add In ChatGPT And Claude</h2>
      <p>The setup flow is almost identical in both clients.</p>
      <div class="steps">
        <div class="step">
          <span class="n">1</span>
          <h3>Give It A Name</h3>
          <p>Create a new connector/app and choose any name, for example <strong>BROSH CRM</strong>.</p>
        </div>
        <div class="step">
          <span class="n">2</span>
          <h3>Paste MCP URL</h3>
          <p>Paste <code>https://mcp.brosh.io</code> as the MCP server URL.</p>
        </div>
        <div class="step">
          <span class="n">3</span>
          <h3>Click Connect</h3>
          <p>Click connect/add, then complete OAuth login when prompted.</p>
        </div>
      </div>
      <div class="shot-grid">
        <div class="shot-card">
          <div class="shot-head">
            <h3>ChatGPT MCP Setup</h3>
            <span class="shot-tag">Screenshot</span>
          </div>
          <div class="shot-wrap">
            <img src="/.well-known/cpt_mcp.jpg" alt="ChatGPT MCP setup screen for BROSH CRM" class="zoomable-shot">
          </div>
          <ul class="shot-steps">
            <li>Open connectors/tools and create a new MCP connection.</li>
            <li>Name it <strong>BROSH CRM</strong> and paste <code>https://mcp.brosh.io</code>.</li>
            <li>Click connect and finish OAuth in the browser popup.</li>
          </ul>
        </div>
        <div class="shot-card">
          <div class="shot-head">
            <h3>Claude MCP Setup</h3>
            <span class="shot-tag">Screenshot</span>
          </div>
          <div class="shot-wrap">
            <img src="/.well-known/brosh_cload.jpg" alt="Claude MCP setup screen for BROSH CRM" class="zoomable-shot">
          </div>
          <ul class="shot-steps">
            <li>Add a new MCP server in Claude settings.</li>
            <li>Use server URL <code>https://mcp.brosh.io</code> and save.</li>
            <li>Authorize once, then start querying and updating CRM from chat.</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="card" style="margin-bottom:18px">
      <h2 class="section-title">Features</h2>
      <p class="section-sub">Everything you need to run BROSH CRM through MCP with security, speed, and automation.</p>
      <div class="features-grid">
        <div class="feature-card"><span class="feature-icon ic1"><i class="bi bi-shield-lock"></i></span><h3>Enterprise OAuth2</h3><p>Secure auth, scoped access, and robust session handling.</p></div>
        <div class="feature-card"><span class="feature-icon ic2"><i class="bi bi-database"></i></span><h3>Full CRUD</h3><p>Create, read, update, and delete records across key CRM tables.</p></div>
        <div class="feature-card"><span class="feature-icon ic3"><i class="bi bi-robot"></i></span><h3>AI Native</h3><p>Ask in natural language and execute multi-step CRM workflows.</p></div>
        <div class="feature-card"><span class="feature-icon ic4"><i class="bi bi-lightning-charge"></i></span><h3>Zero Config</h3><p>Add the MCP URL, sign in, and start using it in minutes.</p></div>
        <div class="feature-card"><span class="feature-icon ic5"><i class="bi bi-arrow-repeat"></i></span><h3>Token Auto Refresh</h3><p>Expired tokens are refreshed automatically when possible.</p></div>
        <div class="feature-card"><span class="feature-icon ic6"><i class="bi bi-diagram-3"></i></span><h3>OpenAI/Claude Ready</h3><p>Works with modern MCP clients and OAuth discovery flows.</p></div>
      </div>
    </section>

    <section class="card" style="margin-bottom:18px">
      <h2 class="section-title">Use Cases</h2>
      <p class="section-sub">Common ways teams use BROSH MCP in daily operations.</p>
      <div class="cases-grid">
        <div class="case-card"><h3>AI Data Enrichment</h3><ul><li>Detect missing CRM attributes automatically</li><li>Research and infer relevant values with AI</li><li>Sample prompt: "Tell me which account and contact fields are missing, enrich them with researched values, and update each record."</li></ul></div>
        <div class="case-card"><h3>Customer Prospecting</h3><ul><li>Scan public market activity for likely customer demand</li><li>Capture company and decision-maker details</li><li>Sample prompt: "Scan the stock exchange and suggest customers that may need my service/product, get their details, and enter them into the CRM."</li></ul></div>
        <div class="case-card"><h3>Sales Pipeline</h3><ul><li>Score leads and prioritize outreach</li><li>Track stage progression</li><li>Sample prompt: "List enterprise deals over 75k with no activity in 7 days and propose next steps."</li></ul></div>
        <div class="case-card"><h3>CSV Import With Field Revision</h3><ul><li>Learn CSV headers and compare against CRM schema</li><li>Create or modify missing fields through MCP before import</li><li>Sample prompt: "Review this CSV, add missing contact fields in BROSH CRM, and import the cleaned dataset."</li></ul></div>
        <div class="case-card"><h3>CRM Template Newsletter</h3><ul><li>Use existing CRM templates with dynamic fields</li><li>Send newsletter campaigns directly via MCP send-email tools</li><li>Sample prompt: "Send the monthly newsletter template to all customers with active subscriptions and include account-level merge fields."</li></ul></div>
        <div class="case-card"><h3>Custom AI Tailored Email</h3><ul><li>Research each customer/account before outreach</li><li>Generate and send one-by-one personalized product emails</li><li>Sample prompt: "Do market research for each lead, write a custom product pitch, and send each customer a tailored email via MCP."</li></ul></div>
        <div class="case-card"><h3>Customer Success</h3><ul><li>Review account history instantly</li><li>Update contact and account info</li><li>Sample prompt: "Find at-risk accounts with low usage and open tickets, then suggest recovery actions."</li></ul></div>
        <div class="case-card"><h3>Support Operations</h3><ul><li>Create and update tickets</li><li>Monitor SLA response times</li><li>Sample prompt: "Show all tickets that may breach SLA in 12 hours sorted by customer value."</li></ul></div>
      </div>
    </section>

    <section class="card" style="margin-bottom:18px">
      <h2 class="section-title">Who It’s For</h2>
      <p class="section-sub">Built for every role that needs fast CRM action from AI.</p>
      <div class="persona-grid">
        <div class="persona-card"><h3>Sales Teams</h3><ul><li>Update deals from chat</li><li>Access customer context live</li><li>Generate quick reports</li></ul></div>
        <div class="persona-card"><h3>Customer Success</h3><ul><li>Track health and support</li><li>Manage accounts faster</li><li>Reduce manual data entry</li></ul></div>
        <div class="persona-card"><h3>Executives & Ops</h3><ul><li>Get live KPI snapshots</li><li>Ask plain-English questions</li><li>Accelerate decisions</li></ul></div>
      </div>
    </section>

    <section class="card">
      <h2>OpenAI Responses API (MCP)</h2>
      <p>After login, use the issued MCP token as <code>authorization</code> and point <code>server_url</code> to the MCP endpoint.</p>
      <div class="snippet">{  "type": "mcp",
  "server_label": "brosh_crm",
  "server_url": "${SERVER_URL}${MCP_PATH}",
  "authorization": "&lt;brosh-mcp-access-token&gt;",
  "require_approval": "never"}</div>
      <p style="margin-top:12px;color:#4d6288;font-size:14px">Custom GPT Actions OAuth: <code>${SERVER_URL}${AUTHORIZE_PATH}</code> and <code>${SERVER_URL}${TOKEN_PATH}</code></p>
      <div class="mini-grid">
        <div class="mini">
          <h3>Common Prompt Examples</h3>
          <p>"Show enterprise leads created in the last 14 days with score above 80 and no call logged in 5 days."<br>"Create a renewal opportunity for Acme Q3 Expansion, value 120000, close date Sep 30, owner Sarah."<br>"List support tickets breaching SLA in the next 12 hours, grouped by priority and account ARR."<br>"Find all open tickets, draft a good email answer for each, and send to the connected contact with brosh_send_message_single."<br>"Find all new leads, write personalized welcome emails using lead source + description interest + country/address, send them, and if no meeting exists then offer and schedule one in my calendar and log a meeting activity in CRM."</p>
        </div>
        <div class="mini">
          <h3>Automation Scenarios</h3>
          <p>Auto-generate follow-up tasks after discovery calls, summarize weekly account risk changes, and build manager-ready pipeline digests in seconds. These scenarios can be scheduled in Codex or Claude as repeatable task runs.</p>
        </div>
      </div>
    </section>

    <section class="card" style="margin-top:18px">
      <h2>Benefits of Using MCP</h2>
      <p>Model Context Protocol turns BROSH into an AI-ready CRM platform with secure, scalable connectivity for real business workflows.</p>
      <ul class="list">
        <li><span class="ico"><i class="bi bi-shield-lock"></i></span><span><strong>Secure OAuth2 architecture:</strong> standards-based authorization, scoped access, and automatic token refresh support.</span></li>
        <li><span class="ico"><i class="bi bi-lightning-charge"></i></span><span><strong>Fast enterprise rollout:</strong> one MCP URL for ChatGPT, Claude, VS Code, and compatible AI assistants.</span></li>
        <li><span class="ico"><i class="bi bi-bar-chart"></i></span><span><strong>Full CRM API coverage:</strong> read, create, update, and delete records across sales, support, and operations data.</span></li>
        <li><span class="ico"><i class="bi bi-cpu"></i></span><span><strong>Higher team productivity:</strong> replace repetitive manual CRM clicks with natural-language commands.</span></li>
      </ul>
    </section>

    <div class="footer">BROSH AI CRM | MCP-ready API server</div>
  </div>
  <script src="/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
  <div id="agentModal" class="agent-modal" aria-hidden="true">
    <div class="agent-modal-card" role="dialog" aria-modal="true" aria-labelledby="agentModalTitle">
      <div class="agent-modal-head">
        <div>
          <h3 id="agentModalTitle">Connect BROSH MCP</h3>
          <p id="agentModalSub">Copy this prompt and paste it into your selected agent.</p>
        </div>
        <button type="button" class="agent-close" id="agentModalClose" aria-label="Close">×</button>
      </div>
      <div id="agentPromptText" class="agent-prompt"></div>
      <div class="agent-modal-actions">
        <button type="button" id="agentCopyBtn" class="agent-copy">Copy prompt</button>
        <a id="agentOpenLink" class="btn btn-soft agent-open-link" href="https://claude.ai/chats" target="_blank" rel="noopener">Open agent</a>
      </div>
    </div>
  </div>
  <div id="shotLightbox" class="lightbox" aria-hidden="true">
    <button type="button" class="lightbox-close" aria-label="Close image viewer">×</button>
    <img id="shotLightboxImg" alt="Expanded setup screenshot">
    <div class="lightbox-hint">Click image, press Esc, or click outside to close</div>
  </div>
  <script>
    (function () {
      var lightbox = document.getElementById('shotLightbox');
      var lightboxImg = document.getElementById('shotLightboxImg');
      var closeBtn = lightbox ? lightbox.querySelector('.lightbox-close') : null;
      var zoomables = document.querySelectorAll('.zoomable-shot');
      var agentConnect = document.querySelector('.agent-connect');
      var agentGrid = document.getElementById('agentGrid');
      var agentSearch = document.getElementById('agentSearch');
      var agentEmpty = document.getElementById('agentEmpty');
      var otherAgents = document.getElementById('otherAgents');
      var agentOthersToggle = document.getElementById('agentOthersToggle');
      var agentModal = document.getElementById('agentModal');
      var agentModalClose = document.getElementById('agentModalClose');
      var agentPromptText = document.getElementById('agentPromptText');
      var agentModalTitle = document.getElementById('agentModalTitle');
      var agentModalSub = document.getElementById('agentModalSub');
      var agentCopyBtn = document.getElementById('agentCopyBtn');
      var agentOpenLink = document.getElementById('agentOpenLink');
      var currentPrompt = '';
      var othersExpanded = false;

      var agentPrompts = {
        claude: {
          name: 'Claude',
          launchUrl: 'https://claude.ai/chats',
          prompt: 'Connect BROSH MCP for me using https://mcp.brosh.io. If the connector is not installed, install brosh-crm-mcp. Then run OAuth authentication and validate the connection by listing available BROSH MCP tools.'
        },
        chatgpt: {
          name: 'ChatGPT',
          launchUrl: 'https://chat.openai.com',
          prompt: 'Help me connect BROSH MCP. Configure the MCP server using https://mcp.brosh.io, complete OAuth, and verify by running a simple query for the latest contacts.'
        },
        cursor: {
          name: 'Cursor',
          launchUrl: 'https://cursor.com',
          prompt: 'Set up BROSH MCP in this workspace using https://mcp.brosh.io. Create or update .vscode/mcp.json to use npx brosh-crm-mcp, complete OAuth sign-in, and run a sample lead search query.'
        },
        copilot: {
          name: 'Microsoft Copilot',
          launchUrl: 'https://code.visualstudio.com/docs/copilot/overview',
          prompt: 'Configure BROSH MCP in Microsoft Copilot/VS Code MCP settings using https://mcp.brosh.io (or npx brosh-crm-mcp). Start OAuth authentication, then validate the token and fetch a short list of contacts.'
        },
        gemini: {
          name: 'Gemini',
          launchUrl: 'https://gemini.google.com',
          prompt: 'Connect BROSH MCP in Gemini using https://mcp.brosh.io. Complete OAuth authentication, then verify access by listing the latest contacts and available BROSH MCP tools.'
        },
        grok: {
          name: 'Grok',
          launchUrl: 'https://grok.com',
          prompt: 'Connect BROSH MCP in Grok using https://mcp.brosh.io. Add it as an MCP connector/tool, complete OAuth authentication, and verify access by listing the latest contacts and available BROSH MCP tools.'
        },
        cline: {
          name: 'Cline',
          launchUrl: 'https://github.com/cline/cline',
          prompt: 'Add BROSH MCP to Cline using https://mcp.brosh.io (or npx brosh-crm-mcp), complete OAuth, and verify with this query: Find leads created in the last 7 days sorted by score.'
        },
        openclaw: {
          name: 'OpenClaw',
          launchUrl: 'https://openclaw.ai',
          prompt: 'Connect BROSH MCP in OpenClaw using https://mcp.brosh.io. Complete OAuth authentication and validate by listing recent contacts and available BROSH tools.'
        },
        ollama: {
          name: 'Ollama',
          launchUrl: 'https://ollama.com',
          prompt: 'Set up BROSH MCP with Ollama using https://mcp.brosh.io. Complete OAuth, then run a test query to fetch recent opportunities and confirm MCP tool availability.'
        }
      };

      function setOthersOpen(isOpen) {
        if (!otherAgents || !agentOthersToggle) return;
        otherAgents.classList.toggle('open', isOpen);
        agentOthersToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        agentOthersToggle.textContent = isOpen ? 'Hide others' : 'Show others';
      }

      function closeAgentModal() {
        if (!agentModal) return;
        agentModal.classList.remove('open');
        agentModal.setAttribute('aria-hidden', 'true');
      }

      function openAgentModal(agentKey) {
        var data = agentPrompts[agentKey];
        if (!data || !agentModal || !agentPromptText || !agentModalTitle || !agentModalSub || !agentOpenLink || !agentCopyBtn) return;
        currentPrompt = data.prompt;
        agentModalTitle.textContent = 'Connect BROSH MCP with ' + data.name;
        agentModalSub.textContent = 'Copy this prompt and paste it into ' + data.name + '.';
        agentPromptText.textContent = data.prompt;
        agentOpenLink.href = data.launchUrl;
        agentOpenLink.textContent = 'Open ' + data.name;
        agentCopyBtn.textContent = 'Copy prompt';
        agentCopyBtn.classList.remove('copied');
        agentModal.classList.add('open');
        agentModal.setAttribute('aria-hidden', 'false');
      }

      function fallbackCopyText(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }

      if (agentConnect) {
        agentConnect.addEventListener('click', function (event) {
          var target = event.target;
          if (!target) return;
          var card = target.closest('.agent-tile');
          if (!card) return;
          openAgentModal(card.getAttribute('data-agent'));
        });
      }

      if (agentOthersToggle) {
        setOthersOpen(false);
        agentOthersToggle.addEventListener('click', function () {
          othersExpanded = !othersExpanded;
          if (!agentSearch || !(agentSearch.value || '').trim()) {
            setOthersOpen(othersExpanded);
          }
        });
      }

      if (agentSearch) {
        agentSearch.addEventListener('input', function () {
          var query = (agentSearch.value || '').trim().toLowerCase();
          var cards = document.querySelectorAll('.agent-tile');
          var visible = 0;
          var otherVisible = 0;

          if (!query) {
            cards.forEach(function (card) {
              card.style.display = 'block';
            });
            setOthersOpen(othersExpanded);
            if (agentEmpty) agentEmpty.style.display = 'none';
            return;
          }

          cards.forEach(function (card) {
            var hay = (card.getAttribute('data-search') || '').toLowerCase();
            var show = !query || hay.indexOf(query) !== -1;
            card.style.display = show ? 'block' : 'none';
            if (show) {
              visible += 1;
              if (card.closest('#otherAgents')) otherVisible += 1;
            }
          });

          setOthersOpen(otherVisible > 0);

          if (agentEmpty) {
            agentEmpty.style.display = visible ? 'none' : 'block';
          }
        });
      }

      if (agentCopyBtn) {
        agentCopyBtn.addEventListener('click', function () {
          if (!currentPrompt) return;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(currentPrompt).catch(function () {
              fallbackCopyText(currentPrompt);
            });
          } else {
            fallbackCopyText(currentPrompt);
          }
          agentCopyBtn.textContent = 'Copied';
          agentCopyBtn.classList.add('copied');
          setTimeout(function () {
            if (!agentCopyBtn) return;
            agentCopyBtn.textContent = 'Copy prompt';
            agentCopyBtn.classList.remove('copied');
          }, 1300);
        });
      }

      if (agentModalClose) {
        agentModalClose.addEventListener('click', closeAgentModal);
      }

      if (agentModal) {
        agentModal.addEventListener('click', function (event) {
          if (event.target === agentModal) {
            closeAgentModal();
          }
        });
      }

      function closeLightbox() {
        if (!lightbox || !lightboxImg) return;
        lightbox.classList.remove('open');
        lightbox.setAttribute('aria-hidden', 'true');
        lightboxImg.removeAttribute('src');
      }

      zoomables.forEach(function (img) {
        img.addEventListener('click', function () {
          if (!lightbox || !lightboxImg) return;
          var src = img.getAttribute('src');
          var alt = img.getAttribute('alt') || 'Expanded setup screenshot';
          if (!src) return;
          lightboxImg.setAttribute('src', src);
          lightboxImg.setAttribute('alt', alt);
          lightbox.classList.add('open');
          lightbox.setAttribute('aria-hidden', 'false');
        });
      });

      if (closeBtn) closeBtn.addEventListener('click', closeLightbox);

      if (lightbox) {
        lightbox.addEventListener('click', function (event) {
          if (event.target === lightbox || event.target === lightboxImg) {
            closeLightbox();
          }
        });
      }

      document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
          closeLightbox();
          closeAgentModal();
        }
      });
    })();
  </script>
</body>
</html>`);
});

app.get("/.well-known/cpt_mcp.jpg", (_req: Request, res: Response) => {
  const filePath = path.join(
    process.cwd(),
    "www",
    "mcp",
    ".well-known",
    "cpt_mcp.jpg",
  );
  if (!fs.existsSync(filePath)) {
    res.status(404).send("Image not found");
    return;
  }
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(filePath);
});

app.get("/.well-known/brosh_cload.jpg", (_req: Request, res: Response) => {
  const filePath = path.join(
    process.cwd(),
    "www",
    "mcp",
    ".well-known",
    "brosh_cload.jpg",
  );
  if (!fs.existsSync(filePath)) {
    res.status(404).send("Image not found");
    return;
  }
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(filePath);
});

// ─── Health Check ──────────────────────────────────────────────────────────────

app.get([HEALTH_PATH, "/health"], (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    activeSessions: sessions.size,
    serverUrl: SERVER_URL,
    broshBaseUrl: BROSH_BASE_URL,
    timestamp: new Date().toISOString(),
  });
});

// ─── OAuth2 — Web Login (users authenticate directly in browser) ───────────────

app.get([LOGIN_PATH, "/oauth/login"], (_req: Request, res: Response) => {
  const state = crypto.randomBytes(32).toString("hex");
  oauthStates.set(state, { createdAt: Date.now() });
  saveOAuthStates();
  const authUrl = buildBroshAuthUrl(state, `${SERVER_URL}${CALLBACK_PATH}`);
  res.redirect(authUrl);
});

// ─── OAuth2 — OpenAI Authorize Endpoint ───────────────────────────────────────
// OpenAI redirects the user here to start the OAuth flow for a Custom GPT Action.

app.get(
  [AUTHORIZE_PATH, "/oauth/authorize"],
  async (req: Request, res: Response) => {
    const {
      client_id,
      redirect_uri,
      resource,
      state,
      scope,
      nonce,
      code_challenge,
      code_challenge_method,
    } = req.query as Record<string, string>;

    if (!redirect_uri) {
      res.status(400).send("Missing redirect_uri");
      return;
    }

    let requestedResource: string;
    try {
      requestedResource = resolveRequestedResource(resource);
    } catch (err: unknown) {
      res.status(400).json({
        error: "invalid_target",
        error_description: String(err),
      });
      return;
    }

    // PKCE: only S256 and plain are accepted; MCP spec recommends S256
    if (
      code_challenge &&
      code_challenge_method &&
      !["S256", "plain"].includes(code_challenge_method)
    ) {
      res.status(400).json({
        error: "invalid_request",
        error_description:
          "Unsupported code_challenge_method. Use S256 (recommended) or plain.",
      });
      return;
    }

    try {
      await validateClientAuthorizationRequest(client_id, redirect_uri);
    } catch (err: unknown) {
      res.status(400).json({
        error: "unauthorized_client",
        error_description: String(err),
      });
      return;
    }

    // Map our internal BROSH state → OpenAI's redirect info + OIDC/PKCE params
    const broshState = crypto.randomBytes(32).toString("hex");
    oauthStates.set(broshState, {
      openaiRedirectUri: redirect_uri,
      openaiState: state,
      clientId: client_id,
      requestedScope: scope,
      requestedResource,
      nonce,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      createdAt: Date.now(),
    });
    saveOAuthStates();

    const authUrl = buildBroshAuthUrl(
      broshState,
      `${SERVER_URL}${CALLBACK_PATH}`,
    );
    res.redirect(authUrl);
  },
);

// ─── OAuth2 — BROSH Callback ───────────────────────────────────────────────────
// BROSH redirects here with `code` + `state` after user authorises.

app.get(
  [CALLBACK_PATH, "/oauth/callback"],
  async (req: Request, res: Response) => {
    const { code, state, error } = req.query as Record<string, string>;

    if (error) {
      res.status(400).send(errorPage("Authentication Denied", error));
      return;
    }
    if (!code || !state) {
      res
        .status(400)
        .send(
          errorPage("Invalid Callback", "Missing code or state parameter."),
        );
      return;
    }

    const stateData = oauthStates.get(state);
    if (!stateData) {
      const consumed = consumedOAuthStates.get(state);
      if (
        consumed?.callbackUrl &&
        Date.now() - consumed.consumedAt <= CONSUMED_STATE_REPLAY_TTL_MS
      ) {
        deliverOAuthCallback(res, consumed.callbackUrl);
        return;
      }
      res
        .status(400)
        .send(
          errorPage(
            "Invalid State",
            "The OAuth state is invalid or has expired. Please try again.",
          ),
        );
      return;
    }
    oauthStates.delete(state);
    saveOAuthStates();

    // Exchange code for BROSH tokens
    let tokens: {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
    };
    try {
      const tokenRes = await axios.post(
        `${BROSH_BASE_URL}/api/oauth2/token/${BROSH_SOURCE}`,
        {
          code,
          redirect_uri: `${SERVER_URL}${CALLBACK_PATH}`,
          client_id: BROSH_CLIENT_ID,
          client_secret: BROSH_CLIENT_SECRET_VAL,
          grant_type: "authorization_code",
        },
        {
          headers: { "Content-Type": "application/json" },
        },
      );
      tokens = tokenRes.data;
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? JSON.stringify(err.response?.data || err.message)
        : String(err);
      res.status(500).send(errorPage("Token Exchange Failed", msg));
      return;
    }

    // Create server-side session
    const sessionId = uuidv4();
    const session: UserSession = {
      id: sessionId,
      broshAccessToken: tokens.access_token,
      broshRefreshToken: tokens.refresh_token,
      broshTokenExpiresAt: tokens.expires_in
        ? Date.now() + tokens.expires_in * 1000
        : Date.now() + SESSION_TTL_MS,
      sessionExpiresAt: Date.now() + SESSION_TTL_MS,
      tokenAudience: stateData.requestedResource ?? ROOT_RESOURCE,
      // Forward OIDC / PKCE fields from the authorization request
      requestedScope: stateData.requestedScope,
      nonce: stateData.nonce,
      codeChallenge: stateData.codeChallenge,
      codeChallengeMethod: stateData.codeChallengeMethod,
      createdAt: Date.now(),
    };

    // Fetch user info — captures name and email for OIDC id_token / userinfo claims
    try {
      const me = await broshRequest(
        "POST",
        `/api/oauth2/me/${BROSH_SOURCE}`,
        tokens.access_token,
        {},
      );
      session.userInfo = me as UserSession["userInfo"];
    } catch {
      /* ignore */
    }

    try {
      const { tables, fieldsByTable } = await fetchAvailableTablesForSession(
        tokens.access_token,
      );
      if (tables.length > 0) {
        session.availableTables = tables;
        session.availableTableFields = fieldsByTable;
      }
      console.log(
        `[Auth] Loaded ${tables.length} available tables for session ${sessionId}`,
      );
    } catch (err: unknown) {
      console.warn(
        "[Auth] Failed to load available tables for session. Falling back to static list.",
        err,
      );
    }

    sessions.set(sessionId, session);
    saveSessions();

    // ── Case A: Triggered by OpenAI GPT OAuth flow ─────────────────────────────
    if (stateData.openaiRedirectUri) {
      const authCode = crypto.randomBytes(32).toString("hex");
      authorizationCodes.set(authCode, {
        sessionId,
        clientId: stateData.clientId,
        redirectUri: stateData.openaiRedirectUri,
        requestedResource: stateData.requestedResource ?? ROOT_RESOURCE,
        expiresAt: Date.now() + AUTH_CODE_TTL_MS,
        createdAt: Date.now(),
      });
      const redirectUrl = new URL(stateData.openaiRedirectUri);
      redirectUrl.searchParams.set("code", authCode);
      if (stateData.openaiState)
        redirectUrl.searchParams.set("state", stateData.openaiState);
      const callbackUrl = redirectUrl.toString();
      consumedOAuthStates.set(state, {
        callbackUrl,
        consumedAt: Date.now(),
      });
      deliverOAuthCallback(res, callbackUrl);
      return;
    }

    // ── Case B: Direct web login — confirm connection without exposing tokens ─
    const userName = session.userInfo?.name || "User";

    res.setHeader("Content-Type", "text/html; charset=UTF-8");
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM — Connected</title>
  <link rel="icon" href="https://www.brosh.io/favicon.ico">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;
      display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.3);
      padding:48px;max-width:560px;width:100%;text-align:center}
    .icon{font-size:64px;margin-bottom:16px}
    h1{font-size:26px;font-weight:700;margin-bottom:8px;
      background:linear-gradient(135deg,#667eea,#764ba2);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    p{color:#4a5568;font-size:15px;line-height:1.6;margin-bottom:12px}
    .status{background:#ebf8ff;border-left:4px solid #63b3ed;padding:16px 18px;
      border-radius:8px;text-align:left;margin-top:20px}
    .status p{font-size:14px;color:#2c5282;margin-bottom:8px}
    a{color:#667eea;font-weight:600;text-decoration:none}
    a.home{display:inline-block;margin-top:20px;font-size:14px}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Connected to BROSH CRM!</h1>
    <p>Welcome, <strong>${escapeHtml(userName)}</strong>.</p>
    <p>Your BROSH CRM account is connected successfully.</p>

    <div class="status">
      <p><strong>Connection complete.</strong></p>
      <p>You can close this window and return to your AI assistant.</p>
    </div>

    <a class="home" href="/">← Back to Server Status</a>
  </div>
</body>
</html>`);
  },
);

// ─── OAuth2 — Token Endpoint (called by OpenAI after redirect) ────────────────
// OpenAI exchanges the `code` (our sessionId) for a JWT access token here.
// Supports both JSON body and application/x-www-form-urlencoded (RFC 6749 §4.1.3).
// Client credentials can be in the body OR in an HTTP Basic Auth header (RFC 6749 §2.3).

app.post([TOKEN_PATH, "/oauth/token"], (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  const { grant_type, code, redirect_uri, refresh_token, resource } = body;
  let { client_id, client_secret } = body;

  // Also accept client credentials via HTTP Basic Auth header (RFC 6749 §2.3.1)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const [basicId, basicSecret] = decoded.split(":").map(decodeURIComponent);
    if (!client_id) client_id = basicId;
    if (!client_secret) client_secret = basicSecret;
  }

  // Client authentication mode matrix:
  // 1) DCR clients: validate against registered auth method/secret.
  // 2) CIMD clients (URL client_id): treat as public clients (none/private_key_jwt path).
  // 3) Static OpenAI credentials: enforce configured client_id/client_secret.
  if (client_id && registeredClients.has(client_id)) {
    // DCR client — verify secret (skip for public clients with auth_method=none)
    const reg = registeredClients.get(client_id)!;
    if (
      reg.token_endpoint_auth_method !== "none" &&
      reg.client_secret !== client_secret
    ) {
      res
        .status(401)
        .json({
          error: "invalid_client",
          error_description: "Client secret mismatch.",
        });
      return;
    }
  } else if (client_id && isUrlClientId(client_id)) {
    // CIMD public client (none/private_key_jwt). No client_secret validation here.
  } else if (OPENAI_CLIENT_ID && OPENAI_CLIENT_SECRET) {
    if (
      client_id !== OPENAI_CLIENT_ID ||
      client_secret !== OPENAI_CLIENT_SECRET
    ) {
      res
        .status(401)
        .json({
          error: "invalid_client",
          error_description: "Client authentication failed.",
        });
      return;
    }
  }
  // URL-based client_ids (CIMD) and unconfigured deployments are accepted as public clients

  if (grant_type === "authorization_code" && code) {
    const authorizationCode = authorizationCodes.get(code);
    if (!authorizationCode || authorizationCode.expiresAt < Date.now()) {
      authorizationCodes.delete(code);
      res
        .status(400)
        .json({
          error: "invalid_grant",
          error_description: "Code not found or expired.",
        });
      return;
    }
    if (
      authorizationCode.clientId &&
      client_id &&
      client_id !== authorizationCode.clientId
    ) {
      res
        .status(400)
        .json({
          error: "invalid_grant",
          error_description: "Client ID does not match authorization code.",
        });
      return;
    }
    if (redirect_uri !== authorizationCode.redirectUri) {
      res
        .status(400)
        .json({
          error: "invalid_grant",
          error_description: "redirect_uri does not match authorization code.",
        });
      return;
    }

    let requestedAudience: string;
    try {
      requestedAudience = resolveRequestedResource(resource);
    } catch (err: unknown) {
      res
        .status(400)
        .json({ error: "invalid_target", error_description: String(err) });
      return;
    }
    if (requestedAudience !== authorizationCode.requestedResource) {
      res
        .status(400)
        .json({
          error: "invalid_target",
          error_description:
            "resource does not match the original authorization request.",
        });
      return;
    }

    authorizationCodes.delete(code);

    const session = sessions.get(authorizationCode.sessionId);
    if (!session) {
      res
        .status(400)
        .json({
          error: "invalid_grant",
          error_description: "Session not found or expired.",
        });
      return;
    }

    // ── PKCE verification ────────────────────────────────────────────────────
    if (session.codeChallenge) {
      const codeVerifier = body.code_verifier;
      if (!codeVerifier) {
        res
          .status(400)
          .json({
            error: "invalid_request",
            error_description: "code_verifier is required for this grant.",
          });
        return;
      }
      const method = session.codeChallengeMethod ?? "plain";
      if (!verifyPkce(codeVerifier, session.codeChallenge, method)) {
        res
          .status(400)
          .json({
            error: "invalid_grant",
            error_description:
              "PKCE code_verifier does not match code_challenge.",
          });
        return;
      }
      // One-time use: clear PKCE fields from session
      session.codeChallenge = undefined;
      session.codeChallengeMethod = undefined;
      sessions.set(session.id, session);
    }

    session.tokenAudience = requestedAudience;
    sessions.set(session.id, session);
    saveSessions();

    const accessToken = signJwt(session.id, requestedAudience);
    const nextRefreshToken = signRefreshToken(session.id, requestedAudience);
    const tokenResponse: Record<string, unknown> = {
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SEC,
      scope: session.requestedScope ?? "Full",
    };

    // ── OIDC: issue id_token when "openid" scope was requested ──────────────
    const requestedScopes = (session.requestedScope ?? "").split(/\s+/);
    if (requestedScopes.includes("openid")) {
      tokenResponse.id_token = mintIdToken(
        session,
        client_id ||
          authorizationCode.clientId ||
          OPENAI_CLIENT_ID ||
          BROSH_CLIENT_ID,
        session.nonce,
      );
    }

    res.json(tokenResponse);
    return;
  }

  if (grant_type === "refresh_token" && refresh_token) {
    try {
      const payload = jwt.verify(refresh_token, JWT_SECRET, {
        issuer: SERVER_URL,
      }) as jwt.JwtPayload & {
        sessionId: string;
        token_use?: string;
      };
      if (payload.token_use !== "refresh") {
        throw new Error("Invalid refresh token.");
      }
      if (!sessions.has(payload.sessionId)) {
        res
          .status(400)
          .json({
            error: "invalid_grant",
            error_description: "Session not found.",
          });
        return;
      }
      const refreshAudience = getTokenAudience(payload) ?? ROOT_RESOURCE;
      let requestedAudience: string;
      try {
        requestedAudience = resolveRequestedResource(
          resource ?? refreshAudience,
        );
      } catch (err: unknown) {
        res
          .status(400)
          .json({ error: "invalid_target", error_description: String(err) });
        return;
      }
      if (requestedAudience !== refreshAudience) {
        res
          .status(400)
          .json({
            error: "invalid_target",
            error_description:
              "resource does not match the refresh token audience.",
          });
        return;
      }
      const newToken = signJwt(payload.sessionId, requestedAudience);
      const rotatedRefreshToken = signRefreshToken(
        payload.sessionId,
        requestedAudience,
      );
      res.json({
        access_token: newToken,
        refresh_token: rotatedRefreshToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SEC,
      });
    } catch {
      res
        .status(400)
        .json({
          error: "invalid_grant",
          error_description: "Invalid refresh token.",
        });
    }
    return;
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// ─── OAuth2 — Token Revocation Endpoint (RFC 7009) ───────────────────────────
// Revokes an access_token or refresh_token by invalidating the underlying
// session. Per RFC 7009, unknown or already-revoked tokens still return HTTP 200.

app.post([REVOKE_PATH, "/oauth/revoke"], (req: Request, res: Response) => {
  const body = req.body as Record<string, string | undefined>;
  const { token, token_type_hint } = body;
  let { client_id, client_secret } = body;

  if (!token) {
    res
      .status(400)
      .json({
        error: "invalid_request",
        error_description: "token is required.",
      });
    return;
  }

  // Also accept client credentials via HTTP Basic Auth header (RFC 6749 §2.3.1)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const [basicId, basicSecret] = decoded.split(":").map(decodeURIComponent);
    if (!client_id) client_id = basicId;
    if (!client_secret) client_secret = basicSecret;
  }

  // Keep client auth policy aligned with the token endpoint.
  if (client_id && registeredClients.has(client_id)) {
    const reg = registeredClients.get(client_id)!;
    if (
      reg.token_endpoint_auth_method !== "none" &&
      reg.client_secret !== client_secret
    ) {
      res
        .status(401)
        .json({
          error: "invalid_client",
          error_description: "Client secret mismatch.",
        });
      return;
    }
  } else if (client_id && isUrlClientId(client_id)) {
    // CIMD public client (none/private_key_jwt). No client_secret validation here.
  } else if (OPENAI_CLIENT_ID && OPENAI_CLIENT_SECRET) {
    if (
      client_id !== OPENAI_CLIENT_ID ||
      client_secret !== OPENAI_CLIENT_SECRET
    ) {
      res
        .status(401)
        .json({
          error: "invalid_client",
          error_description: "Client authentication failed.",
        });
      return;
    }
  }

  let sessionId: string | undefined;
  const canTryAccess =
    !token_type_hint || token_type_hint === "access_token";
  const canTryRefresh =
    !token_type_hint || token_type_hint === "refresh_token";

  if (canTryAccess) {
    try {
      const payload = verifyAccessToken(token, [
        ROOT_RESOURCE,
        API_RESOURCE,
        MCP_RESOURCE,
        LEGACY_MCP_RESOURCE,
      ]);
      sessionId = payload.sessionId;
    } catch {
      // Ignore and continue to refresh-token verification.
    }
  }

  if (!sessionId && canTryRefresh) {
    try {
      const payload = jwt.verify(token, JWT_SECRET, {
        issuer: SERVER_URL,
      }) as jwt.JwtPayload & { sessionId?: string; token_use?: string };
      if (payload.token_use === "refresh" && payload.sessionId) {
        sessionId = payload.sessionId;
      }
    } catch {
      // Per RFC 7009, invalid token still returns 200.
    }
  }

  if (sessionId && sessions.delete(sessionId)) {
    saveSessions();
  }

  res.status(200).end();
});

// ─── CRM API Routes ────────────────────────────────────────────────────────────

// ─── OIDC — UserInfo Endpoint ───────────────────────────────────────────────────
// Returns OIDC claims for the authenticated session (OIDC Core §5.3).
// ChatGPT calls this after token exchange to fetch the user's email for
// authorization domain claiming. Supports both GET and POST per the spec.

app.get(
  [USERINFO_PATH, "/oauth/userinfo"],
  requireAuth as express.RequestHandler,
  (req: Request, res: Response) => {
    res.json(buildUserinfoClaims((req as AuthRequest).userSession));
  },
);

app.post(
  [USERINFO_PATH, "/oauth/userinfo"],
  requireAuth as express.RequestHandler,
  (req: Request, res: Response) => {
    res.json(buildUserinfoClaims((req as AuthRequest).userSession));
  },
);

var VALID_TABLES = new Set([
  "accounts",
  "activity",
  "campaigns",
  "contacts",
  "currency",
  "icon",
  "menu",
  "objects",
  "opportunities",
  "opportunity_products",
  "payments",
  "email_settings",
  "products",
  "projects",
  "templates",
  "tickets",
  "timesheet",
  "users",
  "views",
]);

function isTableAllowedForSession(
  session: UserSession | undefined,
  tableName: string,
): boolean {
  const normalized = normalizeTableName(tableName);
  if (!normalized) return false;
  if (!isEnglishTableName(normalized)) return false;
  if (session?.availableTables && session.availableTables.length > 0) {
    return session.availableTables.includes(normalized);
  }
  return VALID_TABLES.has(normalized);
}

function resolveAllowedTableName(
  session: UserSession | undefined,
  tableName: unknown,
): string {
  const normalized = normalizeTableName(tableName);
  if (!normalized || !isEnglishTableName(normalized)) {
    throw new Error(
      "Table name must be English letters, numbers, and underscores, and must start with a letter.",
    );
  }
  if (!isTableAllowedForSession(session, normalized)) {
    const allowed =
      session?.availableTables && session.availableTables.length > 0
        ? session.availableTables
        : [...VALID_TABLES];
    throw new Error(
      `Invalid table: ${normalized}. Available tables: ${allowed.join(", ")}`,
    );
  }
  return normalized;
}

function validateTableMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const { table } = req.params;
  const session = (req as Partial<AuthRequest>).userSession;
  let normalizedTable: string;
  try {
    normalizedTable = resolveAllowedTableName(session, table);
  } catch {
    const allowed =
      session?.availableTables && session.availableTables.length > 0
        ? session.availableTables
        : [...VALID_TABLES];
    res.status(400).json({
      error: `Invalid table name: "${table}". Valid tables: ${allowed.join(", ")}`,
    });
    return;
  }
  req.params.table = normalizedTable;
  next();
}

// GET /api/me — validate token and return current user info
app.get(
  "/api/me",
  requireAuth as express.RequestHandler,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    try {
      const data = await broshRequest(
        "POST",
        `/api/oauth2/me/${BROSH_SOURCE}`,
        session.broshAccessToken,
        {},
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// POST /api/:table/get — get records by array of IDs
app.post(
  "/api/:table/get",
  requireAuth as express.RequestHandler,
  validateTableMiddleware,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    const { table } = req.params;
    const { ids, limit } = req.body as { ids: number[]; limit?: number };

    if (!Array.isArray(ids) || ids.length === 0) {
      res
        .status(400)
        .json({ error: "`ids` must be a non-empty array of numbers." });
      return;
    }

    try {
      const data = await broshRequest(
        "POST",
        `/api/oauth2/getRecords/${BROSH_SOURCE}/${table}?limit=${limit}`,
        session.broshAccessToken,
        ids,
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// POST /api/:table/find — flexible search with filters, sort, pagination
app.post(
  "/api/:table/find",
  requireAuth as express.RequestHandler,
  validateTableMiddleware,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    const { table } = req.params;
    const { fields, filter, sort, page_size, page, limit } = req.body as Record<
      string,
      unknown
    >;

    const body: Record<string, unknown> = {};
    if (fields !== undefined) body.fields = fields;
    if (filter !== undefined) body.filter = filter;
    if (sort !== undefined) body.sort = sort;
    if (page_size !== undefined || limit !== undefined)
      body.page_size = page_size || limit || 10;
    if (page !== undefined) body.page = page;

    try {
      let url = `/api/oauth2/findRecords/${BROSH_SOURCE}/${table}`;
      if (limit !== undefined) {
        url += `?limit=${limit}`;
      }

      const data = await broshRequest(
        "POST",
        url,
        session.broshAccessToken,
        body,
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// POST /api/:table/create — create one or more records
app.post(
  "/api/:table/create",
  requireAuth as express.RequestHandler,
  validateTableMiddleware,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    const { table } = req.params;

    if (!Array.isArray(req.body) || req.body.length === 0) {
      res
        .status(400)
        .json({
          error: "Request body must be a non-empty array of record objects.",
        });
      return;
    }

    try {
      const data = await broshRequest(
        "POST",
        `/api/oauth2/create/${BROSH_SOURCE}/${table}`,
        session.broshAccessToken,
        req.body,
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// POST /api/:table/update — update one or more records (each must have `id`)
app.post(
  "/api/:table/update",
  requireAuth as express.RequestHandler,
  validateTableMiddleware,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    const { table } = req.params;

    if (!Array.isArray(req.body) || req.body.length === 0) {
      res
        .status(400)
        .json({
          error: "Request body must be a non-empty array of record objects.",
        });
      return;
    }
    if (!req.body.every((r: Record<string, unknown>) => r.id !== undefined)) {
      res
        .status(400)
        .json({
          error: "Each record in the array must include an `id` field.",
        });
      return;
    }

    try {
      const data = await broshRequest(
        "POST",
        `/api/oauth2/update/${BROSH_SOURCE}/${table}`,
        session.broshAccessToken,
        req.body,
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// POST /api/:table/delete — delete records by IDs
app.post(
  "/api/:table/delete",
  requireAuth as express.RequestHandler,
  validateTableMiddleware,
  async (req: Request, res: Response) => {
    const session = (req as AuthRequest).userSession;
    const { table } = req.params;
    const { ids } = req.body as { ids: number[] };

    if (!Array.isArray(ids) || ids.length === 0) {
      res
        .status(400)
        .json({ error: "`ids` must be a non-empty array of numbers." });
      return;
    }

    try {
      const payload = ids.map((id: number) => ({ id }));
      const data = await broshRequest(
        "POST",
        `/api/oauth2/delete/${BROSH_SOURCE}/${table}`,
        session.broshAccessToken,
        payload,
      );
      res.json(data);
    } catch (err: unknown) {
      handleBroshError(err, res);
    }
  },
);

// ─── OpenAPI Schema ────────────────────────────────────────────────────────────

app.get([OPENAPI_PATH, "/openapi.json"], (_req: Request, res: Response) => {
  (async () => {
    const session = await resolveBroshSession(_req.headers.authorization);
    res.setHeader("Content-Type", "application/json");
    res.json(buildOpenApiSpec(session!));
  })();
});

// ─── MCP Endpoint (Streamable HTTP) ──────────────────────────────────────────
// Implements the MCP protocol for OpenAI Responses API and compatible clients.
// The caller supplies an access token issued by this server in the
// `authorization` field of the Responses API tool config; OpenAI forwards it as
// `Authorization: Bearer <token>` on every request.

interface McpMessage {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

/**
 * Resolves a server-issued access token to the upstream BROSH access token stored
 * in the authenticated session.
 */
async function resolveBroshSession(
  authHeader: string | undefined,
): Promise<UserSession | null> {
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);

  try {
    const payload = verifyAccessToken(token, [
      ROOT_RESOURCE,
      MCP_RESOURCE,
      LEGACY_MCP_RESOURCE,
    ]);
    let session = sessions.get(payload.sessionId);
    if (session) {
      const now = Date.now();
      const isExpired = session.broshTokenExpiresAt <= now;
      const expiresSoon = session.broshTokenExpiresAt - now < 7 * 24 * 60 * 60 * 1000; // 7 days

      if (expiresSoon) {
        const refreshed = await tryRefreshBroshToken(session);
        if (refreshed) {
          session = refreshed;
        } else if (isExpired) {
          // Hard-fail on expired upstream tokens when refresh fails.
          return null;
        }
      }

      if (session.broshTokenExpiresAt <= Date.now()) {
        return null;
      }

      return session;
    }
  } catch {
    return null;
  }

  return null;
}

function buildMcpToolList(session?: UserSession): object[] {
  const tableEnum =
    session?.availableTables && session.availableTables.length > 0
      ? session.availableTables
      : [...VALID_TABLES];

  const scalarFieldSchema = {
    oneOf: [
      { type: "string" },
      { type: "number" },
      { type: "boolean" },
      { type: "null" },
    ],
  };

  const dateLikeFieldSchema = {
    type: "string",
    description: "Recommended format: YYYY-MM-DD or ISO datetime.",
  };

  const fieldConditionSchema = {
    oneOf: [
      { type: "string" },
      { type: "number" },
      { type: "boolean" },
      {
        type: "object",
        required: ["operator", "value"],
        additionalProperties: false,
        properties: {
          operator: {
            type: "string",
            enum: [
              "=",
              "!=",
              ">",
              "<",
              ">=",
              "<=",
              "LIKE",
              "IN",
              "NOT IN",
              "in",
              "not in",
            ],
          },
          value: {
            oneOf: [
              { type: "string" },
              { type: "number" },
              { type: "boolean" },
              {
                type: "array",
                minItems: 1,
                items: {
                  oneOf: [
                    { type: "string" },
                    { type: "number" },
                    { type: "boolean" },
                  ],
                },
              },
            ],
          },
        },
      },
    ],
  };

  const mapFieldTypeToSchema = (fieldType: string): Record<string, unknown> => {
    const t = fieldType.toUpperCase();
    if (["INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT"].includes(t)) {
      return { type: "integer" };
    }
    if (["DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL"].includes(t)) {
      return { type: "number" };
    }
    if (["BOOL", "BOOLEAN", "BIT"].includes(t)) {
      return { type: "boolean" };
    }
    if (["DATE", "DATETIME", "TIMESTAMP", "TIME"].includes(t)) {
      return dateLikeFieldSchema;
    }
    if (["JSON", "OBJECT"].includes(t)) {
      return { type: "object", additionalProperties: true };
    }
    if (["ARRAY", "LIST"].includes(t)) {
      return { type: "array", items: scalarFieldSchema };
    }
    if (["VARCHAR", "CHAR", "TEXT", "MEDIUMTEXT", "LONGTEXT", "BLOB"].includes(t)) {
      return { type: "string" };
    }
    return scalarFieldSchema;
  };

  const resolveDynamicFieldName = (field: Record<string, unknown>): string | null => {
    const candidates = [
      field.name,
      field.orgName,
      field.field,
      field.column,
      field.api_name,
      field.key,
    ];
    for (const candidate of candidates) {
      const value = String(candidate ?? "").trim();
      if (value) return value;
    }
    return null;
  };

  const dynamicFieldSchemasByTable: Record<string, Record<string, unknown>> = {};
  for (const [rawTableName, rawFields] of Object.entries(
    session?.availableTableFields ?? {},
  )) {
    if (!Array.isArray(rawFields)) continue;
    const tableName = normalizeTableName(rawTableName);
    if (!tableName) continue;

    const tableFieldSchema: Record<string, unknown> = {};
    for (const rawField of rawFields) {
      if (!rawField || typeof rawField !== "object" || Array.isArray(rawField)) {
        continue;
      }

      const field = rawField as Record<string, unknown>;
      const fieldName = resolveDynamicFieldName(field);
      if (!fieldName) continue;

      const rawType = String(
        field.format3 ?? field.type ?? field.data_type ?? field.format ?? "",
      ).trim();
      tableFieldSchema[fieldName] = rawType
        ? mapFieldTypeToSchema(rawType)
        : scalarFieldSchema;
    }

    if (Object.keys(tableFieldSchema).length > 0) {
      dynamicFieldSchemasByTable[tableName] = tableFieldSchema;
    }
  }

  const recordFieldSchemas: Record<string, Record<string, unknown>> = {
    accounts: {
      name: { type: "string" },
      phone: { type: "string" },
      website: { type: "string" },
      address: { type: "string" },
      country: { type: "string" },
      owner: { type: "integer" },
      type: { type: "string", enum: ["Lead", "Account", "Competitor"] },
      industry: { type: "string" },
      company_size: { type: "string" },
      headquarters: { type: "string" },
      founded: { type: "string" },
      linkedin: { type: "string" },
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
      created_by: { type: "integer" },
      "number_of_contacts-exp": { type: "number" },
      "number_of_users-exp": { type: "number" },
    },
    activity: {
      name: { type: "string" },//label subject
      type: {
        type: "string",
        enum: [
          "Email",
          "Call",
          "Meeting",
          "Event",
          "Task",
          "Marketing Automation",
          "Availability",
        ],
      },
      status: {
        type: "string",
        enum: ["Not Started", "In Progress", "Completed", "Stuck"],
      },
      owner: { type: "integer" },
      person: { type: "integer" }, // person maps to contact in activity
      account: { type: "integer" },
      opportunities: { type: "integer" },
      project: { type: "integer" },
      start_date: dateLikeFieldSchema,
      end_date: dateLikeFieldSchema,
      progress: { type: "integer", minimum: 0, maximum: 100 },
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
      created_date: dateLikeFieldSchema,
      ticket: { type: "integer" },
      campaign: { type: "integer" },
      template: { type: "integer" },
      from: scalarFieldSchema,
      to: { type: "string" },
      cc: { type: "string" },
      message_status: { type: "string" },
      message_additional_info: { type: "string" },
      file: { type: "integer" },
      created_by: { type: "integer" },
    },
    campaigns: {
      name: { type: "string" },
      status: { type: "string" },
      owner: { type: "integer" },
      start_date: dateLikeFieldSchema,
      end_date: dateLikeFieldSchema,
    },
    contacts: {
      name: { type: "string" },
      first_name: { type: "string" },
      last_name: { type: "string" },
      email: { type: "string" },
      phone: { type: "string" },
      mobile_phone: { type: "string" },
      account: { type: "integer" },
      owner: { type: "integer" },
      type: { type: "string", enum: ["lead", "customer", "contact"] },
      country: { type: "string" },
      town: { type: "string" },
      title: { type: "string" },
      department: { type: "string" },
      industry: { type: "string" },
      linkedin: { type: "string" },
      email_opt_out: { type: "integer" },
      address: { type: "string" },
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
    },
    currency: {
      name: { type: "string" },
      code: { type: "string" },
      symbol: { type: "string" },
      rate: { type: "number" },
      active: { type: "integer" },
    },
    icon: {
      name: { type: "string" },
      type: { type: "string" },
      icon: { type: "string" },
      color: { type: "string" },
    },
    menu: {
      name: { type: "string" },
      parent: { type: "integer" },
      order: { type: "integer" },
      url: { type: "string" },
      icon: { type: "string" },
    },
    objects: {
      name: { type: "string" },
      description: { type: "string" },
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
      settings: scalarFieldSchema,
      api: { type: "string" },
    },
    opportunities: {
      name: { type: "string" },
      stage: {
        type: "string",
        enum: [
          "Prospecting",
          "Qualification",
          "Needs Analysis",
          "Value Proposition",
          "Id. Decision Makers",
          "Perception Analysis",
          "Proposal/Price Quote",
          "Negotiation/Review",
          "Closed Won",
          "Closed Lost",
        ],
      },
      amount: { type: "number" },
      type: { type: "string", enum: ["Opportunity", "Quote", "Invoice"] },
      account: { type: "integer" },
      contact: { type: "integer" },
      owner: { type: "integer" },
      close_date: dateLikeFieldSchema,
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
      currency: {
        type: "string",
        enum: [
          "USD",
          "EUR",
          "GBP",
          "AED",
          "AUD",
          "BRL",
          "ILS",
          "HKD",
          "JPY",
          "NZD",
          "PLN",
          "QAR",
          "RUB",
        ],
      },
      tax: { type: "number" },
      discount: { type: "number" },
      sub_total: { type: "number" },
    },
    opportunity_products: {
      opportunity: { type: "integer" },
      product: { type: "integer" },
      name: { type: "string" },
      "product_code-exp": { type: "string" },
      list_price: { type: "number" },
      quantity: { type: "number" },
      unit_price: { type: "number" },
      "total_price-exp": { type: "number" },
      currency: {
        type: "string",
        enum: [
          "USD",
          "EUR",
          "GBP",
          "AED",
          "AUD",
          "BRL",
          "ILS",
          "HKD",
          "JPY",
          "NZD",
          "PLN",
          "QAR",
          "RUB",
        ],
      },
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
    },
    payments: {
      name: { type: "string" },
      amount: { type: "number" },
      currency: { type: "string" },
      status: { type: "string" },
      date: dateLikeFieldSchema,
      account: { type: "integer" },
      opportunities: { type: "integer" },
    },
    email_settings: {
      name: { type: "string" },
      email_label: { type: "string" },
      email: { type: "string" },
      type: { type: "string" },
      host: { type: "string" },
      port: { type: "integer" },
      reply_to: { type: "string" },
      bcc: { type: "string" },
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
    },
    products: {
      name: { type: "string" },
      productcode: { type: "string" },
      description: { type: "string" },
      price: { type: "number" },
      list_price: { type: "number" },
      currency: {
        type: "string",
        enum: [
          "USD",
          "EUR",
          "GBP",
          "AED",
          "AUD",
          "BRL",
          "ILS",
          "HKD",
          "JPY",
          "NZD",
          "PLN",
          "QAR",
          "RUB",
        ],
      },
      link: { type: "string" },
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
    },
    projects: {
      name: { type: "string" },
      status: { type: "string" },
      owner: { type: "integer" },
      Progress: { type: "integer", minimum: 0, maximum: 100 },
      Budget: { type: "number" },
      start_date: dateLikeFieldSchema,
      end_date: dateLikeFieldSchema,
    },
    templates: {
      name: { type: "string" },
      subject: { type: "string" },
      description: { type: "string" },
      type: {
        type: "string",
        enum: ["email", "web + pdf", "web + pdf + sign", "web form"],
      },
      sub_type: {
        type: "string",
        enum: ["Marketing", "Finance", "Sales", "Sales & Finance", "All"],
      },
      sub_title: { type: "string" },
      body: { type: "string" },
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
    },
    tickets: {
      name: { type: "string" },
      description: { type: "string" },//label subject
      contact: { type: "integer" },
      email: { type: "string" },
      status: { type: "string", enum: ["New", "In Work", "Closed"] },
      priority: { type: "string", enum: ["High", "Medium", "Low"] },
      origin: { type: "string", enum: ["Phone", "Web", "Call"] },
      owner: { type: "integer" },
      account: { type: "integer" },
      created_date: dateLikeFieldSchema,
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
    },
    timesheet: {
      user: { type: "integer" },
      project: { type: "integer" },
      activity: { type: "integer" },
      date: dateLikeFieldSchema,
      hours: { type: "number" },
      description: { type: "string" },
      status: { type: "string" },
    },
    users: {
      name: { type: "string" },
      username: { type: "string" },
      email: { type: "string" },
      manager: { type: "integer" },
      active: { type: "integer" },
      role: { type: "string" },
      first_name: { type: "string" },
      last_name: { type: "string" },
      last_modified_by: { type: "integer" },
      last_modified_date: dateLikeFieldSchema,
    },
    views: {
      name: { type: "string" },
      settings: { type: "string" },
      conf: { type: "string" },
      main_object: { type: "integer" },
      last_modified_date: dateLikeFieldSchema,
      last_modified_by: { type: "integer" },
      visible_to_user_roles: { type: "string" },
    },
  };

  const createRequiredFieldsByTable: Record<string, string[]> = {
    accounts: ["name"],
    activity: ["name", "type", "owner", "start_date", "end_date", "status"],
    campaigns: ["name", "status", "owner"],
    contacts: ["first_name", "last_name"],
    currency: ["name", "code"],
    email_settings: ["name", "email"],
    icon: ["name"],
    menu: ["name"],
    objects: ["name"],
    opportunities: ["name", "stage", "type", "account", "contact", "owner"],
    opportunity_products: ["opportunity", "product", "name", "list_price", "quantity", "unit_price"],
    payments: ["name", "amount", "currency", "status", "date", "account"],
    products: ["name", "productcode", "price", "list_price", "currency"],
    projects: ["name", "status", "owner", "start_date", "end_date"],
    templates: ["name", "type"],
    tickets: ["name"],
    timesheet: ["user", "project", "activity", "date", "hours"],
    users: ["name", "username", "email"],
    views: ["name"],
  };

  const mergedRecordFieldSchemas: Record<string, Record<string, unknown>> = {};
  for (const tableName of tableEnum) {
    const normalizedTable = normalizeTableName(tableName);
    mergedRecordFieldSchemas[tableName] = {
      ...(recordFieldSchemas[tableName] ?? {}),
      ...(dynamicFieldSchemasByTable[normalizedTable] ?? {}),
    };
  }

  const createAllOfByTable = tableEnum.map((tableName) => ({
    if: {
      properties: { table: { const: tableName } },
    },
    then: {
      properties: {
        records: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            additionalProperties: true,
            required: createRequiredFieldsByTable[tableName] ?? [],
            properties: mergedRecordFieldSchemas[tableName] ?? {},
          },
        },
      },
    },
  }));

  const updateAllOfByTable = tableEnum.map((tableName) => ({
    if: {
      properties: { table: { const: tableName } },
    },
    then: {
      properties: {
        records: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            required: ["id"],
            additionalProperties: true,
            properties: {
              id: { type: "integer" },
              ...(mergedRecordFieldSchemas[tableName] ?? {}),
            },
          },
        },
      },
    },
  }));

  return [
    {
      name: "brosh_me",
      title: "Get BROSH Profile",
      description:
        "Get the current authenticated BROSH CRM user profile. " +
        "Example: call this first to confirm auth and inspect user role/account context.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {},
        examples: [{}],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_available_tables",
      title: "List Available BROSH Tables",
      description:
        "Get the current user's available CRM table names and field metadata. " +
        "Call this before find/get/create/update/delete when the target table is not one of the common examples.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
        examples: [{}],
      },
      outputSchema: {
        type: "object",
        required: ["tableNames", "tables"],
        properties: {
          tableNames: {
            type: "array",
            items: { type: "string" },
            description: "Available English table names for this authenticated user.",
          },
          tables: {
            type: "array",
            items: {
              type: "object",
              required: ["name", "fields"],
              properties: {
                name: { type: "string" },
                fields: {
                  type: "array",
                  items: { type: "object", additionalProperties: true },
                },
              },
              additionalProperties: true,
            },
          },
        },
        additionalProperties: true,
      },
    },
    {
      name: "brosh_find",
      title: "Search BROSH Records",
      description:
        "Search CRM records with optional filtering, sorting, and pagination. " +
        'Standard sales opportunities are stored in opportunities with type="Opportunity". ' +
        "Quotes and invoices are also stored in the opportunities table as types/subtypes, " +
        "and quote/invoice lines are stored in opportunity_products. " +
        "In opportunities, common fields include name, stage, amount, type, account, contact, owner, close_date, created_date, last_modified_date, currency, tax, discount, and sub_total. " +
        "Type values are Opportunity, Quote, Invoice. " +
        "Stage values include Prospecting, Qualification, Needs Analysis, Value Proposition, Id. Decision Makers, Perception Analysis, Proposal/Price Quote, Negotiation/Review, Closed Won, Closed Lost. " +
        "In contacts, common fields include name, first_name, last_name, email, phone, mobile_phone, account, owner, type, country, town, title, department, industry, linkedin, email_opt_out, address, created_date, and last_modified_date. " +
        "Contact type values are typically lead/customer (and some views may include contact). " +
        "In accounts, common fields include id, name, phone, website, address, country, owner, type, industry, company_size, headquarters, founded, linkedin, created_date, last_modified_date, last_modified_by, created_by, number_of_contacts-exp, and number_of_users-exp. " +
        "Account type values include Lead, Account, and Competitor. " +
        "In products, common fields include name, productcode, description, price, list_price, currency, link, created_date, and last_modified_date. " +
        "Product currency values include USD, EUR, GBP, AED, AUD, BRL, ILS, HKD, JPY, NZD, PLN, QAR, and RUB. " +
        "In templates, common fields include id, name, subject, description, type, sub_type, sub_title, body, created_date, last_modified_date, and last_modified_by. " +
        "Template type values include email, web + pdf, web + pdf + sign, and web form. " +
        "Template sub_type values may include Marketing, Finance, Sales, Sales & Finance, and All. " +
        "Activity stores emails, e-signatures on documents, tasks, and events linked to multiple related objects, and is also used for project tasks. " +
        "In activity, core fields include name (subject), type, status, owner, person, account, opportunities, project, start_date, end_date, progress, last_modified_date, last_modified_by, created_date, ticket, campaign, template, from, to, cc, message_status, message_additional_info, file, and created_by. " +
        "For activity-contact relationships, use the person field (not contact). " +
        "In tickets, common fields include name (subject), description, contact, email, status, priority, origin, owner, account, created_date, last_modified_date, and last_modified_by. " +
        "Ticket status values include New, In Work, Closed. Ticket priority values include High, Medium, Low. Ticket origin values include Phone, Web, Call. " +
        "Use filter.search for free-text on the name field, filter.where for field-level " +
        "conditions (plain value or {operator, value}), and sort for ordering results. " +
        'Example: find opportunities where type="Opportunity" sorted by last_modified_date DESC, ' +
        'or filter opportunities by type="Quote" / type="Invoice", or query activity by related object/project fields, or query tickets by status/priority/origin/contact/account.',
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "filter"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "English CRM table name to query. Call brosh_available_tables for the current user's full table list. Common examples: " +
              tableEnum.join(", "),
          },
          fields: {
            type: "array",
            items: { type: "string" },
            description: "Columns to return. Omit for all.",
          },
          filter: {
            type: "object",
            additionalProperties: false,
            oneOf: [
              { required: ["search"] },
              { required: ["id"] },
              { required: ["where"] },
            ],
            properties: {
              search: {
                type: "string",
                description: "Free-text search on the name field.",
              },
              id: {
                oneOf: [
                  { type: "integer" },
                  { type: "array", items: { type: "integer" }, minItems: 1 },
                ],
                description: "Filter by one record ID or a list of record IDs.",
              },
              where: {
                type: "object",
                additionalProperties: fieldConditionSchema,
                description:
                  "Field conditions map. Value can be a plain value (equality) or { operator, value }. " +
                  "Common fields by table include: opportunities(name,type,stage,amount,account,contact,owner,close_date,currency,tax,discount,sub_total,created_date,last_modified_date), " +
                  "opportunity_products(opportunity,product,list_price,quantity,unit_price,total_price-exp,currency,last_modified_date,last_modified_by), " +
                  "contacts(name,first_name,last_name,email,phone,mobile_phone,account,owner,type,country,town,title,department,industry,linkedin,email_opt_out,address,created_date,last_modified_date), " +
                  "accounts(name,phone,website,address,country,owner,type,industry,company_size,headquarters,founded,linkedin,created_date,last_modified_date,last_modified_by,created_by,number_of_contacts-exp,number_of_users-exp), " +
                  "products(name,productcode,description,price,list_price,currency,link,created_date,last_modified_date), " +
                  "templates(name,subject,description,type,sub_type,sub_title,body,created_date,last_modified_date,last_modified_by), " +
                  "activity(name,type,status,owner,person,account,opportunities,project,start_date,end_date,progress,last_modified_date,last_modified_by,created_date,ticket,campaign,template,from,to,cc,message_status,message_additional_info,file,created_by). For activity-contact relationships, use person (not contact), " +
                  "tickets(name,description,contact,email,status,priority,origin,owner,account,created_date,last_modified_date,last_modified_by), " +
                  "users(name,username,email,manager,active,role,first_name,last_name,last_modified_by,last_modified_date), " +
                  "views(name,main_object,conf,settings,last_modified_date,last_modified_by,visible_to_user_roles), " +
                  "projects(name,status,manager,start_date,end_date), " +
                  "email_settings(name,email_label,email,type,host,port,reply_to,bcc,last_modified_date,last_modified_by). Custom fields are supported through additional where keys.",
                properties: {
                  id: fieldConditionSchema,
                  name: fieldConditionSchema,
                  type: fieldConditionSchema,
                  status: fieldConditionSchema,
                  owner: fieldConditionSchema,
                  account: {
                    oneOf: [
                      { type: "string" },
                      { type: "number" },
                      { type: "boolean" },
                      {
                        type: "object",
                        required: ["operator", "value"],
                        additionalProperties: false,
                        properties: {
                          operator: {
                            type: "string",
                            enum: [
                              "=",
                              "!=",
                              ">",
                              "<",
                              ">=",
                              "<=",
                              "LIKE",
                              "IN",
                              "NOT IN",
                              "in",
                              "not in",
                            ],
                          },
                          value: {
                            oneOf: [
                              { type: "string" },
                              { type: "number" },
                              { type: "boolean" },
                              {
                                type: "array",
                                minItems: 1,
                                items: {
                                  oneOf: [
                                    { type: "string" },
                                    { type: "number" },
                                    { type: "boolean" },
                                  ],
                                },
                              },
                            ],
                          },
                        },
                      },
                    ],
                  },
                  contact: {
                    oneOf: [
                      { type: "string" },
                      { type: "number" },
                      { type: "boolean" },
                      {
                        type: "object",
                        required: ["operator", "value"],
                        additionalProperties: false,
                        properties: {
                          operator: {
                            type: "string",
                            enum: [
                              "=",
                              "!=",
                              ">",
                              "<",
                              ">=",
                              "<=",
                              "LIKE",
                              "IN",
                              "NOT IN",
                              "in",
                              "not in",
                            ],
                          },
                          value: {
                            oneOf: [
                              { type: "string" },
                              { type: "number" },
                              { type: "boolean" },
                              {
                                type: "array",
                                minItems: 1,
                                items: {
                                  oneOf: [
                                    { type: "string" },
                                    { type: "number" },
                                    { type: "boolean" },
                                  ],
                                },
                              },
                            ],
                          },
                        },
                      },
                    ],
                  },
                  person: {
                    oneOf: [
                      { type: "string" },
                      { type: "number" },
                      { type: "boolean" },
                      {
                        type: "object",
                        required: ["operator", "value"],
                        additionalProperties: false,
                        properties: {
                          operator: {
                            type: "string",
                            enum: [
                              "=",
                              "!=",
                              ">",
                              "<",
                              ">=",
                              "<=",
                              "LIKE",
                              "IN",
                              "NOT IN",
                              "in",
                              "not in",
                            ],
                          },
                          value: {
                            oneOf: [
                              { type: "string" },
                              { type: "number" },
                              { type: "boolean" },
                              {
                                type: "array",
                                minItems: 1,
                                items: {
                                  oneOf: [
                                    { type: "string" },
                                    { type: "number" },
                                    { type: "boolean" },
                                  ],
                                },
                              },
                            ],
                          },
                        },
                      },
                    ],
                    description:
                      "For activity table contact relations, use person (contact ID) rather than contact.",
                  },
                },
              },
            },
            description:
              'Filter: provide exactly one of search, id, or where. search is free-text on name, id filters one record or an id list, and where is a field map where each key is a plain value or { operator, value }. For standard opportunities use table="opportunities" with where.type="Opportunity"; for quotes/invoices use where.type="Quote" or "Invoice"; for line items use table="opportunity_products" and filter by opportunity; for contacts use table="contacts" and filter by fields like type/account/owner/email/email_opt_out; for accounts use table="accounts" and filter by fields like type/country/owner/name/industry/company_size/address/headquarters/founded/linkedin/created_date/last_modified_date/last_modified_by/created_by; for products use table="products" and filter by fields like currency/productcode/price/list_price; for templates use table="templates" and filter by fields like type/sub_type/name/subject; for communications/tasks/events use table="activity" and filter by activity type/status and relation fields (person, account, opportunities, project, ticket, campaign). For activity-contact relations, use person (not contact); for support work use table="tickets" and filter by fields like status/priority/origin/contact/account/owner/email. Activity type values include Email, Call, Meeting, Event, Task, Marketing Automation, Availability. Activity status values include Not Started, In Progress, Completed, Stuck. Ticket status values include New, In Work, Closed. Ticket priority values include High, Medium, Low. Ticket origin values include Phone, Web, Call. To model "My Open Activities", filter by owner or last_modified_by and exclude status="Completed".',
          },
          sort: {
            type: "array",
            items: {
              type: "object",
              required: ["field", "direction"],
              properties: {
                field: { type: "string" },
                direction: { type: "string", enum: ["ASC", "DESC"] },
              },
            },
          },
          page_size: {
            type: "integer",
            description: "Records per page (default 50).",
          },
          page: { type: "integer", description: "Page number (default 1)." },
          limit: { type: "integer", minimum: 1, maximum: 10000 },
        },
        examples: [
          {
            table: "opportunities",
            fields: [
              "id",
              "name",
              "type",
              "stage",
              "amount",
              "account",
              "contact",
              "owner",
              "close_date",
              "last_modified_date",
            ],
            filter: { where: { type: "Opportunity" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 25,
          },
          {
            table: "opportunities",
            fields: [
              "id",
              "name",
              "type",
              "stage",
              "amount",
              "account",
              "contact",
              "owner",
              "close_date",
              "last_modified_date",
            ],
            filter: { where: { type: "Quote" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 25,
          },
          {
            table: "opportunities",
            fields: [
              "id",
              "name",
              "type",
              "stage",
              "amount",
              "account",
              "contact",
              "owner",
              "close_date",
              "last_modified_date",
            ],
            filter: { where: { type: "Invoice" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 25,
          },
          {
            table: "opportunity_products",
            fields: [
              "id",
              "name",
              "product_code-exp",
              "product",
              "list_price",
              "quantity",
              "unit_price",
              "total_price-exp",
              "currency",
              "last_modified_date",
              "last_modified_by",
            ],
            filter: { where: { opportunity: 12345 } },
            sort: [{ field: "id", direction: "ASC" }],
            limit: 100,
          },
          {
            table: "contacts",
            fields: [
              "id",
              "name",
              "first_name",
              "last_name",
              "email",
              "phone",
              "account",
              "owner",
              "type",
              "country",
              "linkedin",
              "email_opt_out",
              "last_modified_date",
            ],
            filter: { where: { type: "lead", email_opt_out: 0 } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "contacts",
            fields: [
              "id",
              "name",
              "email",
              "phone",
              "account",
              "owner",
              "type",
              "town",
              "industry",
              "created_date",
            ],
            filter: { where: { type: "customer", account: 4102 } },
            sort: [{ field: "created_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "accounts",
            fields: [
              "id",
              "name",
              "phone",
              "website",
              "address",
              "country",
              "owner",
              "type",
              "industry",
              "company_size",
              "headquarters",
              "founded",
              "linkedin",
              "created_date",
              "last_modified_date",
              "last_modified_by",
              "created_by",
              "number_of_contacts-exp",
              "number_of_users-exp",
            ],
            filter: { where: { type: "Account", country: "USA" } },
            sort: [{ field: "name", direction: "ASC" }],
            limit: 50,
          },
          {
            table: "accounts",
            fields: [
              "id",
              "name",
              "owner",
              "phone",
              "website",
              "address",
              "country",
              "type",
              "industry",
              "company_size",
              "headquarters",
              "founded",
              "linkedin",
              "created_date",
              "last_modified_date",
              "last_modified_by",
              "created_by",
              "number_of_contacts-exp",
              "number_of_users-exp",
            ],
            filter: { where: { owner: 123 } },
            sort: [{ field: "created_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "products",
            fields: [
              "id",
              "name",
              "productcode",
              "description",
              "price",
              "list_price",
              "currency",
              "link",
              "last_modified_date",
            ],
            filter: { where: { currency: "USD" } },
            sort: [{ field: "name", direction: "ASC" }],
            limit: 50,
          },
          {
            table: "products",
            fields: [
              "id",
              "name",
              "productcode",
              "price",
              "list_price",
              "currency",
              "created_date",
            ],
            filter: { where: { list_price: { operator: ">", value: 0 } } },
            sort: [{ field: "created_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "templates",
            fields: [
              "id",
              "name",
              "type",
              "sub_type",
              "subject",
              "sub_title",
              "description",
              "last_modified_date",
            ],
            filter: { where: { type: "email", sub_type: "Marketing" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "templates",
            fields: ["id", "name", "type", "subject", "body", "created_date"],
            filter: { where: { type: "web + pdf + sign" } },
            sort: [{ field: "created_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "email_settings",
            fields: [
              "id",
              "name",
              "email_label",
              "email",
              "type",
              "host",
              "port",
              "reply_to",
              "bcc",
              "last_modified_date",
              "last_modified_by",
            ],
            filter: { where: { id: 3 } },
            limit: 1,
          },
          {
            table: "email_settings",
            fields: [
              "id",
              "name",
              "email_label",
              "email",
              "type",
              "host",
              "port",
              "last_modified_date",
            ],
            sort: [{ field: "id", direction: "ASC" }],
            limit: 20,
          },
          {
            table: "projects",
            fields: [
              "id",
              "name",
              "status",
              "manager",
              "start_date",
              "end_date",
            ],
            filter: {
              where: {
                status: { operator: "in", value: ["Active", "Planning"] },
              },
            },
            sort: [{ field: "name", direction: "ASC" }],
            limit: 50,
          },
          {
            table: "views",
            fields: [
              "id",
              "name",
              "main_object",
              "conf",
              "settings",
              "last_modified_date",
            ],
            filter: { where: { main_object: "projects" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 25,
          },
          {
            table: "users",
            fields: [
              "id",
              "name",
              "username",
              "email",
              "manager",
              "active",
              "role",
              "first_name",
              "last_name",
              "last_modified_by",
              "last_modified_date",
            ],
            filter: { where: { active: 1 } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 20,
          },
          {
            table: "activity",
            fields: [
              "id",
              "name",
              "type",
              "status",
              "owner",
              "person",
              "account",
              "opportunities",
              "project",
              "start_date",
              "end_date",
              "last_modified_date",
            ],
            filter: {
              where: {
                type: "Task",
                project: 3001,
                status: { operator: "!=", value: "Completed" },
              },
            },
            sort: [{ field: "start_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "activity",
            fields: [
              "id",
              "name",
              "type",
              "status",
              "owner",
              "last_modified_by",
              "start_date",
              "last_modified_date",
            ],
            filter: {
              where: {
                owner: 123,
                status: { operator: "!=", value: "Completed" },
              },
            },
            sort: [{ field: "start_date", direction: "ASC" }],
            limit: 20,
          },
          {
            table: "tickets",
            fields: [
              "id",
              "name",
              "description",
              "contact",
              "email",
              "status",
              "priority",
              "origin",
              "owner",
              "account",
              "created_date",
              "last_modified_date",
              "last_modified_by",
            ],
            filter: {
              where: {
                status: { operator: "!=", value: "Closed" },
                priority: "High",
                origin: "Web",
              },
            },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 50,
          },
          {
            table: "views",
            fields: [
              "id",
              "name",
              "conf",
              "main_object",
              "settings",
              "last_modified_date",
              "last_modified_by",
              "visible_to_user_roles",
            ],
            filter: { where: { name: "tickets" } },
            sort: [{ field: "last_modified_date", direction: "DESC" }],
            limit: 5,
          },
        ],
      },
      outputSchema: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    },
    {
      name: "brosh_get",
      title: "Get BROSH Records",
      description:
        "Retrieve specific CRM records by their numeric IDs. " +
        'Use table="accounts" for company records and account-level ownership/profile fields such as id, name, phone, website, address, country, owner, type, industry, company_size, headquarters, founded, linkedin, created_date, last_modified_date, last_modified_by, created_by, number_of_contacts-exp, and number_of_users-exp. ' +
        'Use table="products" for product catalog records (pricing, SKU/code, currency, links). ' +
        'Use table="templates" for email/document/web templates and their body/subject/type metadata. ' +
        'Use table="opportunities" for Opportunity/quote/invoice headers and table="opportunity_products" for quote/invoice lines. ' +
        'Use table="tickets" for support/helpdesk records (subject/name, description, contact, email, status, priority, origin, owner, account, created/modified timestamps). ' +
        'Use table="activity" for email logs, e-signature activities, tasks/events, and project tasks, linked by fields like person/account/opportunities/project/ticket/campaign. ' +
        "Example: fetch contacts by IDs to enrich or validate before update.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "ids"],
        properties: {
          table: { type: "string", 
            //enum: tableEnum 
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "English CRM table name to query. Call brosh_available_tables for the current user's full table list. Common examples: " +
              tableEnum.join(", "),
          },
          ids: {
            type: "array",
            items: { type: "integer" },
            description: "Record IDs to fetch.",
          },
          limit: { type: "integer", minimum: 1, maximum: 10000 },
        },
        examples: [
          {
            table: "contacts",
            ids: [101, 202, 303],
            limit: 100,
          },
          {
            table: "accounts",
            ids: [401, 402, 403],
            limit: 100,
          },
          {
            table: "products",
            ids: [801, 802, 803],
            limit: 100,
          },
          {
            table: "templates",
            ids: [901, 902, 903],
            limit: 100,
          },
          {
            table: "opportunities",
            ids: [5501, 5502],
            limit: 100,
          },
          {
            table: "opportunity_products",
            ids: [90001, 90002],
            limit: 100,
          },
          {
            table: "activity",
            ids: [70001, 70002],
            limit: 100,
          },
          {
            table: "tickets",
            ids: [1101, 1102, 1103],
            limit: 100,
          },
          {
            table: "email_settings",
            ids: [3],
            limit: 10,
          },
          {
            table: "projects",
            ids: [501, 502, 503],
            limit: 25,
          },
          {
            table: "views",
            ids: [425, 423],
            limit: 10,
          },
          {
            table: "users",
            ids: [1, 2, 3],
            limit: 20,
          },
        ],
      },
      outputSchema: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    },
    {
      name: "api_table_find",
      title: "/api/table/find",
      description:
        "Fixed-path alias for brosh_find. Provide an English table name plus optional fields, filter, sort, and pagination.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "filter"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description: "English CRM table name.",
          },
          fields: {
            type: "array",
            items: { type: "string" },
          },
          filter: {
            type: "object",
            oneOf: [
              { required: ["search"] },
              { required: ["id"] },
              { required: ["where"] },
            ],
            properties: {
              search: { type: "string" },
              id: {
                oneOf: [
                  { type: "integer" },
                  { type: "array", minItems: 1, items: { type: "integer" } },
                ],
              },
              where: {
                type: "object",
                additionalProperties: fieldConditionSchema,
              },
            },
            additionalProperties: false,
          },
          sort: {
            type: "array",
            items: {
              type: "object",
              required: ["field", "direction"],
              properties: {
                field: { type: "string" },
                direction: { type: "string", enum: ["ASC", "DESC"] },
              },
              additionalProperties: false,
            },
          },
          page_size: { type: "integer", minimum: 1 },
          page: { type: "integer", minimum: 1 },
          limit: { type: "integer", minimum: 1, maximum: 10000 },
        },
        additionalProperties: false,
      },
      outputSchema: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    },
    {
      name: "api_table_get",
      title: "/api/table/get",
      description:
        "Fixed-path alias for brosh_get. Provide an English table name and a JSON body with ids.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "ids"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description: "English CRM table name.",
          },
          ids: {
            type: "array",
            minItems: 1,
            items: { type: "integer" },
          },
          limit: { type: "integer", minimum: 1, maximum: 10000 },
        },
        additionalProperties: false,
      },
      outputSchema: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    },
    {
      name: "api_table_create",
      title: "/api/table/create",
      description:
        "Fixed-path alias for brosh_create. Provide an English table name and records JSON array.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "records"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description: "English CRM table name.",
          },
          records: {
            type: "array",
            minItems: 1,
            items: { type: "object", additionalProperties: true },
          },
        },
        additionalProperties: false,
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "api_table_update",
      title: "/api/table/update",
      description:
        "Fixed-path alias for brosh_update. Provide an English table name and records JSON array; each record must include id.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "records"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description: "English CRM table name.",
          },
          records: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              required: ["id"],
              additionalProperties: true,
              properties: { id: { type: "integer" } },
            },
          },
        },
        additionalProperties: false,
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "api_table_delete",
      title: "/api/table/delete",
      description:
        "Fixed-path alias for brosh_delete. Provide an English table name and ids JSON array. Uses the same confirmation flow as brosh_delete.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "ids"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description: "English CRM table name.",
          },
          ids: {
            type: "array",
            minItems: 1,
            items: { type: "integer" },
          },
          confirm: { type: "boolean" },
          confirmationToken: { type: "string" },
          previewOnly: { type: "boolean" },
        },
        additionalProperties: false,
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_create",
      title: "Create BROSH Records",
      description:
        "Create one or more CRM records. Pass an array of field objects. " +
        "Schema is table-aware and includes common fields per table to improve first-call accuracy. " +
        "Example: create a new lead/contact/opportunity from prospecting output.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "records"],
        allOf: createAllOfByTable,
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "English CRM table name to create in. Call brosh_available_tables for the current user's full table list. Common examples: " +
              tableEnum.join(", "),
          },
          records: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              additionalProperties: true,
            },
            description:
              "Array of records to create. Item fields are validated using the selected table schema (common fields listed in this file).",
          },
        },
        examples: [
          {
            table: "contacts",
            records: [
              {
                name: "Dana Cohen",
                email: "dana@example.com",
                company: "Acme Ltd",
                title: "CFO",
              },
            ],
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_update",
      title: "Update BROSH Records",
      description:
        'Update one or more CRM records. Each object must include an "id" field. ' +
        "Schema is table-aware and includes common updatable fields per table to improve first-call accuracy. " +
        "Example: update missing fields after AI enrichment.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "records"],
        allOf: updateAllOfByTable,
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "English CRM table name to update. Call brosh_available_tables for the current user's full table list. Common examples: " +
              tableEnum.join(", "),
          },
          records: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              required: ["id"],
              additionalProperties: true,
              properties: { id: { type: "integer" } },
            },
            description:
              "Array of records to update. Each item requires id and may include table-specific fields.",
          },
        },
        examples: [
          {
            table: "contacts",
            records: [
              {
                id: 101,
                industry: "FinTech",
                company_size: "51-200",
                title: "Head of Operations",
              },
            ],
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_modify_field",
      title: "Modify BROSH CRM Field",
      description:
        "Modify or create a CRM table field using BROSH modifyField API. " +
        "Calls /api/oauth2/modifyfield/:source/:tableName and expects oldField + newField objects (or legacy xFields as [oldField, newField]). " +
        "Supported format3 values: VARCHAR, DATE, DATETIME, DECIMAL, INT, BLOB, TEXT, MEDIUMTEXT. " +
        "Validation mirrors BROSH constraints for type/length/decimals before sending.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["tableName", "oldField", "newField"],
        properties: {
          tableName: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "Target English table name. Use brosh_available_tables to list available tables.",
          },
          oldField: {
            type: "object",
            additionalProperties: true,
            required: ["orgName"],
            description:
              "Existing field definition. Use orgName=\"\" when creating a brand-new field.",
            properties: {
              orgName: {
                type: "string",
                pattern: "^[a-zA-Z0-9_]*$",
                description:
                  "Existing field name. Empty string means create a new field.",
              },
              format3: {
                type: "string",
                enum: [
                  "VARCHAR",
                  "DATE",
                  "DATETIME",
                  "DECIMAL",
                  "INT",
                  "BLOB",
                  "TEXT",
                  "MEDIUMTEXT",
                ],
              },
              format: { type: "string" },
              length: { type: "integer", minimum: 0, maximum: 250 },
              decimals: { type: "integer", minimum: 0, maximum: 3 },
              ext: { type: "string" },
            },
          },
          newField: {
            type: "object",
            additionalProperties: true,
            required: ["orgName", "format3", "length", "decimals"],
            description: "New field definition (or replacement definition).",
            properties: {
              orgName: {
                type: "string",
                pattern: "^[a-zA-Z0-9_]+$",
                description: "New or updated field name.",
              },
              format3: {
                type: "string",
                enum: [
                  "VARCHAR",
                  "DATE",
                  "DATETIME",
                  "DECIMAL",
                  "INT",
                  "BLOB",
                  "TEXT",
                  "MEDIUMTEXT",
                ],
              },
              format: { type: "string", default: "" },
              length: { type: "integer", minimum: 0, maximum: 250 },
              decimals: { type: "integer", minimum: 0, maximum: 3 },
              ext: { type: "string", default: "" },
            },
          },
          xFields: {
            type: "array",
            minItems: 2,
            maxItems: 2,
            description:
              "Legacy format. Preferred fields are oldField and newField for better argument inference.",
            items: { type: "object", additionalProperties: true },
          },
        },
        examples: [
          {
            tableName: "contacts",
            oldField: {
              orgName: "ai_score",
              format3: "INT",
              format: "",
              length: 3,
              decimals: 0,
              ext: "",
            },
            newField: {
              orgName: "ai_score",
              format3: "DECIMAL",
              format: "",
              length: 8,
              decimals: 2,
              ext: "",
            },
          },
          {
            tableName: "accounts",
            oldField: {
              orgName: "",
              format3: "",
              format: "",
              length: 0,
              decimals: 0,
              ext: "",
            },
            newField: {
              orgName: "market_segment",
              format3: "VARCHAR",
              format: "",
              length: 100,
              decimals: 0,
              ext: "",
            },
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_delete",
      title: "Delete BROSH Records",
      description:
        "Delete CRM records by ID. Deleted records move to recycle bin for 30 days. " +
        "This tool requires explicit two-step confirmation: first call returns a preview + confirmationToken; " +
        "second call must include confirm=true and the token. " +
        "Example: remove duplicate test records after cleanup.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        required: ["table", "ids"],
        properties: {
          table: {
            type: "string",
            pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
            description:
              "English CRM table name to delete from. Call brosh_available_tables for the current user's full table list. Common examples: " +
              tableEnum.join(", "),
          },
          ids: {
            type: "array",
            items: { type: "integer" ,description: "ID of the record to delete."},
            description: "IDs of records to delete.",
          },
          confirm: {
            type: "boolean",
            description:
              "Set to true only on the second call after reviewing the preview.",
          },
          confirmationToken: {
            type: "string",
            description:
              "Token returned by the preview call; required when confirm=true.",
          },
          previewOnly: {
            type: "boolean",
            description:
              "Optional hint to indicate this call should only return a preview.",
          },
        },
        examples: [
          {
            table: "contacts",
            ids: [9981, 9982],
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_send_email",
      title: "Send BROSH Email",
      description:
        "Send emails using the BROSH CRM sendEmails engine. BROSH sends one message per row, skips contacts where email_opt_out is 1, and logs a Completed activity for each sent/bounced recipient. " +
        "For direct email without a saved template, put the subject in task.name and the HTML/text body in task.description. For saved templates, pass templateid or template.id plus template.subject/template.body; BROSH renders EJS-style contact fields from each row. " +
        "BROSH sendmailDB sends html from the rendered body, text from sub_title, cc from task.cc, bcc from fromEmailSets.bcc, and reply-to from fromEmailSets.reply_to or a default noreply address. Inline data:image base64 content in the body is converted to CID inline attachments, and template.attachments base64 files are sent as regular attachments. " +
        "Before sending, resolve the sender from email_settings: pass fromEmailSet as email_settings.id and preferably pass the full fromEmailSets record used to build the SMTP transport. " +
        "Do not use consumer sender records such as Gmail/Yahoo/Hotmail/abv.bg addresses; BROSH blocks those sender domains in sendmailDB. " +
        "Use rows for recipients, task for activity/email fields, fromEmailSets for sender settings, and template/templateid only when using BROSH templates.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: "object",
        required: ["rows"],
        properties: {
          rows: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              additionalProperties: true,
              properties: {
                id: {
                  type: "integer",
                  description: "Optional recipient/contact ID.",
                },
                email: {
                  type: "string",
                  description: "Recipient email address.",
                },
                name: {
                  type: "string",
                  description: "Recipient display name.",
                },
                first_name: {
                  type: "string",
                  description: "Recipient first name, available to templates as contacts.first_name.",
                },
                last_name: {
                  type: "string",
                  description: "Recipient last name, available to templates as contacts.last_name.",
                },
                account: {
                  type: "integer",
                  description:
                    "Optional account ID. BROSH copies this to the logged activity account field.",
                },
                email_opt_out: {
                  type: ["string", "integer", "boolean"],
                  description:
                    "If this value is 1, BROSH skips sending to this row.",
                },
                parent_exp: {
                  type: ["string", "integer"],
                  description:
                    "Optional related parent record ID used by BROSH templates and activity lookup logging.",
                },
                parentTable_exp: {
                  type: "string",
                  description:
                    "Optional related parent table name. If not campaigns/contacts/activity, BROSH writes activity[parentTable_exp] = parent_exp.",
                },
              },
              anyOf: [{ required: ["id"] }, { required: ["email"] }],
            },
            description:
              "Recipient/contact rows. BROSH iterates these rows and sends/logs one email per row.",
          },
          templateid: {
            type: "integer",
            description:
              "Optional template ID. If provided, BROSH loads template data by ID.",
          },
          template: {
            type: "object",
            additionalProperties: true,
            properties: {
              id: { type: "integer" },
              name: { type: "string" },
              subject: {
                type: "string",
                description:
                  "Template email subject. BROSH renders EJS-style placeholders against contacts.",
              },
              body: {
                type: "string",
                description:
                  "Template HTML/body. BROSH renders EJS-style placeholders and link/open tracking for saved templates.",
              },
              sub_title: { type: "string" },
              cc: {
                type: "string",
                description:
                  "Optional email CC copied to objectFill.cc. You can also set task.cc.",
              },
              attachments: {
                type: "array",
                description:
                  "Optional base64 file attachments. BROSH sends each item with contentDisposition=attachment.",
                items: {
                  type: "object",
                  additionalProperties: true,
                  required: ["content"],
                  properties: {
                    id: { type: "integer" },
                    name: {
                      type: "string",
                      description:
                        "Attachment filename, for example invite.ics or proposal.pdf.",
                    },
                    type: {
                      type: "string",
                      description:
                        "File extension/content type hint used when name is missing, for example ics, pdf, png.",
                    },
                    content: {
                      type: "string",
                      description:
                        "Base64 encoded attachment content. Do not include a data: prefix.",
                    },
                    size: { type: "integer" },
                    description: { type: "string" },
                  },
                },
              },
              calendar_invite: {
                type: ["integer", "string", "boolean"],
                description:
                  "default 0, When 1, BROSH generates and attaches an invite.ics file from the task start_date and end_date to be scheduled.",
              },
            },
            description:
              "Optional BROSH template payload. For direct non-template sends, prefer task.name/task.description with templateid=0.",
          },
          fromEmailSet: {
            type: "integer",
            description:
              "Sender email set ID from email_settings.id. Query email_settings first to get this value. Defaults to 3 if omitted.",
          },
          fromEmailSets: {
            type: "object",
            additionalProperties: true,
            required: ["id", "email"],
            properties: {
              id: { type: "integer", description: "Email settings ID.  Query from the database the full approved settings." },
              name: { type: "string", description: "Name of the sender." },
              email: { type: "string", format: "email", description: "Email address of the sender." },
              email_label: { type: "string", description: "Label for the sender email, e.g. 'Sales Team'." },
              type: { type: "string", description: "Sender transport type from email_settings, usually SMTP/email. Avoid sms/whatsapp for email." },
              host: { type: "string", description: "SMTP host or transport host from email_settings." },
              port: { type: "integer", description: "SMTP port from email_settings." },
              password: {
                type: "string",
                description:
                  "Sender credential from email_settings when returned by BROSH. Pass through the approved row; do not invent or expose it in chat.",
              },
              reply_to: { type: "string", description: "Reply-to email address. If blank, BROSH uses fromEmailSets.email." },
              bcc: { type: "string", description: "BCC address copied to the outgoing email message." },
              last_modified_date: { type: "string", description: "Date when the email settings were last modified." },
              last_modified_by: { type: "integer", description: "User ID of the person who last modified the email settings." },
            },
            description:
              "Full sender object from email_settings. BROSH uses this to create the SMTP/WhatsApp/SMS transport; for email use a normal email sender, not sms/whatsapp settings.",
          },
          task: {
            type: "object",
            additionalProperties: true,
            properties: {
              name: {
                type: "string",
                description:
                  "Email subject for direct sends and the subject stored on the logged activity.",
              },
              description: {
                type: "string",
                description:
                  "Email body for direct sends when templateid=0 or no saved template is used. Plain newlines are converted to <br> by BROSH.",
              },
              status: {
                type: "string",
                description:
                  'Activity status. BROSH sets this to "Completed" during send.',
              },
              type: {
                type: "string",
                description:
                  'Activity type. Use "Email" for email activity; BROSH uses "sms" or "whatsapp" for those sender types.',
              },
              owner: { type: "integer", description: "user id" },
              person: { type: "integer", description: "contact id" },
              account: { type: "integer", description: "account id" },
              opportunities: { type: "integer", description: "opportunity id" },
              project: { type: "integer", description: "project id" },
              start_date: {
                type: "string",
                description: "Recommended format: YYYY-MM-DD or ISO datetime.",
              },
              end_date: {
                type: "string",
                description: "Recommended format: YYYY-MM-DD or ISO datetime.",
              },
              progress: { type: "integer", minimum: 0, maximum: 100 },
              last_modified_date: {
                type: "string",
                description: "Last modified date of the task",
              },
              last_modified_by: {
                type: "integer",
                description: "User ID of the person who last modified the task",
              },
              created_date: {
                type: "string",
                description: "Creation date of the task",
              },
              ticket: { type: "integer", description: "ticket id" },
              campaign: { type: "integer", description: "campaign id" },
              template: { type: "integer", description: "template id" },
              from: { type: "integer", description: "email_settings ID, use fromEmailSets id" },
              to: { type: "string", description: "email recipient" },
              cc: { type: "string", description: "email cc" },
              message_status: {
                type: "string",
                description: "sent, failed, etc",
              },
              message_additional_info: {
                type: "string",
                description: "any additional info about the send result",
              } ,
              file: { type: "integer", description: "file id" },
              created_by: { type: "integer", description: "user id" },
              due_date: {
                type: "string",
                description:
                  "Alias commonly used by clients; maps to activity schedule semantics.",
              },
            },
            description:
              "Activity object cloned for each recipient. BROSH fills person from row.id, account from row.account, status Completed, last_modified_date now, and message_status/message_additional_info after send.",
          },
        },
        examples: [
          {
            templateid: 0, //select a template from BROSH by ID (configured in BROSH CRM dashboard)
            fromEmailSet: 3, //query email_settings first and pass the chosen email_settings.id
            rows: [
              { id: 101, email: "buyer1@example.com", first_name: "Buyer", last_name: "One", account: 55 },
              { id: 102, email: "buyer2@example.com", first_name: "Buyer", last_name: "Two", account: 55 },
            ],
            task: {
              name: "Q2 follow-up campaign",
              description: "Hi, thanks for your interest. I wanted to follow up on the Q2 campaign.",
              due_date: "2024-07-31",
              type: "Email",
            },
          },
          {
            templateid: 0,
            fromEmailSet: 3,
            template: {
              id: 0,
              subject: "Intro Outreach",
              body: "Hi Buyer Two,<br>We can help with ...<br><img src=\"data:image/png;base64,iVBORw0KGgo...\">",
              sub_title: "Plain text preview / fallback text",
              calendar_invite: 0,
            },
            fromEmailSets: {
              id: 3,
              name: "Sales",
              email: "sales@your-company.com",
            }, //query email_settings first and pass the full sender row
            rows: [{ email: "lead@example.com", name: "Buyer Two" }], // the contacts
            task: {
              name: "Reducing SLA risk this month",
              description:
                "Hi Buyer Two, we found 3 actions that can reduce SLA risk immediately...",
              due_date: "2024-07-31",
              status: "Completed",
              type: "Email",
            },
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
    {
      name: "brosh_send_message_single",
      title: "Send Message Single (One By One)",
      description:
        "Send emails one-by-one with a custom subject/body per row. This wrapper converts each row's subject/message into the BROSH sendEmails payload fields task.name and task.description, then calls BROSH sendEmail once per recipient. " +
        "BROSH skips rows where email_opt_out is 1 and logs a Completed activity with message_status for each sent/bounced recipient. " +
        "BROSH sendmailDB sends html from the body, text from sub_title, cc from task.cc, bcc from fromEmailSets.bcc, and reply-to from fromEmailSets.reply_to or noreply. Inline data:image base64 content becomes CID inline attachments; template.attachments base64 files are sent as normal attachments. " +
        "Before sending, resolve the sender from email_settings: pass fromEmailSet as email_settings.id and preferably pass the full fromEmailSets record. " +
        "Do not use consumer sender records such as Gmail/Yahoo/Hotmail/abv.bg addresses; BROSH blocks those sender domains in sendmailDB. " +
        "Use this when AI generates a unique email for each contact/account.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: "object",
        required: ["rows"],
        properties: {
          rows: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              additionalProperties: true,
              properties: {
                id: {
                  type: "integer",
                  description: " recipient/contact ID.",
                },
                email: {
                  type: "string",
                  description: "Recipient email address.",
                },
                name: { type: "string", description: "Email's subject." },
                subject: {
                  type: "string",
                  description:
                    "Per-recipient email subject. If omitted, row.name or template.subject/name is used.",
                },
                message: {
                  type: "string",
                  description:
                    "Per-recipient email body. This is copied into task.description before BROSH sendEmails is called.",
                },
                body: {
                  type: "string",
                  description:
                    "Alias for message. Use HTML or plain text; BROSH converts plain newlines to <br>.",
                },
                first_name: {
                  type: "string",
                  description: "Recipient's first name.",
                },
                last_name: {
                  type: "string",
                  description: "Recipient's last name.",
                },
                account: {
                  type: "integer",
                  description:
                    "Optional account ID. BROSH copies this to the logged activity account field.",
                },
                email_opt_out: {
                  type: ["string", "integer", "boolean"],
                  description:
                    "If this value is 1, BROSH skips sending to this row.",
                },
                parent_exp: {
                  type: ["string", "integer"],
                  description:
                    "Optional related parent record ID used by BROSH templates and activity lookup logging.",
                },
                parentTable_exp: {
                  type: "string",
                  description:
                    "Optional related parent table name. If not campaigns/contacts/activity, BROSH writes activity[parentTable_exp] = parent_exp.",
                },
              },
              allOf: [
                { anyOf: [{ required: ["id"] }, { required: ["email"] }] },
                { anyOf: [{ required: ["message"] }, { required: ["body"] }] },
              ],
            description:
                "Per-recipient row. Requires recipient (email or id) and message content (message or body).",
            },
          },
          fromEmailSet: {
            type: "integer",
            description:
              "Sender email set ID from email_settings.id. Query email_settings first to get this value. Defaults to 3 if omitted.",
          },
          fromEmailSets: {
            type: "object",
            additionalProperties: true,
            required: ["id", "email"],
            properties: {
              id: { type: "integer" ,description: "Email setting ID, query from the database the full approved settings" },
              name: { type: "string", description: "Name of the sender." },
              email: { type: "string", format: "email", description: "Email address of the sender." },
              email_label: { type: "string" ,description: "Label for the sender email, e.g. 'Sales Team'." },
              type: { type: "string", description: "Sender transport type from email_settings, usually SMTP/email. Avoid sms/whatsapp for email." },
              host: { type: "string", description: "SMTP host or transport host from email_settings." },
              port: { type: "integer", description: "SMTP port from email_settings." },
              password: {
                type: "string",
                description:
                  "Sender credential from email_settings when returned by BROSH. Pass through the approved row; do not invent or expose it in chat.",
              },
              reply_to: { type: "string", description: "Reply-to email address. If blank, BROSH uses fromEmailSets.email." },
              bcc: { type: "string", description: "BCC address copied to the outgoing email message." },
              last_modified_date: { type: "string", description: "Date when the email settings were last modified." },
              last_modified_by: { type: "integer", description: "User ID of the person who last modified the email settings." },
            },
            description:
              "Full sender object from email_settings. BROSH uses this to create the SMTP/WhatsApp/SMS transport; for email use a normal email sender, not sms/whatsapp settings.",
          },
          template: {
            type: "object",
            additionalProperties: true,
            properties: {
              id: { type: "integer" },
              subject: {
                type: "string",
                description:
                  "Default subject when a row does not provide subject/name.",
              },
              name: {
                type: "string",
                description:
                  "Legacy default subject fallback when subject is omitted.",
              },
              body: {
                type: "string",
                description:
                  "Default body when a row does not provide message/body. May include HTML and inline data:image base64.",
              },
              sub_title: {
                type: "string",
                description:
                  "Plain-text sub title of the email.",
              },
              attachments: {
                type: "array",
                description:
                  "Optional base64 file attachments applied to each single-send message.",
                items: {
                  type: "object",
                  additionalProperties: true,
                  required: ["content"],
                  properties: {
                    name: { type: "string" },
                    type: { type: "string" },
                    content: {
                      type: "string",
                      description:
                        "Base64 encoded attachment content. Do not include a data: prefix.",
                    },
                    size: { type: "integer" },
                    description: { type: "string" },
                  },
                },
              },
            },
            description:
              "Optional defaults copied into the BROSH objectFill/template payload for each per-row email.",
          },
          task: {
            type: "object",
            additionalProperties: true,
            properties: {
              name: { type: "string", description: "Default email subject and logged activity subject. Per-row subject overrides this." },
              description: { type: "string", description: "Default email body. Per-row message/body overrides this." },
              status: { type: "string", description: "Activity status. BROSH sets this to Completed during send." },
              type: { type: "string", description: "Activity type. Use Email for email activity." },
              owner: { type: "integer", description: "User ID of the task owner." },
              person: { type: "integer", description: "Contact ID associated with the task." },
              account: { type: "integer", description: "Account ID associated with the task." },
              opportunities: { type: "integer", description: "Opportunity ID associated with the task." },
              project: { type: "integer", description: "Project ID associated with the task." },
              start_date: {
                type: "string",
                description: "Recommended format: YYYY-MM-DD or ISO datetime.",
              },
              end_date: {
                type: "string",
                description: "Recommended format: YYYY-MM-DD or ISO datetime.",
              },
              progress: { type: "integer", minimum: 0, maximum: 100 },
              last_modified_date: { type: "string", description: "Date when the task was last modified." },
              last_modified_by: { type: "integer", description: "User ID of the person who last modified the task." },
              created_date: { type: "string", description: "Date when the task was created." },
              ticket: { type: "integer" , description: "Ticket ID associated with the task."}, //ticket id
              campaign: { type: "integer" , description: "Campaign ID associated with the task."}, //
              template: { type: "integer", description: "Template ID associated with the task." }, //
              from: { type: "integer", description: "Email settings ID, use fromEmailSets id. Query from the database the full approved settings and pass the entire sender record here to ensure the send operation has all the necessary sender details and permissions." }, //email sender
              to: { type: "string", description: "Email recipient." }, //email recipient
              cc: { type: "string", description: "Email CC." }, //email cc
              message_status: { type: "string", description: "Message status, e.g. 'sent', 'failed'." }, //sent, failed, etc
              message_additional_info: { type: "string", description: "Any additional info about the send result." }, //any additional info about the send result
               
              file: { type: "integer", description: "File ID associated with the task." },
              created_by: { type: "integer", description: "User ID of the creator." },
              due_date: {
                type: "string",
                description:
                  "Alias commonly used by clients; maps to activity schedule semantics.",
              },
            },
            description:
              "Base activity object. For each row, this wrapper sets task.name to the row subject and task.description to the row message before calling BROSH.",
          } 
           
        },
        examples: [
          {
            fromEmailSet: 3, //query email_settings first and pass the chosen email_settings.id
            rows: [
              //contacts rows and BROSH will call sendEmail once per row/recipient
              {
                id: 101,
                email: "buyer1@example.com",
                first_name: "Buyer",
                last_name: "One",
                subject: "Reducing SLA risk this month",
                message:
                  "Hi Buyer One, we found 3 actions that can reduce SLA risk immediately...",
              },
              {
                id: 102,
                email: "buyer2@example.com",
                first_name: "Buyer",
                last_name: "Two",
                subject: "Reducing SLA risk this month",
                message:
                  "Hi Buyer Two, we found 2 actions that can reduce SLA risk immediately...",
              },
            ],
            task: {
              name: "Fallback subject",
              description: "Fallback body",
              due_date: "2024-07-31",
              status: "Completed",
              type: "Email",
            },
          },
        ],
      },
      outputSchema: { type: "object", additionalProperties: true },
    },
  ].filter(
    (tool) =>
      !String((tool as { name?: unknown }).name ?? "").startsWith("api_table_"),
  );
}

const DEFAULT_FROM_EMAIL_SET_ID = 3;
const SMS_FROM_EMAIL_SET_ID = 6;

function parsePositiveInteger(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value) && value > 0)
    return value;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isInteger(parsed) && parsed > 0) return parsed;
  }
  return null;
}

function asRecordArray(data: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(data)) {
    return data.filter(
      (item): item is Record<string, unknown> =>
        !!item && typeof item === "object",
    );
  }
  if (data && typeof data === "object") {
    const items = (data as { items?: unknown }).items;
    if (Array.isArray(items)) {
      return items.filter(
        (item): item is Record<string, unknown> =>
          !!item && typeof item === "object",
      );
    }
  }
  return [];
}

function isSmsLikeEmailSetting(record: Record<string, unknown>): boolean {
  const id = parsePositiveInteger(record.id);
  const name = String(record.name ?? "")
    .trim()
    .toLowerCase();
  const type = String(record.type ?? "")
    .trim()
    .toLowerCase();
  return (
    id === SMS_FROM_EMAIL_SET_ID || name.includes("sms") || type.includes("sms")
  );
}

function buildSenderFromRecord(
  record: Record<string, unknown>,
  fallbackId: number,
): Record<string, unknown> {
  const senderEmail = String(record.email ?? "").trim();
  return {
    id: parsePositiveInteger(record.id) ?? fallbackId,
    name: String(record.name ?? "").trim(),
    email: senderEmail,
    ...(String(record.email_label ?? "").trim()
      ? { email_label: String(record.email_label ?? "").trim() }
      : {}),
    ...(String(record.reply_to ?? "").trim()
      ? { reply_to: String(record.reply_to ?? "").trim() }
      : {}),
    ...(String(record.bcc ?? "").trim()
      ? { bcc: String(record.bcc ?? "").trim() }
      : {}),
  };
}

async function getEmailSettingById(
  id: number,
  broshToken: string,
): Promise<Record<string, unknown> | null> {
  const senderData = await broshRequest(
    "POST",
    `/api/oauth2/getRecords/${BROSH_SOURCE}/email_settings?limit=1`,
    broshToken,
    [id],
  );
  return asRecordArray(senderData)[0] ?? null;
}

async function listEmailSettingCandidates(
  broshToken: string,
): Promise<Array<Record<string, unknown>>> {
  const data = await broshRequest(
    "POST",
    `/api/oauth2/findRecords/${BROSH_SOURCE}/email_settings?limit=100`,
    broshToken,
    {
      fields: ["id", "name", "email", "email_label", "reply_to", "bcc", "type"],
      sort: [{ field: "id", direction: "ASC" }],
    },
  );
  return asRecordArray(data);
}

async function resolveEmailSenderPayload(
  args: Record<string, unknown>,
  broshToken: string,
): Promise<{
  normalizedArgs: Record<string, unknown>;
  sender: Record<string, unknown>;
}> {
  const requestedFromEmailSet = args.fromEmailSet;
  const requestedId =
    requestedFromEmailSet === undefined
      ? DEFAULT_FROM_EMAIL_SET_ID
      : parsePositiveInteger(requestedFromEmailSet);

  if (!requestedId) {
    throw new Error("fromEmailSet must be a positive integer.");
  }

  const isExplicitSelection = requestedFromEmailSet !== undefined;
  if (isExplicitSelection && requestedId === SMS_FROM_EMAIL_SET_ID) {
    throw new Error(
      "fromEmailSet=6 appears to be SMS settings. Use email sender settings (prefer id=3).",
    );
  }

  let senderRecord = await getEmailSettingById(requestedId, broshToken);
  let selectedId = requestedId;
  const senderEmail = String(senderRecord?.email ?? "").trim();
  const senderLooksValid =
    !!senderRecord && !!senderEmail && !isSmsLikeEmailSetting(senderRecord);

  if (!senderLooksValid && !isExplicitSelection) {
    const candidates = await listEmailSettingCandidates(broshToken);
    const fallback = candidates.find((record) => {
      const email = String(record.email ?? "").trim();
      return !!email && !isSmsLikeEmailSetting(record);
    });
    if (fallback) {
      senderRecord = fallback;
      selectedId = parsePositiveInteger(fallback.id) ?? requestedId;
    }
  }

  if (!senderRecord) {
    throw new Error(
      `No email_settings row found for fromEmailSet=${requestedId}.`,
    );
  }
  if (isSmsLikeEmailSetting(senderRecord)) {
    throw new Error(
      `email_settings row ${selectedId} is SMS-like and cannot be used for email sending.`,
    );
  }
  if (!String(senderRecord.email ?? "").trim()) {
    throw new Error(
      `email_settings row ${selectedId} is missing an email value.`,
    );
  }

  const sender = buildSenderFromRecord(senderRecord, selectedId);

  return {
    normalizedArgs: {
      ...args,
      fromEmailSet: selectedId,
      fromEmailSets: sender,
    },
    sender,
  };
}

async function callMcpTool(
  name: string,
  args: Record<string, unknown>,
  broshToken: string,
  sessionId: string,
): Promise<unknown> {
  // Use the user's BROSH access token from their session
  // (obtained during OAuth callback and passed through resolveBroshToken)
  const toolName = name;

  switch (toolName) {
    case "brosh_me":
      return broshRequest(
        "POST",
        `/api/oauth2/me/${BROSH_SOURCE}`,
        broshToken,
        {},
      );

    case "brosh_available_tables": {
      const session = sessions.get(sessionId);
      const { tables, fieldsByTable } = await fetchAvailableTablesForSession(
        broshToken,
      );

      if (session && tables.length > 0) {
        session.availableTables = tables;
        session.availableTableFields = fieldsByTable;
        saveSessions();
      }

      return {
        tableNames: tables,
        tables: tables.map((tableName) => ({
          name: tableName,
          fields: fieldsByTable[tableName] ?? [],
        })),
        total_count: tables.length,
      };
    }

    case "brosh_find": {
      const { table, fields, filter, sort, page_size, page, limit } = args;
      const tableName = resolveAllowedTableName(sessions.get(sessionId), table);
      const body: Record<string, unknown> = {};
      if (fields !== undefined) body.fields = fields;
      if (filter !== undefined) body.filter = filter;
      if (sort !== undefined) body.sort = sort;
      if (page_size !== undefined || limit !== undefined)
        body.page_size = page_size || limit || 10;
      if (page !== undefined) body.page = page;

      // Build URL with query params
      let url = `/api/oauth2/findRecords/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`;
      if (limit !== undefined) {
        url += `?limit=${limit}`;
      }

      return broshRequest("POST", url, broshToken, body);
    }

    case "brosh_get": {
      const { table, ids, limit } = args;
      const tableName = resolveAllowedTableName(sessions.get(sessionId), table);

      // Build URL with query params
      let url = `/api/oauth2/getRecords/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`;
      if (limit) {
        url += `?limit=${limit}`;
      }

      // Body should be array of IDs
      return broshRequest("POST", url, broshToken, ids);
    }

    case "brosh_create": {
      const { table, records } = args;
      const tableName = resolveAllowedTableName(sessions.get(sessionId), table);
      return broshRequest(
        "POST",
        `/api/oauth2/create/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`,
        broshToken,
        records,
      );
    }

    case "brosh_update": {
      const { table, records } = args;
      const tableName = resolveAllowedTableName(sessions.get(sessionId), table);
      return broshRequest(
        "POST",
        `/api/oauth2/update/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`,
        broshToken,
        records,
      );
    }

    case "brosh_modify_field": {
      const payload = args as {
        tableName?: string;
        oldField?: Record<string, unknown>;
        newField?: Record<string, unknown>;
        xFields?: Array<Record<string, unknown>>;
      };

      const tableName = String(payload.tableName ?? "").trim();
      if (!tableName || !isEnglishTableName(tableName)) {
        throw new Error(
          "brosh_modify_field requires a valid English tableName (letters, numbers, underscore, starting with a letter).",
        );
      }

      if (payload.xFields !== undefined && (!Array.isArray(payload.xFields) || payload.xFields.length !== 2)) {
        throw new Error(
          "brosh_modify_field requires xFields with exactly two items: [oldField, newField].",
        );
      }

      const oldFieldRaw =
        (Array.isArray(payload.xFields) ? payload.xFields[0] : payload.oldField) ??
        null;
      const newFieldRaw =
        (Array.isArray(payload.xFields) ? payload.xFields[1] : payload.newField) ??
        null;

      if (
        !oldFieldRaw ||
        typeof oldFieldRaw !== "object" ||
        Array.isArray(oldFieldRaw) ||
        !newFieldRaw ||
        typeof newFieldRaw !== "object" ||
        Array.isArray(newFieldRaw)
      ) {
        throw new Error(
          "brosh_modify_field requires oldField and newField objects (or xFields with exactly two objects).",
        );
      }

      const oldField = oldFieldRaw as Record<string, unknown>;
      const newField = newFieldRaw as Record<string, unknown>;
      const format3 = String(newField.format3 ?? "").toUpperCase();
      const allowedFormat3 = new Set([
        "VARCHAR",
        "DATE",
        "DATETIME",
        "DECIMAL",
        "INT",
        "BLOB",
        "TEXT",
        "MEDIUMTEXT",
      ]);

      if (!allowedFormat3.has(format3)) {
        throw new Error(
          "brosh_modify_field newField.format3 must be one of: VARCHAR, DATE, DATETIME, DECIMAL, INT, BLOB, TEXT, MEDIUMTEXT.",
        );
      }

      const newColName = String(newField.orgName ?? "").trim();
      if (!newColName || !/^[a-zA-Z0-9_]+$/.test(newColName)) {
        throw new Error(
          "brosh_modify_field newField.orgName is required and must contain only letters, numbers, underscore.",
        );
      }

      const oldColName = String(oldField.orgName ?? "").trim();
      if (oldColName && !/^[a-zA-Z0-9_]+$/.test(oldColName)) {
        throw new Error(
          "brosh_modify_field oldField.orgName may only contain letters, numbers, underscore.",
        );
      }

      const length = Number(newField.length ?? 0);
      const decimals = Number(newField.decimals ?? 0);
      if (format3 === "VARCHAR" || format3 === "INT") {
        if (!(length > 0 && length <= 250)) {
          throw new Error(
            `brosh_modify_field ${format3} requires length between 1 and 250.`,
          );
        }
      }
      if (format3 === "DECIMAL") {
        if (!(length > 0 && length <= 16 && decimals >= 0 && decimals <= 3)) {
          throw new Error(
            "brosh_modify_field DECIMAL requires length 1-16 and decimals 0-3.",
          );
        }
      }

      const xFieldsPayload = [oldField, newField];

      return broshRequest(
        "POST",
        `/api/oauth2/modifyfield/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`,
        broshToken,
        xFieldsPayload,
      );
    }

    case "brosh_delete": {
      const { table, ids } = args;
      const tableName = resolveAllowedTableName(sessions.get(sessionId), table);
      if (
        !Array.isArray(ids) ||
        ids.length === 0 ||
        !ids.every((id) => Number.isInteger(id))
      ) {
        throw new Error(
          "brosh_delete requires ids as a non-empty array of integers.",
        );
      }

      const confirm = args.confirm === true;
      const confirmationToken =
        typeof args.confirmationToken === "string"
          ? args.confirmationToken
          : "";
      const preview = {
        table: tableName,
        idsCount: ids.length,
        sampleIds: (ids as number[]).slice(0, 10),
      };

      if (!confirm) {
        const pending = createPendingConfirmation(
          sessionId,
          "brosh_delete",
          args,
          preview,
        );
        return buildConfirmationRequiredResponse("brosh_delete", pending);
      }

      if (!confirmationToken) {
        throw new Error(
          "brosh_delete confirm=true requires confirmationToken from a preview call.",
        );
      }
      consumePendingConfirmation(
        sessionId,
        "brosh_delete",
        args,
        confirmationToken,
      );

      const payload = (ids as number[]).map((id: number) => ({ id }));
      return broshRequest(
        "POST",
        `/api/oauth2/delete/${BROSH_SOURCE}/${encodeURIComponent(tableName)}`,
        broshToken,
        payload,
      );
    }

    case "brosh_send_email": {
      const payload = args as {
        rows?: unknown[];
        fromEmailSet?: number;
      };

      if (!Array.isArray(payload.rows) || payload.rows.length === 0) {
        throw new Error("brosh_send_email requires a non-empty rows array.");
      }

      const { normalizedArgs } = await resolveEmailSenderPayload(
        args,
        broshToken,
      );

      return broshRequest(
        "POST",
        `/api/oauth2/sendEmail/${BROSH_SOURCE}`,
        broshToken,
        normalizedArgs,
      );
    }

    case "brosh_send_message_single": {
      const payload = args as {
        rows?: Array<Record<string, unknown>>;
        fromEmailSet?: number;
        template?: Record<string, unknown>;
        task?: Record<string, unknown>;
      };

      if (!Array.isArray(payload.rows) || payload.rows.length === 0) {
        throw new Error(
          "brosh_send_message_single requires a non-empty rows array.",
        );
      }

      const { normalizedArgs } = await resolveEmailSenderPayload(
        args,
        broshToken,
      );

      const normalizedPayload = normalizedArgs as typeof payload;
      const {
        rows: normalizedRows,
        ...basePayload
      } = normalizedPayload;
      const rows = normalizedRows ?? [];
      const results: Array<{
        index: number;
        recipient?: string;
        result: unknown;
      }> = [];

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i] ?? {};
        const message = String(row.message ?? row.body ?? "").trim();
        const subject = String(
          row.subject ??
            row.name ??
            payload.template?.subject ??
            payload.template?.name ??
            "AI Message",
        ).trim();

        if (!message) {
          throw new Error(
            `brosh_send_message_single row ${i} is missing message/body.`,
          );
        }

        const singlePayload: Record<string, unknown> = {
          ...basePayload,
          templateid: 0,
          template: {
            ...(payload.template ?? {}),
            id: 0,
            subject: subject || "AI Message",
            body: message,
          },
          task: {
            ...((basePayload.task as Record<string, unknown> | undefined) ?? {}),
            name: subject || "AI Message",
            description: message,
            type:
              ((basePayload.task as Record<string, unknown> | undefined)?.type as string | undefined) ??
              "Email",
          },
          rows: [row],
        };

        const sendResult = await broshRequest(
          "POST",
          `/api/oauth2/sendEmail/${BROSH_SOURCE}`,
          broshToken,
          singlePayload,
        );
        results.push({
          index: i,
          recipient: String(row.email ?? row.id ?? ""),
          result: sendResult,
        });
      }

      return {
        processed: rows.length,
        mode: "one-by-one",
        results,
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

async function handleMcpRequest(
  msg: McpMessage,
  session: UserSession,
): Promise<unknown> {
  const { method, id, params } = msg;

  // console.log('[MCP Handler] method:', method, 'id:', id, 'hasId:', 'id' in msg);

  // JSON-RPC notifications have no `id` and require no response
  if (!("id" in msg) || method.startsWith("notifications/")) {
    console.log("[MCP Handler] Treating as notification, returning null");
    return null;
  }

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          capabilities: { tools: { listChanged: true } },
          serverInfo: { name: "brosh-crm", version: "1.0.0" },
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: buildMcpToolList(session) },
      };

    case "tools/call": {
      const { name, arguments: toolArgs = {} } = (params ?? {}) as {
        name: string;
        arguments?: Record<string, unknown>;
      };
      try {
        let activeSession = session;
        let output: unknown;

        try {
          output = await callMcpTool(
            name,
            toolArgs,
            activeSession.broshAccessToken,
            activeSession.id,
          );
        } catch (err: unknown) {
          if (axios.isAxiosError(err) && err.response?.status === 401) {
            const refreshed = await tryRefreshBroshToken(activeSession);
            if (refreshed) {
              activeSession = refreshed;
              output = await callMcpTool(
                name,
                toolArgs,
                activeSession.broshAccessToken,
                activeSession.id,
              );
            } else {
              // Token refresh failed — signal caller to return HTTP 401 so
              // OpenAI (and other MCP clients) surface the reconnect button.
              throw new BroshUnauthorizedError();
            }
          } else {
            throw err;
          }
        }

        const text =
          typeof output === "string" ? output : JSON.stringify(output);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text }],
          },
        };
      } catch (err: unknown) {
        // BroshUnauthorizedError must reach handleMcpHttpRequest so it can
        // return HTTP 401 and trigger the MCP client's OAuth reconnect UI.
        if (err instanceof BroshUnauthorizedError) throw err;

        // Extract meaningful error message from axios errors
        let errorMessage: string;
        let isUnauthorized = false;
        if (axios.isAxiosError(err)) {
          const status = err.response?.status || "N/A";
          isUnauthorized = err.response?.status === 401;
          const data = err.response?.data;
          const details =
            typeof data === "object"
              ? JSON.stringify(data)
              : String(data || err.message);
          errorMessage = `BROSH API Error (${status}): ${details}`;
          console.error(`[MCP Tool Error] ${name}:`, errorMessage);
        } else if (err instanceof Error) {
          errorMessage = err.message;
          console.error(`[MCP Tool Error] ${name}:`, err.message, err.stack);
        } else {
          errorMessage = String(err);
          console.error(`[MCP Tool Error] ${name}:`, err);
        }

        const authUrl = `${SERVER_URL}${LOGIN_PATH}`;
        const reconnectHint = isUnauthorized
          ? `\n\n⚠️ Session expired or unauthorized. Re-authorize at: ${authUrl}`
          : "";

        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              { type: "text", text: `Error calling ${name}: ${errorMessage}${reconnectHint}` },
            ],
            isError: true,
          },
        };
      }
    }

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

function buildMcpWwwAuthenticateHeader(): string {
  return `Bearer resource_metadata="${SERVER_URL}/.well-known/oauth-protected-resource", scope="openid profile email Full"`;
}

async function handleMcpHttpRequest(
  req: Request,
  res: Response,
): Promise<void> {
  const msg = req.body as McpMessage;
  const session = await resolveBroshSession(req.headers.authorization);

  if (!session) {
    // Allow initialize unauthenticated so MCP clients can probe server capabilities
    // before OAuth. Tool discovery is authenticated because the table list is
    // user-specific and must be built from the linked BROSH profile.
    const isUnauthenticatedAllowed =
      msg?.method === "initialize";

    if (isUnauthenticatedAllowed) {
      // For initialize / tools/list: delegate to handleMcpRequest with a dummy session stub.
      // We pass null and handle below — actually just handle them inline.
      if (msg?.method === "initialize") {
        res.json({
          jsonrpc: "2.0",
          id: msg.id ?? null,
          result: {
            protocolVersion: "2025-03-26",
          capabilities: { tools: { listChanged: true } },
            serverInfo: { name: "brosh-crm", version: "1.0.0" },
          },
        });
        return;
      }
    }

    res
      .status(401)
      .set("WWW-Authenticate", buildMcpWwwAuthenticateHeader())
      .json({
        jsonrpc: "2.0",
        id: msg?.id ?? null,
        error: {
          code: -32001,
          message:
            "Unauthorized — provide an access token issued by this server via Authorization: Bearer <token>.",
        },
      });
    return;
  }

  // console.log('[MCP] Received request:', JSON.stringify(msg, null, 2));

  try {
    const result = await handleMcpRequest(msg, session);
    // console.log('[MCP] Response:', result === null ? 'null (notification)' : JSON.stringify(result, null, 2));

    if (result === null) {
      res.status(202).end(); // notifications: 202 Accepted, no body
    } else {
      res.json(result);
    }
  } catch (err: unknown) {
    // When BROSH session is truly expired, return HTTP 401 so MCP clients
    // (OpenAI, Claude, etc.) surface the OAuth reconnect / blue button UI.
    if (err instanceof BroshUnauthorizedError) {
      res
        .status(401)
        .set("WWW-Authenticate", buildMcpWwwAuthenticateHeader())
        .json({
          jsonrpc: "2.0",
          id: (msg as unknown as Record<string, unknown>).id ?? null,
          error: {
            code: -32001,
            message:
              "Unauthorized — BROSH session expired. Re-authorize via the Connect button.",
          },
        });
      return;
    }
    console.error("[MCP] Unhandled error:", err);
    res.status(500).json({
      jsonrpc: "2.0",
      id: (msg as unknown as Record<string, unknown>).id ?? null,
      error: { code: -32603, message: String(err) },
    });
  }
}

// GET /api/mcp — canonical MCP endpoint. Legacy /mcp remains as a compatibility
// alias for older client configurations.
app.get([MCP_PATH, "/mcp"], (_req: Request, res: Response) => {
  res
    .status(401)
    .set("WWW-Authenticate", buildMcpWwwAuthenticateHeader())
    .json({
      error:
        "Unauthorized — use OAuth Bearer token and POST to send MCP messages.",
    });
});

app.options([MCP_PATH, "/mcp"], (_req: Request, res: Response) => {
  res
    .status(401)
    .set("WWW-Authenticate", buildMcpWwwAuthenticateHeader())
    .set("Allow", "POST, OPTIONS")
    .json({
      error:
        "Unauthorized — use OAuth Bearer token and POST to send MCP messages.",
    });
});

// POST /api/mcp — canonical Streamable HTTP transport (MCP spec §2).
// Legacy POST / and POST /mcp remain available for previously configured clients.
app.post([MCP_PATH, "/mcp", "/"], handleMcpHttpRequest);

// ─── OIDC / OAuth AS Discovery ────────────────────────────────────────────────────
// MCP spec (2025-11-25) requires authorization servers to expose at least one of:
//   • OAuth 2.0 Authorization Server Metadata (RFC 8414)
//   • OpenID Connect Discovery 1.0
// We serve both so every MCP client and OIDC-capable consumer can discover endpoints.

function buildAuthServerMetadata() {
  return {
    issuer: SERVER_URL,
    authorization_endpoint: `${SERVER_URL}${AUTHORIZE_PATH}`,
    token_endpoint: `${SERVER_URL}${TOKEN_PATH}`,
    revocation_endpoint: `${SERVER_URL}${REVOKE_PATH}`,
    userinfo_endpoint: `${SERVER_URL}${USERINFO_PATH}`,
    jwks_uri: `${SERVER_URL}/.well-known/jwks.json`,
    // RFC 7591 — Dynamic Client Registration (required for ChatGPT Apps SDK)
    registration_endpoint: `${SERVER_URL}${REGISTER_PATH}`,
    resource_parameter_supported: true,
    // scopes_supported signals to ChatGPT that OIDC email claims are available
    scopes_supported: ["openid", "profile", "email", "Full"],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: [
      "none",
      "private_key_jwt",
    ],
    // For CIMD clients, ChatGPT supports none/private_key_jwt. Keep the
    // explicit default aligned to CIMD-safe behavior.
    token_endpoint_auth_method: "private_key_jwt",
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "name",
      "email",
      "email_verified",
      "nonce",
    ],
    // PKCE — required by MCP spec §11.4; S256 is strongly preferred
    code_challenge_methods_supported: ["S256", "plain"],
    // MCP spec §5.1.4 — advertise support for Client ID Metadata Documents (CIMD)
    // Both CIMD and DCR (RFC 7591) are fully implemented
    client_id_metadata_document_supported: true,
    // RFC 7591 support declaration
    registration_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  };
}

// OpenID Connect Discovery 1.0
app.get("/.well-known/openid-configuration", (_req: Request, res: Response) => {
  res
    .setHeader("Content-Type", "application/json")
    .setHeader("Cache-Control", "public, max-age=3600")
    .json(buildAuthServerMetadata());
});

app.options(
  "/.well-known/openid-configuration",
  (_req: Request, res: Response) => {
    res
      .setHeader("Access-Control-Allow-Origin", "*")
      .setHeader("Access-Control-Allow-Methods", "GET, OPTIONS")
      .status(204)
      .end();
  },
);

// RFC 8414 — OAuth 2.0 Authorization Server Metadata
app.get(
  "/.well-known/oauth-authorization-server",
  (_req: Request, res: Response) => {
    res
      .setHeader("Content-Type", "application/json")
      .setHeader("Cache-Control", "public, max-age=3600")
      .json(buildAuthServerMetadata());
  },
);

app.options(
  "/.well-known/oauth-authorization-server",
  (_req: Request, res: Response) => {
    res
      .setHeader("Access-Control-Allow-Origin", "*")
      .setHeader("Access-Control-Allow-Methods", "GET, OPTIONS")
      .status(204)
      .end();
  },
);

// JWKS endpoint — exposes the RS256 public key used to sign id_tokens.
// Clients use this to verify id_token signatures without contacting the server.
app.get("/.well-known/jwks.json", (_req: Request, res: Response) => {
  res
    .setHeader("Content-Type", "application/json")
    .setHeader("Cache-Control", "public, max-age=3600")
    .json({
      keys: [
        {
          ...oidcPublicJwk,
          use: "sig",
          alg: "RS256",
          kid: OIDC_KID,
        },
      ],
    });
});

app.options("/.well-known/jwks.json", (_req: Request, res: Response) => {
  res
    .setHeader("Access-Control-Allow-Origin", "*")
    .setHeader("Access-Control-Allow-Methods", "GET, OPTIONS")
    .status(204)
    .end();
});

function buildProtectedResourceMetadata(resource: string) {
  return {
    resource,
    authorization_servers: [SERVER_URL],
    bearer_methods_supported: ["header"],
    scopes_supported: ["openid", "email", "profile", "Full"],
    resource_documentation: `${SERVER_URL}${OPENAPI_PATH}`,
    // Hint for clients that need explicit OAuth client parameters during
    // app submission/publishing validation.
    oauth_client_params: {
      token_endpoint_auth_method: "none",
    },
  };
}

// GET /.well-known/oauth-protected-resource — MCP auth discovery (RFC 9728)
// Tells MCP clients where to find the authorization server and which scopes are needed.
app.get(
  "/.well-known/oauth-protected-resource",
  (_req: Request, res: Response) => {
    res
      .setHeader("Content-Type", "application/json")
      .setHeader("Cache-Control", "public, max-age=3600")
      .json(buildProtectedResourceMetadata(ROOT_RESOURCE));
  },
);

app.options(
  "/.well-known/oauth-protected-resource",
  (_req: Request, res: Response) => {
    res
      .setHeader("Access-Control-Allow-Origin", "*")
      .setHeader("Access-Control-Allow-Methods", "GET, OPTIONS")
      .setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
      .status(204)
      .end();
  },
);

app.get(
  [
    "/.well-known/oauth-protected-resource/api/mcp",
    "/.well-known/oauth-protected-resource/mcp",
  ],
  (_req: Request, res: Response) => {
    res
      .setHeader("Content-Type", "application/json")
      .setHeader("Cache-Control", "public, max-age=3600")
      .json(buildProtectedResourceMetadata(MCP_RESOURCE));
  },
);

app.get(
  "/.well-known/openai-apps-challenge",
  (_req: Request, res: Response) => {
    res
      .setHeader("Content-Type", "application/json")
      .setHeader("Cache-Control", "public, max-age=3600")
      .send("M6L4zzq7tLqX2od1NoUkGg3lHgp2dJ3MouA7n5ABBQY")
      .end();
  },
);

// ─── RFC 7591 — Dynamic Client Registration ────────────────────────────────────
// ChatGPT and other MCP clients call this once to self-register without manual setup.
// Returns a client_id + client_secret the client stores and uses for token exchange.
// Fully compliant with RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol).

app.post([REGISTER_PATH, "/oauth/register"], (req: Request, res: Response) => {
  // console.log('[DCR] Registration request received:', JSON.stringify(req.body, null, 2));

  const body = req.body as Record<string, unknown>;

  // Validate redirect_uris (required per RFC 7591 §3.1)
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
    console.log("[DCR] ERROR: Missing or invalid redirect_uris");
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description:
        "redirect_uris is required and must be a non-empty array.",
    });
    return;
  }

  // Validate redirect URIs are valid URLs
  const redirect_uris = body.redirect_uris as string[];
  for (const uri of redirect_uris) {
    try {
      const url = new URL(uri);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new Error("Invalid protocol");
      }
    } catch (err) {
      console.log(`[DCR] ERROR: Invalid redirect_uri: ${uri}`);
      res.status(400).json({
        error: "invalid_redirect_uri",
        error_description: `Invalid redirect_uri: ${uri}. Must be a valid HTTPS URL.`,
      });
      return;
    }
  }

  const grant_types: string[] = Array.isArray(body.grant_types)
    ? (body.grant_types as string[])
    : ["authorization_code"];
  const response_types: string[] = Array.isArray(body.response_types)
    ? (body.response_types as string[])
    : ["code"];
  const token_endpoint_auth_method =
    typeof body.token_endpoint_auth_method === "string"
      ? body.token_endpoint_auth_method
      : "client_secret_basic";

  // Validate token_endpoint_auth_method is supported
  const supportedAuthMethods = [
    "none",
    "client_secret_post",
    "client_secret_basic",
 
    "private_key_jwt",
  ];
  if (!supportedAuthMethods.includes(token_endpoint_auth_method)) {
    console.log(
      `[DCR] ERROR: Unsupported token_endpoint_auth_method: ${token_endpoint_auth_method}`,
    );
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description: `Unsupported token_endpoint_auth_method. Supported methods: ${supportedAuthMethods.join(", ")}`,
    });
    return;
  }

  const client_id = `dyn-${crypto.randomBytes(16).toString("hex")}`;
  const client_secret =
    token_endpoint_auth_method === "none"
      ? ""
      : crypto.randomBytes(32).toString("hex");

  const client: RegisteredClient = {
    client_id,
    client_secret,
    redirect_uris,
    client_name:
      typeof body.client_name === "string" ? body.client_name : undefined,
    client_uri:
      typeof body.client_uri === "string" ? body.client_uri : undefined,
    grant_types,
    response_types,
    token_endpoint_auth_method,
    scope:
      typeof body.scope === "string" ? body.scope : "openid profile email Full",
    created_at: Date.now(),
  };

  registeredClients.set(client_id, client);
  console.log(`[DCR] ✓ Successfully registered client: ${client_id}`);
  console.log(`[DCR]   Client name: ${client.client_name ?? "unnamed"}`);
  console.log(`[DCR]   Auth method: ${token_endpoint_auth_method}`);
  console.log(`[DCR]   Redirect URIs: ${redirect_uris.join(", ")}`);

  // RFC 7591 §3.2.1 — Client Information Response
  const response: Record<string, unknown> = {
    client_id,
    client_id_issued_at: Math.floor(client.created_at / 1000),
    redirect_uris,
    grant_types,
    response_types,
    token_endpoint_auth_method,
  };

  // Only include client_secret if not a public client (RFC 7591 §3.2.1)
  if (token_endpoint_auth_method !== "none") {
    response.client_secret = client_secret;
    response.client_secret_expires_at = 0; // never expires
  }

  // Optional metadata
  if (client.client_name) response.client_name = client.client_name;
  if (client.client_uri) response.client_uri = client.client_uri;
  if (client.scope) response.scope = client.scope;

  res
    .status(201)
    .setHeader("Content-Type", "application/json")
    .setHeader("Cache-Control", "no-store")
    .setHeader("Pragma", "no-cache")
    .json(response);
});

// ─── Helpers ───────────────────────────────────────────────────────────────────

function stripConfirmationFields(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const { confirm, confirmationToken, previewOnly, ...rest } = args;
  return rest;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(
    ([a], [b]) => a.localeCompare(b),
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

function hashToolArgs(args: Record<string, unknown>): string {
  const normalized = stableStringify(stripConfirmationFields(args));
  return crypto.createHash("sha256").update(normalized).digest("hex");
}

function createPendingConfirmation(
  sessionId: string,
  toolName: ConfirmableToolName,
  args: Record<string, unknown>,
  preview: Record<string, unknown>,
): PendingConfirmation {
  const token = `cfm_${crypto.randomBytes(16).toString("hex")}`;
  const now = Date.now();
  const pending: PendingConfirmation = {
    token,
    sessionId,
    toolName,
    argsHash: hashToolArgs(args),
    preview,
    createdAt: now,
    expiresAt: now + OP_CONFIRM_TTL_MS,
  };
  pendingConfirmations.set(token, pending);
  return pending;
}

function consumePendingConfirmation(
  sessionId: string,
  toolName: ConfirmableToolName,
  args: Record<string, unknown>,
  confirmationToken: string,
): void {
  const pending = pendingConfirmations.get(confirmationToken);
  if (!pending) {
    throw new Error(
      "Invalid confirmationToken. Run the preview call again to get a fresh token.",
    );
  }
  if (pending.expiresAt < Date.now()) {
    pendingConfirmations.delete(confirmationToken);
    throw new Error("confirmationToken expired. Run the preview call again.");
  }
  if (pending.sessionId !== sessionId) {
    throw new Error(
      "confirmationToken does not belong to the current session.",
    );
  }
  if (pending.toolName !== toolName) {
    throw new Error(
      `confirmationToken is for ${pending.toolName}, not ${toolName}.`,
    );
  }
  if (pending.argsHash !== hashToolArgs(args)) {
    throw new Error(
      "Request payload changed since preview. Re-run preview and confirm again.",
    );
  }

  // One-time use confirmation token
  pendingConfirmations.delete(confirmationToken);
}

function buildConfirmationRequiredResponse(
  toolName: ConfirmableToolName,
  pending: PendingConfirmation,
): Record<string, unknown> {
  return {
    requiresConfirmation: true,
    operation: toolName,
    confirmationToken: pending.token,
    expiresAt: pending.expiresAt,
    preview: pending.preview,
    nextStep: `Call ${toolName} again with the same arguments plus confirm=true and confirmationToken.`,
  };
}

function signJwt(sessionId: string, audience: string = ROOT_RESOURCE): string {
  return jwt.sign({ sessionId, token_use: "access" }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL_SEC,
    issuer: SERVER_URL,
    audience,
    subject: sessionId,
  });
}

function signRefreshToken(
  sessionId: string,
  audience: string = ROOT_RESOURCE,
): string {
  return jwt.sign({ sessionId, token_use: "refresh" }, JWT_SECRET, {
    expiresIn: REFRESH_TOKEN_TTL_SEC,
    issuer: SERVER_URL,
    audience,
    subject: sessionId,
  });
}

/**
 * Mints an OIDC id_token (RS256) for the given session.
 * Includes standard JWT claims plus name/email when available from the upstream IdP.
 */
function mintIdToken(
  session: UserSession,
  audience: string,
  nonce?: string,
): string {
  const now = Math.floor(Date.now() / 1000);
  const sub = String(session.userInfo?.userid ?? session.id);
  const claims: Record<string, unknown> = {
    iss: SERVER_URL,
    sub,
    aud: audience,
    iat: now,
    exp: now + 3600,
  };
  if (session.userInfo?.name) claims.name = session.userInfo.name;
  if (session.userInfo?.email) {
    claims.email = session.userInfo.email;
    claims.email_verified = true;
  }
  if (nonce) claims.nonce = nonce;
  return jwt.sign(claims, OIDC_PRIVATE_KEY, {
    algorithm: "RS256",
    keyid: OIDC_KID,
  });
}

/**
 * Verifies a PKCE code_verifier against the stored code_challenge.
 * Uses timing-safe comparison to prevent timing side-channel attacks.
 */
function verifyPkce(
  verifier: string,
  challenge: string,
  method: string,
): boolean {
  try {
    if (method === "S256") {
      const computed = crypto
        .createHash("sha256")
        .update(verifier)
        .digest("base64url");
      if (computed.length !== challenge.length) return false;
      return crypto.timingSafeEqual(
        Buffer.from(computed),
        Buffer.from(challenge),
      );
    }
    if (method === "plain") {
      if (verifier.length !== challenge.length) return false;
      return crypto.timingSafeEqual(
        Buffer.from(verifier),
        Buffer.from(challenge),
      );
    }
  } catch {
    // timingSafeEqual throws on unequal length; already guarded above
  }
  return false;
}

/** Builds standard OIDC UserInfo response claims from a session. */
function buildUserinfoClaims(session: UserSession): Record<string, unknown> {
  const sub = String(session.userInfo?.userid ?? session.id);
  const claims: Record<string, unknown> = { sub };
  if (session.userInfo?.name) claims.name = session.userInfo.name;
  if (session.userInfo?.email) {
    claims.email = session.userInfo.email;
    claims.email_verified = true;
  }
  return claims;
}

function verifyAccessToken(
  token: string,
  audiences: string[],
): jwt.JwtPayload & { sessionId: string; token_use?: string } {
  const payload = jwt.verify(token, JWT_SECRET, {
    issuer: SERVER_URL,
  }) as unknown as jwt.JwtPayload & { sessionId: string; token_use?: string };
  if (payload.token_use !== "access") {
    throw new Error("Invalid access token type.");
  }
  const audience = getTokenAudience(payload);
  if (!audience || !audiences.includes(audience)) {
    throw new Error("Invalid token audience.");
  }
  return payload;
}

function getTokenAudience(payload: jwt.JwtPayload): string | undefined {
  if (typeof payload.aud === "string") return payload.aud;
  if (
    Array.isArray(payload.aud) &&
    payload.aud.length > 0 &&
    typeof payload.aud[0] === "string"
  ) {
    return payload.aud[0];
  }
  return undefined;
}

function normalizeAbsoluteUrl(value: string): string {
  const url = new URL(value);
  if (url.hash || url.search)
    throw new Error(
      "resource URLs must not include query strings or fragments.",
    );
  const pathname = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "");
  return `${url.protocol}//${url.host}${pathname}`;
}

function resolveRequestedResource(resource?: string): string {
  if (!resource) return ROOT_RESOURCE;
  const normalized = normalizeAbsoluteUrl(resource);

  // Some MCP clients send only the server origin as resource.
  // Canonicalize origin-only targets to the MCP resource audience.
  const allowedOrigins = new Set<string>([
    new URL(SERVER_URL).origin,
    new URL(ROOT_RESOURCE).origin,
    new URL(API_RESOURCE).origin,
    new URL(MCP_RESOURCE).origin,
    new URL(LEGACY_MCP_RESOURCE).origin,
  ]);
  if (allowedOrigins.has(normalized)) {
    return ROOT_RESOURCE;
  }

  const allowedResources = new Set([
    ROOT_RESOURCE,
    API_RESOURCE,
    MCP_RESOURCE,
    LEGACY_MCP_RESOURCE,
  ]);
  if (!allowedResources.has(normalized)) {
    throw new Error(`Unsupported resource: ${normalized}`);
  }
  return normalized;
}

async function validateClientAuthorizationRequest(
  clientId: string | undefined,
  redirectUri: string,
): Promise<void> {
  new URL(redirectUri);

  if (!clientId) return;

  if (OPENAI_CLIENT_ID && clientId === OPENAI_CLIENT_ID) return;

  const registeredClient = registeredClients.get(clientId);
  if (registeredClient) {
    if (!registeredClient.redirect_uris.includes(redirectUri)) {
      throw new Error("redirect_uri is not registered for this client.");
    }
    return;
  }

  if (isUrlClientId(clientId)) {
    const response = await axios.get(clientId, {
      timeout: 5000,
      maxRedirects: 2,
      headers: { Accept: "application/json" },
    });
    const data = response.data as {
      client_id?: string;
      redirect_uris?: string[];
    };
    if (data.client_id !== clientId) {
      throw new Error(
        "CIMD client_id does not match the metadata document URL.",
      );
    }
    if (
      !Array.isArray(data.redirect_uris) ||
      !data.redirect_uris.includes(redirectUri)
    ) {
      throw new Error(
        "redirect_uri is not allowed by the client metadata document.",
      );
    }
    return;
  }

  if (OPENAI_CLIENT_ID) {
    throw new Error("Unknown client_id.");
  }
}

/** Returns true when a client_id looks like a CIMD URL. */
function isUrlClientId(clientId: string): boolean {
  try {
    const u = new URL(clientId);
    return u.protocol === "https:" && u.pathname !== "/";
  } catch {
    return false;
  }
}

function buildBroshAuthUrl(state: string, redirectUri: string): string {
  const url = new URL(`${BROSH_BASE_URL}/en/login`);
  url.searchParams.set("src", BROSH_SOURCE);
  url.searchParams.set("client_id", BROSH_CLIENT_ID);
  url.searchParams.set("state", state);
  url.searchParams.set("scope", "Full");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  return url.toString();
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sendDesktopCallbackBridge(res: Response, callbackUrl: string): void {
  res.setHeader("Content-Type", "text/html; charset=UTF-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM — Connected</title>
  <link rel="icon" href="https://www.brosh.io/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --bg-1:#071426;--bg-2:#0f2e46;--bg-3:#1a6a7e;
      --brand-1:#08a2a1;--brand-2:#1a5cc8;--accent:#ff8a3d;
      --ok-bg:#d8f7e9;--ok-tx:#10563d;
    }
    body{
      font-family:'Manrope',system-ui,-apple-system,sans-serif;
      background:
        radial-gradient(900px 560px at 5% -20%,rgba(255,138,61,.22),transparent 70%),
        radial-gradient(1000px 600px at 95% -30%,rgba(8,162,161,.20),transparent 72%),
        linear-gradient(135deg,var(--bg-1) 0%,var(--bg-2) 45%,var(--bg-3) 100%);
      min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    }
    .card{
      background:linear-gradient(180deg,#fff 0%,#f7fbff 100%);
      border-radius:24px;
      box-shadow:0 28px 80px rgba(1,8,20,.44);
      border:1px solid rgba(255,255,255,.6);
      padding:48px 40px 40px;
      max-width:480px;width:100%;text-align:center;
      animation:rise .55s cubic-bezier(.22,.61,.36,1) both;
      position:relative;overflow:hidden;
    }
    .card::before{
      content:'';position:absolute;width:340px;height:340px;
      right:-160px;top:-180px;border-radius:50%;
      background:radial-gradient(circle,rgba(8,162,161,.18),transparent 70%);
      pointer-events:none;
    }
    @keyframes rise{from{opacity:0;transform:translateY(22px)}to{opacity:1;transform:translateY(0)}}
    .check-wrap{
      width:80px;height:80px;border-radius:50%;
      background:linear-gradient(135deg,var(--brand-1),var(--brand-2));
      box-shadow:0 10px 32px rgba(8,162,161,.45);
      display:flex;align-items:center;justify-content:center;
      margin:0 auto 28px;
      animation:pop .5s .2s cubic-bezier(.34,1.56,.64,1) both;
    }
    @keyframes pop{from{opacity:0;transform:scale(.4)}to{opacity:1;transform:scale(1)}}
    .check-wrap svg{width:38px;height:38px;stroke:#fff;stroke-width:3;fill:none;
      stroke-linecap:round;stroke-linejoin:round}
    .check-path{stroke-dasharray:50;stroke-dashoffset:50;animation:draw .4s .6s ease forwards}
    @keyframes draw{to{stroke-dashoffset:0}}
    h1{
      font-family:'Space Grotesk','Manrope',sans-serif;
      font-size:clamp(22px,4vw,30px);font-weight:700;letter-spacing:-.5px;
      background:linear-gradient(130deg,#104179 0%,#0e7f8f 55%,#ff8a3d 100%);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      margin-bottom:10px;
    }
    .tagline{color:#597095;font-size:15px;font-weight:500;margin-bottom:28px;line-height:1.5}
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      background:var(--ok-bg);color:var(--ok-tx);
      padding:10px 20px;border-radius:50px;
      font-size:14px;font-weight:700;margin-bottom:28px;
    }
    .pill svg{width:16px;height:16px;fill:var(--ok-tx);flex-shrink:0}
    .divider{height:1px;background:#dce8f6;margin:24px 0}
    .hint{font-size:13px;color:#829ab1;line-height:1.6;margin-bottom:20px}
    .btn{
      display:inline-block;padding:13px 28px;border-radius:12px;
      text-decoration:none;color:#fff;font-weight:700;font-size:15px;
      background:linear-gradient(130deg,var(--brand-2),var(--brand-1));
      box-shadow:0 8px 22px rgba(26,92,200,.35);
      transition:opacity .15s,transform .15s;
    }
    .btn:hover{opacity:.88;transform:translateY(-1px)}
    .brand{
      margin-top:28px;font-size:12px;font-weight:600;letter-spacing:.04em;
      color:#b0c4de;text-transform:uppercase;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="check-wrap">
      <svg viewBox="0 0 24 24"><polyline class="check-path" points="4,13 9,18 20,7"/></svg>
    </div>
    <h1>You're Connected!</h1>
    <p class="tagline">Your BROSH CRM account has been authorized.<br>You can close this window and return to your AI assistant.</p>
    <div class="pill">
      <svg viewBox="0 0 20 20"><path d="M10 2a8 8 0 100 16A8 8 0 0010 2zm3.7 6.3l-4 4a1 1 0 01-1.4 0l-2-2a1 1 0 111.4-1.4L9 10.58l3.3-3.3a1 1 0 111.4 1.42z"/></svg>
      Authentication Successful
    </div>
    <div class="divider"></div>
    <p id="hint" class="hint">Finalizing connection…</p>
    <a id="fallback-btn" class="btn" href="${escapeHtml(callbackUrl)}" style="display:none">Open App Manually</a>
    <div class="brand">BROSH AI CRM &nbsp;·&nbsp; Powered by MCP</div>
  </div>
  <script>
    var callbackUrl = ${JSON.stringify(callbackUrl)};
    var parsed = new URL(callbackUrl);
    var isLoopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1';
    var isCustomScheme = parsed.protocol !== 'http:' && parsed.protocol !== 'https:';

    if (isLoopback) {
      // Deliver the OAuth code to Codex's local server via background fetch.
      // Browsers treat http://127.0.0.1 as a secure context (W3C Secure Contexts spec),
      // so this fetch from HTTPS is allowed and is not blocked as mixed content.
      function deliverCode() {
        return fetch(callbackUrl, { mode: 'no-cors' }).catch(function() {});
      }
      deliverCode();
      setTimeout(deliverCode, 700);
      setTimeout(function() {
        deliverCode().then(function() {
          document.getElementById('hint').textContent = 'Connection complete. You can safely close this window.';
        }).catch(function() {
          document.getElementById('hint').textContent = 'Could not reach the app automatically.';
          document.getElementById('fallback-btn').style.display = 'inline-block';
        });
      }, 1400);
    } else if (isCustomScheme) {
      // Custom URL scheme (e.g. myapp://) — must navigate to trigger OS to open the app.
      document.getElementById('hint').textContent = 'Opening your app…';
      window.location.replace(callbackUrl);
    } else {
      document.getElementById('hint').textContent = 'Connection complete. You can safely close this window.';
    }
  </script>
</body>
</html>`);
}

function deliverOAuthCallback(res: Response, callbackUrl: string): void {
  const parsed = new URL(callbackUrl);
  const proto = parsed.protocol.toLowerCase();
  const isLoopback = ["localhost", "127.0.0.1", "::1"].includes(
    parsed.hostname,
  );
  const isCustomScheme = proto !== "https:" && proto !== "http:";
  if (isLoopback || isCustomScheme) {
    sendDesktopCallbackBridge(res, callbackUrl);
    return;
  }
  res.redirect(callbackUrl);
}

function errorPage(title: string, detail: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>BROSH CRM — Error</title>
<link rel="icon" href="https://www.brosh.io/favicon.ico">
<style>body{font-family:system-ui,sans-serif;background:#f7fafc;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.box{background:#fff;border-radius:12px;padding:40px;max-width:480px;
box-shadow:0 4px 20px rgba(0,0,0,.1);text-align:center}
h1{color:#c53030;margin-bottom:12px}p{color:#4a5568;margin-bottom:8px}
.code{background:#fed7d7;color:#c53030;padding:10px;border-radius:6px;
font-family:monospace;font-size:13px;word-break:break-all;margin-top:16px}
a{color:#667eea;font-weight:600}</style></head>
<body><div class="box">
  <h1>❌ ${escapeHtml(title)}</h1>
  <p>Something went wrong during authentication.</p>
  <div class="code">${escapeHtml(detail)}</div>
  <p style="margin-top:24px"><a href="/">← Back to Home</a></p>
</div></body></html>`;
}

function handleBroshError(err: unknown, res: Response): void {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status || 500;
    const body = err.response?.data || err.message;
    res.status(status).json({ error: body });
  } else {
    res.status(500).json({ error: String(err) });
  }
}

function buildOpenApiSpec( session: UserSession): Record<string, unknown> {

  var  tableEnum ;
   if (session?.availableTables && session.availableTables.length > 0) {
    tableEnum = [...session.availableTables];
  }else{
    tableEnum = [...VALID_TABLES];
  }
  return {
    openapi: "3.1.1",
    info: {
      title: "BROSH CRM API",
      description:
        "Full CRUD access to BROSH CRM. Manage contacts, accounts, opportunities, projects, and more. " +
        "All write endpoints accept arrays of records. All endpoints require Bearer token authentication.",
      version: "1.0.1",
    },
    servers: [{ url: SERVER_URL }],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        RecordObject: {
          type: "object",
          description:
            "A CRM record with arbitrary fields. All records include id, name, created_by, created_date, last_modified_by, last_modified_date.",
          additionalProperties: true,
        },
        WriteResult: {
          type: "object",
          properties: {
            id: { type: "integer" },
            affectedRows: { type: "integer" },
            insertId: { type: "integer" },
            changedRows: { type: "integer" },
          },
        },
        TableName: {
          type: "string",
          pattern: "^[a-zA-Z][a-zA-Z0-9_]*$",
          description:
            "English CRM table name. Use /api/table/available to discover available table names and fields.",
        },
        FindBody: {
          type: "object",
          properties: {
            fields: {
              type: "array",
              items: { type: "string" },
              description: "Columns to return. Omit for all fields.",
            },
            filter: {
              type: "object",
              description: "Optional filter criteria.",
              properties: {
                id: {
                  type: ["string", "number"],
                  description: "Exact match by record ID.",
                },
                search: {
                  type: "string",
                  description:
                    "Full-text search on the name field. Supports % wildcards.",
                },
                where: {
                  type: "object",
                  description:
                    "Field conditions. Use simple values for equality or operator objects " +
                    '{"operator":">=","value":100} for comparisons. Operators: =, >, <, >=, <=, !=, LIKE, IN, NOT IN.',
                  additionalProperties: true,
                },
              },
            },
            sort: {
              type: "array",
              items: {
                type: "object",
                required: ["field", "direction"],
                properties: {
                  field: { type: "string" },
                  direction: { type: "string", enum: ["ASC", "DESC"] },
                },
              },
            },
            page_size: {
              type: "integer",
              description: "Records per page (default 50).",
            },
            page: { type: "integer", description: "Page number (default 1)." },
            limit: {
              type: "integer",
              minimum: 1,
              maximum: 10000,
              description:
                "Override pagination: return at most this many records.",
            },
          },
        },
      },
    },
    security: [{ BearerAuth: [] }],
    paths: {
      "/api/me": {
        get: {
          operationId: "getMe",
          summary: "Get current authenticated user info",
          description:
            "Returns the BROSH CRM user profile linked to the current session.",
          responses: {
            "200": {
              description: "User info",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      id: { type: "string" },
                      userid: { type: "integer" },
                      name: { type: "string" },
                    },
                  },
                },
              },
            },
          },
        },
      },
      ...buildTablePaths(tableEnum),
    },
  };
}

function buildFixedTablePaths(): Record<string, unknown> {
  const tableProperty = { $ref: "#/components/schemas/TableName" };
  const recordArraySchema = {
    type: "array",
    minItems: 1,
    items: { $ref: "#/components/schemas/RecordObject" },
  };

  return {
    "/api/table/available": {
      get: {
        operationId: "table_available",
        summary: "List available tables and fields",
        description:
          "Returns the current authenticated user's available CRM table names and field metadata.",
        responses: {
          "200": {
            description: "Available table names and fields",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["tableNames", "tables"],
                  properties: {
                    tableNames: {
                      type: "array",
                      items: { type: "string" },
                    },
                    tables: {
                      type: "array",
                      items: {
                        type: "object",
                        required: ["name", "fields"],
                        properties: {
                          name: { type: "string" },
                          fields: {
                            type: "array",
                            items: {
                              type: "object",
                              additionalProperties: true,
                            },
                          },
                        },
                        additionalProperties: true,
                      },
                    },
                    total_count: { type: "integer" },
                  },
                  additionalProperties: true,
                },
              },
            },
          },
        },
      },
    },
    "/api/table/find": {
      post: {
        operationId: "table_find",
        summary: "Find records in a table",
        description:
          "Fixed-path find operation. Provide an English table name plus optional fields, filter, sort, and pagination.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                allOf: [
                  { $ref: "#/components/schemas/FindBody" },
                  {
                    type: "object",
                    required: ["table"],
                    properties: {
                      table: tableProperty,
                    },
                  },
                ],
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Array of records",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/RecordObject" },
                },
              },
            },
          },
        },
      },
    },
    "/api/table/get": {
      post: {
        operationId: "table_get",
        summary: "Get records from a table",
        description:
          "Fixed-path get operation. Provide an English table name and an array of record IDs.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["table", "ids"],
                properties: {
                  table: tableProperty,
                  ids: {
                    type: "array",
                    minItems: 1,
                    items: { type: "integer" },
                  },
                  limit: { type: "integer", minimum: 1, maximum: 10000 },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Array of records",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/RecordObject" },
                },
              },
            },
          },
        },
      },
    },
    "/api/table/create": {
      post: {
        operationId: "table_create",
        summary: "Create records in a table",
        description:
          "Fixed-path create operation. Provide an English table name and records JSON array.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["table", "records"],
                properties: {
                  table: tableProperty,
                  records: recordArraySchema,
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    },
    "/api/table/update": {
      post: {
        operationId: "table_update",
        summary: "Update records in a table",
        description:
          "Fixed-path update operation. Provide an English table name and records JSON array; each record must include id.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["table", "records"],
                properties: {
                  table: tableProperty,
                  records: {
                    type: "array",
                    minItems: 1,
                    items: {
                      allOf: [
                        { $ref: "#/components/schemas/RecordObject" },
                        {
                          type: "object",
                          required: ["id"],
                          properties: { id: { type: "integer" } },
                        },
                      ],
                    },
                  },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    },
    "/api/table/delete": {
      post: {
        operationId: "table_delete",
        summary: "Delete records from a table",
        description:
          "Fixed-path delete operation. Provide an English table name and an array of record IDs.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["table", "ids"],
                properties: {
                  table: tableProperty,
                  ids: {
                    type: "array",
                    minItems: 1,
                    items: { type: "integer" },
                  },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    },
  };
}

function buildTablePaths(tables: string[]): Record<string, unknown> {
  const paths: Record<string, unknown> = {};

  for (const table of tables) {
    paths[`/api/${table}/find`] = {
      post: {
        operationId: `find_${table}`,
        summary: `Search ${table}`,
        description: `Find ${table} records with optional filtering, sorting, and pagination.`,
        requestBody: {
          required: false,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/FindBody" },
            },
          },
        },
        responses: {
          "200": {
            description: `Array of ${table} records`,
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/RecordObject" },
                },
              },
            },
          },
        },
      },
    };

    paths[`/api/${table}/get`] = {
      post: {
        operationId: `get_${table}`,
        summary: `Get ${table} by IDs`,
        description: `Retrieve specific ${table} records by their numeric IDs.`,
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["ids"],
                properties: {
                  ids: {
                    type: "array",
                    items: { type: "integer" },
                    description: "Array of record IDs to fetch.",
                  },
                  limit: {
                    type: "integer",
                    minimum: 1,
                    maximum: 10000,
                    description: "Max records to return.",
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: `Array of ${table} records`,
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/RecordObject" },
                },
              },
            },
          },
        },
      },
    };

    paths[`/api/${table}/create`] = {
      post: {
        operationId: `create_${table}`,
        summary: `Create ${table} record(s)`,
        description: `Create one or more ${table} records. Send an array of objects.`,
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: { $ref: "#/components/schemas/RecordObject" },
                description: "Array of records to create.",
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    };

    paths[`/api/${table}/update`] = {
      post: {
        operationId: `update_${table}`,
        summary: `Update ${table} record(s)`,
        description: `Update one or more ${table} records. Each record must include an "id" field.`,
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: {
                  allOf: [
                    { $ref: "#/components/schemas/RecordObject" },
                    {
                      required: ["id"],
                      properties: { id: { type: "integer" } },
                    },
                  ],
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    };

    paths[`/api/${table}/delete`] = {
      post: {
        operationId: `delete_${table}`,
        summary: `Delete ${table} record(s)`,
        description: `Delete ${table} records by ID. Deleted records are moved to the recycle bin for 30 days.`,
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["ids"],
                properties: {
                  ids: {
                    type: "array",
                    items: { type: "integer" },
                    description: "Array of IDs to delete.",
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Write result",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WriteResult" },
              },
            },
          },
        },
      },
    };
  }

  return paths;
}

// ─── Global Error Handler ──────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[unhandled error]", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ─── Start ─────────────────────────────────────────────────────────────────────

initBroshCredentials();

app.listen(PORT, HOST, () => {
  console.log(`\n🚀 BROSH CRM API Server`);
  console.log(`   URL:        ${SERVER_URL}`);
  console.log(`   Port:       ${PORT}`);
  console.log(`   Login:      ${SERVER_URL}${LOGIN_PATH}`);
  console.log(`   OpenAPI:    ${SERVER_URL}${OPENAPI_PATH}`);
  console.log(`   Health:     ${SERVER_URL}${HEALTH_PATH}`);
  console.log(
    `   Sessions:   ${sessions.size} active (persisted to ${SESSIONS_FILE})`,
  );
  console.log(`\n   BROSH Client ID: ${BROSH_CLIENT_ID}\n`);
});

// ─── Graceful Shutdown ─────────────────────────────────────────────────────────
// Save sessions before exiting

function gracefulShutdown(signal: string) {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  saveSessions();
  console.log("[Shutdown] Sessions saved. Exiting.");
  process.exit(0);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Save sessions on uncaught errors before crashing
process.on("uncaughtException", (err) => {
  console.error("[FATAL] Uncaught exception:", err);
  saveSessions();
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled rejection:", reason);
  saveSessions();
  process.exit(1);
});

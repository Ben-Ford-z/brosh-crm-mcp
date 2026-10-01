#!/usr/bin/env node

/**
 * BROSH AI CRM MCP Server
 * Provides OAuth2 authentication and full CRUD operations for BROSH CRM
 * Documentation: https://www.brosh.io/page/api-oauth2-documentation
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import axios, { AxiosInstance } from 'axios';
import * as http from 'http';
import * as url from 'url';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

// Supported table names in BROSH CRM
const SUPPORTED_TABLES = [
  'accounts',
  'activity',
  'campaigns',
  'contacts',
  'currency',
  'icon',
  'menu',
  'objects',
  'opportunities',
  'opportunity_products',
  'payments',
  'products',
  'projects',
  'tickets',
  'timesheet',
  'users',
  'views'
] as const;

type TableName = typeof SUPPORTED_TABLES[number];
type SourceType = 'make' | 'zapier' | 'n8n' | 'custom' | 'mcp';

interface TokenData {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  expires_at?: number;
}

// Environment configuration
const BROSH_BASE_URL = process.env.BROSH_BASE_URL || 'https://app.brosh.io';
const BROSH_SOURCE = (process.env.BROSH_SOURCE || 'mcp') as SourceType;
const BROSH_SKIP_STATE_VALIDATION = process.env.BROSH_SKIP_STATE_VALIDATION === 'true';

function getWritableStorageDir(): string {
  const primaryDir = path.join(os.homedir(), 'brosh-crm-mcp')
  const fallbackDir = path.join(os.homedir(), '.brosh-crm-mcp2');

  const checkDir = (dir: string) => {
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK);
      return true;
    } catch {
      return false;
    }
  };

  if (checkDir(primaryDir)) {
    return primaryDir;
  }

  if (checkDir(fallbackDir)) {
    console.error(`⚠️  Current directory is not writable. Using fallback directory: ${fallbackDir}`);
    return fallbackDir;
  }

  console.error(`❌ Unable to write to both current directory and fallback user directory. Using current directory as last resort: ${primaryDir}`);
  return primaryDir;
}

const STORAGE_DIR = getWritableStorageDir();
const TOKEN_FILE = path.join(STORAGE_DIR, '.brosh-tokens.json');
const CLIENT_ID_FILE = path.join(STORAGE_DIR, '.brosh-client-id');
const CLIENT_SECRET_FILE = path.join(STORAGE_DIR, '.brosh-client-secret');
const STATE_FILE = path.join(STORAGE_DIR, '.brosh-oauth-state.json');

// Dynamic port management
let actualPort: number = 3001;
const getRedirectUri = () => process.env.BROSH_REDIRECT_URI || `http://localhost:${actualPort}/oauth/callback`;

// Generate or load client ID (random for each installation like Zapier)
function getOrCreateClientId(): string {
  const envClientId = process.env.BROSH_CLIENT_ID;
  if (envClientId) {
    return envClientId;
  }

  try {
    if (fs.existsSync(CLIENT_ID_FILE)) {
      return fs.readFileSync(CLIENT_ID_FILE, 'utf8').trim();
    }
  } catch (error) {
    console.error('Failed to read client ID file:', error);
  }

  // Generate new client ID in format BROSH-{random_number}
  const randomNum = Math.floor(Math.random() * 1000000000000000);
  const clientId = `BROSH-${randomNum}`;
  try {
    fs.writeFileSync(CLIENT_ID_FILE, clientId, 'utf8');
    console.error(`Generated new client ID and saved to .brosh-client-id: ${clientId}`);
  } catch (error) {
    console.error('Failed to save client ID:', error);
  }
  return clientId;
}

// Generate or load client secret
function getOrCreateClientSecret(): string {
  const envSecret = process.env.BROSH_CLIENT_SECRET;
  if (envSecret) {
    return envSecret;
  }

  try {
    if (fs.existsSync(CLIENT_SECRET_FILE)) {
      return fs.readFileSync(CLIENT_SECRET_FILE, 'utf8').trim();
    }
  } catch (error) {
    console.error('Failed to read client secret file:', error);
  }

  // Generate new client secret
  const secret = 'BROSH-' + crypto.randomBytes(32).toString('hex');
  try {
    fs.writeFileSync(CLIENT_SECRET_FILE, secret, 'utf8');
    console.error('Generated new client secret and saved to .brosh-client-secret');
  } catch (error) {
    console.error('Failed to save client secret:', error);
  }
  return secret;
}

const BROSH_CLIENT_ID = getOrCreateClientId();
const BROSH_CLIENT_SECRET = getOrCreateClientSecret();

// OAuth state management
function generateState(): string {
  return crypto.randomBytes(32).toString('hex');
}

function saveState(state: string): void {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify({ state, timestamp: Date.now() }), 'utf8');
  } catch (error) {
    console.error('Failed to save OAuth state:', error);
  }
}

function validateState(state: string): boolean {
  try {
    if (!fs.existsSync(STATE_FILE)) {
      console.error('State file does not exist');
      return false;
    }
    const data = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    console.error(`Validating state: received="${state.substring(0, 12)}...", expected="${data.state.substring(0, 12)}..."`);
    
    // State expires after 10 minutes
    if (Date.now() - data.timestamp > 600000) {
      console.error('State has expired (>10 minutes old)');
      fs.unlinkSync(STATE_FILE);
      return false;
    }
    const isValid = data.state === state;
    if (isValid) {
      console.error('State validation successful');
      fs.unlinkSync(STATE_FILE);
    } else {
      console.error('State mismatch!');
    }
    return isValid;
  } catch (error) {
    console.error('Failed to validate OAuth state:', error);
    return false;
  }
}

// Token management
let cachedTokens: TokenData | null = null;

function loadTokens(): TokenData | null {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = fs.readFileSync(TOKEN_FILE, 'utf8');
      cachedTokens = JSON.parse(data);
      return cachedTokens;
    }
  } catch (error) {
    console.error('Failed to load tokens:', error);
  }
  return null;
}

function saveTokens(tokens: TokenData): void {
  try {
    // Calculate expiration timestamp if expires_in is provided
    if (tokens.expires_in && !tokens.expires_at) {
      tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
    }
    cachedTokens = tokens;
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2), 'utf8');
  } catch (error) {
    console.error('Failed to save tokens:', error);
  }
}

function getAccessToken(): string | null {
  if (!cachedTokens) {
    cachedTokens = loadTokens();
  }
  return cachedTokens?.access_token || null;
}

async function refreshAccessToken(refreshToken?: string, clientId?: string, clientSecret?: string): Promise<any | null> {
  const refresh = refreshToken || cachedTokens?.refresh_token;
  const client = clientId || BROSH_CLIENT_ID;
  const secret = clientSecret || BROSH_CLIENT_SECRET;
  
  if (!refresh) {
    return null;
  }

  try {
    console.error('🔄 Refreshing access token...');
    const axiosClient = axios.create({ baseURL: BROSH_BASE_URL });
    const response = await axiosClient.post(`/api/oauth2/refresh/${BROSH_SOURCE}`, {
      refresh_token: refresh,
      client_id: client,
      client_secret: secret,
      grant_type: 'refresh_token',
    });

    console.error('✅ Token refresh successful!');
    saveTokens(response.data);
    return response.data;
  } catch (error: any) {
    console.error('❌ Token refresh failed:', error.response?.data || error.message);
    return null;
  }
}

// Create axios instance
function createApiClient(accessToken?: string): AxiosInstance {
  const token = accessToken || getAccessToken();
  return axios.create({
    baseURL: BROSH_BASE_URL,
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
    },
  });
}

async function ensureValidAccessToken(): Promise<void> {
  if (!cachedTokens) {
    cachedTokens = loadTokens();
  }

  if (!cachedTokens?.access_token) {
    throw new Error('No access token available. Please authenticate first using brosh_start_oauth.');
  }

  if (!cachedTokens.expires_at) {
    return;
  }

  const remainingMs = cachedTokens.expires_at - Date.now();
  if (remainingMs > 5 * 60 * 1000) {
    return;
  }

  const refreshed = await refreshAccessToken(cachedTokens.refresh_token, BROSH_CLIENT_ID, BROSH_CLIENT_SECRET);
  if (!refreshed && remainingMs <= 0) {
    throw new Error('Access token expired and auto-refresh failed. Please re-authenticate.');
  }
}

// OAuth2 callback server (runs indefinitely)
function startOAuthCallbackServer(port: number = 3000): Promise<never> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      try {
        const parsedUrl = url.parse(req.url || '', true);
      
        // Serve favicon from app.brosh.io
        if (parsedUrl.pathname === '/favicon.ico') {
          res.writeHead(302, { 'Location': 'https://www.brosh.io/favicon.ico' });
          res.end();
          return;
        }

        // Serve local setup screenshots used in the landing page
        if (parsedUrl.pathname === '/.well-known/cpt_mcp.jpg' || parsedUrl.pathname === '/.well-known/brosh_cload.jpg') {
          try {
            const fileName = parsedUrl.pathname.endsWith('cpt_mcp.jpg') ? 'cpt_mcp.jpg' : 'brosh_cload.jpg';
            const filePath = path.join(process.cwd(), 'www', 'mcp', '.well-known', fileName);
            const imageBuffer = fs.readFileSync(filePath);
            res.writeHead(200, {
              'Content-Type': 'image/jpeg',
              'Cache-Control': 'public, max-age=3600',
            });
            res.end(imageBuffer);
          } catch {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Image not found');
          }
          return;
        }
      
      // Root path - show status/landing page with auto-refresh
      if (parsedUrl.pathname === '/') {
        let isAuthenticated = false;
        let tokenData: any = null;
        let userData: any = null;
        let refreshAttempted = false;
        let refreshSuccess = false;
        
        // Check and refresh authentication status
        try {
          if (fs.existsSync(TOKEN_FILE)) {
            tokenData = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
            
            // Check if token is expired or will expire in next 5 minutes
            const expiresInMs = tokenData.expires_at ? tokenData.expires_at - Date.now() : 0;
            const isExpired = expiresInMs <= 0;
            const willExpireSoon = expiresInMs > 0 && expiresInMs < 300000; // 5 minutes
            
            if (isExpired || willExpireSoon) {
              // Try to refresh token automatically
              if (tokenData.refresh_token) {
                refreshAttempted = true;
                console.error(`🔄 Token ${isExpired ? 'expired' : 'expiring soon'}, attempting auto-refresh...`);
                const newTokens = await refreshAccessToken(tokenData.refresh_token, BROSH_CLIENT_ID, BROSH_CLIENT_SECRET);
                if (newTokens) {
                  tokenData = newTokens;
                  refreshSuccess = true;
                  isAuthenticated = true;
                } else {
                  isAuthenticated = false;
                }
              } else {
                console.error('⚠️  No refresh token available for auto-refresh');
                isAuthenticated = false;
              }
            } else if (tokenData.expires_at && tokenData.expires_at > Date.now()) {
              isAuthenticated = true;
            } else {
              isAuthenticated = false;
            }
            
            if (isAuthenticated) {
              // Try to fetch user info
              try {
                const client = axios.create({
                  baseURL: BROSH_BASE_URL,
                  headers: {
                    'Authorization': `Bearer ${tokenData.access_token}`,
                    'Content-Type': 'application/json'
                  }
                });
                const response = await client.post(`/api/oauth2/me/${BROSH_SOURCE}`, {});
                userData = response.data;
              } catch (error) {
                console.error('Failed to fetch user info:', error);
              }
            }
          } else {
            isAuthenticated = false;
          }
        } catch (error) {
          isAuthenticated = false;
        }

        // Read current state from file (or generate new one if missing)
        let currentState: string;
        try {
          if (fs.existsSync(STATE_FILE)) {
            const stateData = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
            currentState = stateData.state;
          } else {
            currentState = generateState();
            saveState(currentState);
          }
        } catch (error) {
          currentState = generateState();
          saveState(currentState);
        }

        // Build authorization URL with current state
        const authUrl = new URL(`${BROSH_BASE_URL}/en/login`);
        authUrl.searchParams.set('src', BROSH_SOURCE);
        authUrl.searchParams.set('client_id', BROSH_CLIENT_ID);
        authUrl.searchParams.set('state', currentState);
        authUrl.searchParams.set('scope', 'Full');
        authUrl.searchParams.set('redirect_uri', getRedirectUri());
        authUrl.searchParams.set('response_type', 'code');

        // Generate status page HTML
        const timeRemaining = tokenData?.expires_at ? Math.max(0, Math.floor((tokenData.expires_at - Date.now()) / 60000)) : 0;
        const expiryDate = tokenData?.expires_at ? new Date(tokenData.expires_at).toLocaleString() : 'Unknown';
        
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM OAuth2 ${isAuthenticated ? 'Status' : 'Authentication'}</title>
  <meta name="description" content="BROSH CRM MCP authentication page for ChatGPT, Claude, and VS Code. Secure OAuth2 CRM integration with AI workflows, token refresh, and fast setup.">
  <meta name="keywords" content="BROSH CRM MCP, ChatGPT CRM connector, Claude CRM MCP, OAuth2 CRM authentication, AI CRM workflows, MCP token refresh, CRM automation">
  <link rel="icon" type="image/x-icon" href="https://www.brosh.io/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-1: #071426;
      --bg-2: #0f2e46;
      --bg-3: #1a6a7e;
      --ink: #0b213d;
      --muted: #4f6281;
      --line: #d8e4f5;
      --card: #f7fbff;
      --ok-bg: #d8f7e9;
      --ok-tx: #10563d;
      --info-bg: #d9efff;
      --info-tx: #184f7a;
      --warn-bg: #fff2de;
      --warn-tx: #925305;
      --brand-1: #08a2a1;
      --brand-2: #1a5cc8;
      --accent: #ff8a3d;
    }
    body {
      font-family: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
      background:
        radial-gradient(900px 560px at 5% -20%, rgba(255,138,61,.26), transparent 70%),
        radial-gradient(1000px 600px at 95% -30%, rgba(8,162,161,.24), transparent 72%),
        linear-gradient(135deg, var(--bg-1) 0%, var(--bg-2) 45%, var(--bg-3) 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 26px;
      color: var(--ink);
    }
    .container {
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
      border-radius: 24px;
      box-shadow: 0 28px 80px rgba(1, 8, 20, 0.42);
      border: 1px solid rgba(255,255,255,0.6);
      padding: 34px;
      max-width: 980px;
      width: 100%;
      position: relative;
      overflow: hidden;
    }
    .container::before {
      content: '';
      position: absolute;
      width: 440px;
      height: 440px;
      right: -210px;
      top: -230px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(8,162,161,0.2), transparent 70%);
      pointer-events: none;
    }
    .header { text-align: center; margin-bottom: 28px; position: relative; z-index: 1; }
    h1 {
      color: #0b2c4f;
      font-size: clamp(30px, 5vw, 46px);
      font-weight: 800;
      font-family: 'Space Grotesk', 'Manrope', sans-serif;
      margin-bottom: 8px;
      background: linear-gradient(130deg, #104179 0%, #0e7f8f 55%, #ff8a3d 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      letter-spacing: -1px;
    }
    .subtitle { color: #597095; font-size: 16px; font-weight: 500; }
    .content { margin: 24px 0; position: relative; z-index: 1; }
    .steps {
      background: linear-gradient(180deg, #f9fcff 0%, #f1f7ff 100%);
      border-radius: 14px;
      border: 1px solid #dce8f6;
      padding: 22px;
      margin: 24px 0;
    }
    .step {
      display: flex;
      margin-bottom: 16px;
      align-items: flex-start;
    }
    .step:last-child { margin-bottom: 0; }
    .step-number {
      background: linear-gradient(130deg, var(--brand-1), var(--brand-2));
      color: white;
      width: 34px;
      height: 34px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 14px;
      margin-right: 16px;
      flex-shrink: 0;
      box-shadow: 0 6px 18px rgba(26, 92, 200, 0.35);
    }
    .step-content { flex: 1; }
    .step-title {
      color: #1e3a63;
      font-weight: 700;
      font-size: 16px;
      margin-bottom: 4px;
    }
    .step-desc {
      color: #60789e;
      font-size: 14px;
      line-height: 1.5;
    }
    .info-box {
      background: #eef6ff;
      border: 1px solid #d7e7fb;
      border-left: 4px solid var(--brand-2);
      padding: 16px 20px;
      border-radius: 12px;
      margin: 24px 0;
    }
    .info-box p {
      color: #254267;
      font-size: 14px;
      line-height: 1.6;
      margin-bottom: 8px;
    }
    .info-box p:last-child { margin-bottom: 0; }
    .info-box strong { color: #14355d; }
    .button-container { text-align: center; margin-top: 32px; }
    .login-button {
      display: inline-block;
      background: linear-gradient(130deg, var(--brand-1) 0%, var(--brand-2) 65%, #12306f 100%);
      color: white;
      padding: 15px 42px;
      border-radius: 14px;
      font-size: 18px;
      font-weight: 700;
      text-decoration: none;
      box-shadow: 0 12px 26px rgba(16, 65, 121, 0.33);
      transition: transform .2s ease, box-shadow .2s ease, filter .2s ease;
      border: none;
      cursor: pointer;
      letter-spacing: .2px;
    }
    .login-button:hover {
      transform: translateY(-2px) scale(1.01);
      box-shadow: 0 16px 36px rgba(16, 65, 121, 0.4);
      filter: saturate(1.08);
    }
    .login-button:active { transform: translateY(0); }
    .logout-button {
      display: inline-block;
      background: linear-gradient(130deg, #ef4444, #c0392b);
      color: white;
      padding: 12px 32px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      text-decoration: none;
      margin-left: 12px;
      transition: transform .2s ease, box-shadow .2s ease;
    }
    .logout-button:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 20px rgba(192,57,43,.35);
    }
    .footer {
      margin-top: 32px;
      padding-top: 20px;
      border-top: 1px solid #dbe8fa;
      text-align: center;
      color: #60769b;
      font-size: 14px;
      position: relative;
      z-index: 1;
    }
    .status {
      padding: 12px 20px;
      border-radius: 12px;
      margin-bottom: 14px;
      text-align: center;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      border: 1px solid transparent;
    }
    .status.authenticated {
      background: var(--ok-bg);
      color: var(--ok-tx);
      border-color: #bfe8d3;
    }
    .status.ready {
      background: var(--info-bg);
      color: var(--info-tx);
      border-color: #bdddf7;
    }
    .status.warning {
      background: var(--warn-bg);
      color: var(--warn-tx);
      border-color: #ffe0b8;
    }
    .user-info {
      background: linear-gradient(180deg, #f8fcff 0%, #eff7ff 100%);
      border: 1px solid #dce8fa;
      border-radius: 12px;
      padding: 20px;
      margin: 24px 0;
    }
    .user-info-row {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid #e2e8f0;
    }
    .user-info-row:last-child { border-bottom: none; }
    .user-info-label {
      color: #60779d;
      font-size: 14px;
      font-weight: 600;
    }
    .user-info-value {
      color: #1f3b64;
      font-size: 14px;
      font-weight: 700;
    }
    .refresh-hint {
      text-align: center;
      color: #60779d;
      font-size: 13px;
      margin-top: 16px;
    }
    .hero-shell {
      background: linear-gradient(135deg, #071b3b 0%, #164280 55%, #0f9fa8 100%);
      border-radius: 18px;
      padding: 26px;
      color: #e7f1ff;
      border: 1px solid rgba(255,255,255,.15);
      box-shadow: 0 14px 40px rgba(6, 23, 54, 0.28);
      margin-bottom: 20px;
    }
    .hero-shell h2 {
      font-size: clamp(24px, 4vw, 38px);
      line-height: 1.1;
      margin-bottom: 10px;
      color: #ffffff;
      font-family: 'Space Grotesk', 'Manrope', sans-serif;
      letter-spacing: -.6px;
    }
    .hero-shell p {
      color: #c8dafb;
      font-size: 16px;
      line-height: 1.7;
    }
    .hero-install {
      margin-top: 14px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 13px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      background: rgba(255,255,255,0.14);
      color: #e8f3ff;
    }
    .chip-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      color: #eaf4ff;
      border-radius: 999px;
      padding: 8px 12px;
      font-size: 13px;
      text-decoration: none;
      transition: transform .2s ease, background .2s ease;
    }
    .chip-link:hover {
      transform: translateY(-1px);
      background: rgba(255,255,255,0.16);
    }
    .details-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin: 18px 0;
    }
    .detail-card {
      background: linear-gradient(180deg, #fafdff 0%, #f1f7ff 100%);
      border: 1px solid #d9e6f8;
      border-radius: 14px;
      padding: 16px;
      transition: transform .2s ease, box-shadow .2s ease;
    }
    .detail-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 12px 24px rgba(26, 65, 113, 0.12);
    }
    .detail-card h3 {
      font-size: 20px;
      color: #123a66;
      margin-bottom: 8px;
      letter-spacing: -.3px;
    }
    .detail-card p {
      font-size: 14px;
      color: #4a5568;
      line-height: 1.65;
      margin-bottom: 8px;
    }
    .detail-list {
      list-style: none;
      display: grid;
      gap: 8px;
      margin-top: 8px;
    }
    .detail-list li {
      font-size: 14px;
      line-height: 1.5;
      color: #2d3748;
    }
    .mini-steps {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 12px;
    }
    .mini-step {
      background: #ffffff;
      border: 1px solid #d8e5f6;
      border-radius: 12px;
      padding: 12px;
      transition: transform .2s ease, box-shadow .2s ease;
    }
    .mini-step:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(22,66,128,.14);
    }
    .mini-step .num {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(130deg, var(--brand-1), var(--brand-2));
      color: #fff;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 6px;
    }
    .mini-step h4 {
      font-size: 14px;
      color: #1f3b64;
      margin-bottom: 4px;
    }
    .mini-step p {
      font-size: 12px;
      color: #5a6d8b;
      line-height: 1.45;
    }
    .mcp-link-box {
      margin-top: 12px;
      background: rgba(6, 22, 53, 0.74);
      color: #dce8ff;
      border-radius: 12px;
      padding: 10px 12px;
      border: 1px solid rgba(255,255,255,.16);
      font-family: 'Space Grotesk', 'Courier New', monospace;
      font-size: 13px;
      word-break: break-all;
    }
    .section-title {
      font-size: 24px;
      letter-spacing: -.6px;
      color: #123a66;
      margin-bottom: 8px;
    }
    .section-sub {
      font-size: 14px;
      color: #56709a;
      line-height: 1.6;
      margin-bottom: 14px;
    }
    .features-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin: 14px 0;
    }
    .feature-card {
      background: #fff;
      border: 1px solid #d8e5f6;
      border-radius: 12px;
      padding: 14px;
      transition: transform .2s ease, box-shadow .2s ease;
    }
    .feature-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 22px rgba(22,66,128,.12);
    }
    .feature-icon {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      margin-bottom: 8px;
    }
    .feature-card h3 {
      font-size: 14px;
      color: #103463;
      margin-bottom: 6px;
    }
    .feature-card p {
      font-size: 13px;
      color: #5b7196;
      line-height: 1.5;
    }
    .ic1{background:#efe9ff}.ic2{background:#e6f5ff}.ic3{background:#e6fff6}.ic4{background:#fff3e6}.ic5{background:#ebf0ff}.ic6{background:#ffeaf5}
    .cases-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin: 14px 0;
    }
    .case-card {
      background: #fff;
      border: 1px solid #d8e5f6;
      border-radius: 12px;
      padding: 14px;
    }
    .case-card h3 {
      font-size: 14px;
      color: #103463;
      margin-bottom: 7px;
    }
    .case-card ul {
      list-style: none;
      display: grid;
      gap: 6px;
    }
    .case-card li {
      font-size: 12px;
      color: #5a7095;
      line-height: 1.45;
    }
    .case-card li:before { content: '→ '; color: #0b7bc8; font-weight: 700; }
    .persona-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin: 14px 0;
    }
    .persona-card {
      background: #fff;
      border: 1px solid #d8e5f6;
      border-radius: 12px;
      padding: 14px;
    }
    .persona-card h3 {
      font-size: 14px;
      color: #103463;
      margin-bottom: 7px;
    }
    .persona-card ul {
      list-style: none;
      display: grid;
      gap: 6px;
    }
    .persona-card li {
      font-size: 12px;
      color: #5a7095;
      line-height: 1.45;
    }
    .persona-card li:before { content: '✓ '; color: #0e9b63; font-weight: 700; }
    .shot-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 14px;
    }
    .shot-card {
      background: #fff;
      border: 1px solid #d8e5f6;
      border-radius: 12px;
      padding: 12px;
      box-shadow: 0 8px 20px rgba(17, 50, 97, 0.08);
    }
    .shot-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }
    .shot-head h3 {
      font-size: 14px;
      color: #103463;
    }
    .shot-tag {
      font-size: 11px;
      font-weight: 700;
      color: #0b6fc7;
      background: #eaf3ff;
      border: 1px solid #d4e4ff;
      padding: 4px 8px;
      border-radius: 999px;
    }
    .shot-wrap {
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid #d7e4fa;
      background: #f8fbff;
    }
    .shot-wrap img {
      display: block;
      width: 100%;
      height: auto;
      cursor: zoom-in;
    }
    .shot-steps {
      list-style: none;
      display: grid;
      gap: 6px;
      margin-top: 10px;
    }
    .shot-steps li {
      font-size: 12px;
      color: #566f94;
      line-height: 1.45;
    }
    .shot-steps li:before { content: '• '; color: #0b7bc8; font-weight: 700; }
    .lightbox {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(7, 18, 37, 0.86);
      z-index: 9999;
      padding: 20px;
    }
    .lightbox.open { display: flex; }
    .lightbox img {
      max-width: min(1200px, 94vw);
      max-height: 88vh;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.28);
      box-shadow: 0 28px 80px rgba(0,0,0,.45);
      cursor: zoom-out;
    }
    .lightbox-close {
      position: absolute;
      top: 14px;
      right: 18px;
      width: 38px;
      height: 38px;
      border: 1px solid rgba(255,255,255,.35);
      border-radius: 999px;
      background: rgba(8, 20, 45, .8);
      color: #fff;
      font-size: 22px;
      line-height: 1;
      cursor: pointer;
    }
    .lightbox-hint {
      position: absolute;
      left: 50%;
      transform: translateX(-50%);
      bottom: 14px;
      color: #dbe7ff;
      font-size: 12px;
      background: rgba(10,26,56,.7);
      border: 1px solid rgba(255,255,255,.2);
      border-radius: 999px;
      padding: 6px 10px;
    }
    @media (max-width: 900px) {
      .container { padding: 24px; }
      .details-grid { grid-template-columns: 1fr; }
      .mini-steps { grid-template-columns: 1fr; }
      .features-grid, .cases-grid, .persona-grid { grid-template-columns: 1fr 1fr; }
      .shot-grid { grid-template-columns: 1fr; }
      .button-container .logout-button { margin-left: 0; margin-top: 10px; display: inline-block; }
    }
    @media (max-width: 620px) {
      body { padding: 14px; }
      .container { padding: 18px; border-radius: 18px; }
      .hero-shell { padding: 18px; }
      .hero-shell p { font-size: 14px; }
      .chip-link { width: 100%; justify-content: center; }
      .status { font-size: 13px; }
      .step-title { font-size: 15px; }
      .step-desc { font-size: 13px; }
      .features-grid, .cases-grid, .persona-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>BROSH MCP ${isAuthenticated ? 'Status' : 'Authentication'}</h1>
      <p class="subtitle">Model Context Protocol Integration</p>
    </div>

    <div class="status ${isAuthenticated ? 'authenticated' : 'ready'}">
      <span>${isAuthenticated ? '✅' : '🔵'}</span>
      <span>${isAuthenticated ? 'Authenticated & Connected' : 'OAuth Server Ready'}</span>
    </div>

    ${refreshAttempted ? `
    <div class="status ${refreshSuccess ? 'authenticated' : 'warning'}" style="margin-bottom: 24px;">
      <span>${refreshSuccess ? '🔄' : '⚠️'}</span>
      <span>${refreshSuccess ? 'Token auto-refreshed successfully!' : 'Token refresh failed - please re-authenticate'}</span>
    </div>
    ` : ''}

    <div class="content">
      ${isAuthenticated ? `
        <p style="color: #2d3748; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
          You are currently authenticated and connected to BROSH CRM.
        </p>

        ${userData ? `
        <div class="user-info">
          <div class="user-info-row">
            <span class="user-info-label">👤 User</span>
            <span class="user-info-value">${userData.name || 'Unknown'}</span>
          </div>
          <div class="user-info-row">
            <span class="user-info-label">⏱️ Expires In</span>
            <span class="user-info-value">${timeRemaining} minutes</span>
          </div>
          <div class="user-info-row">
            <span class="user-info-label">📅 Expires At</span>
            <span class="user-info-value">${expiryDate}</span>
          </div>
          <div class="user-info-row">
            <span class="user-info-label">🔄 Auto Refresh</span>
            <span class="user-info-value" style="color: #22543d; font-weight: 600;">✅ Enabled</span>
          </div>
        </div>
        ` : `
        <div class="info-box">
          <p><strong>⚠️ Token Valid</strong></p>
          <p>Your authentication token is valid but user information could not be retrieved.</p>
          <p><strong>Expires In:</strong> ${timeRemaining} minutes</p>
          <p><strong>Auto Refresh:</strong> ✅ Enabled</p>
        </div>
        `}

        ${timeRemaining < 10 ? `
        <div class="status warning" style="margin-top: 24px;">
          <span>⚠️</span>
          <span>Token expiring soon! Consider re-authenticating.</span>
        </div>
        ` : ''}

        <div class="info-box">
          <p><strong>💡 What You Can Do</strong></p>
          <p>• Use the BROSH CRM MCP tools with Claude Desktop, Cline, or any MCP-compatible AI application</p>
          <p>• Token will auto-refresh when it expires (if refresh token available)</p>
          <p>• Refresh this page to manually check and update status</p>
          <p>• Re-authenticate manually if auto-refresh fails</p>
        </div>

        <div class="button-container">
          <a href="${authUrl}" class="login-button">🔄 Re-authenticate</a>
          <a href="/logout" class="logout-button">🚪 Logout</a>
        </div>
        <div class="refresh-hint">This page auto-updates status on each visit</div>
      ` : `
        <div class="hero-shell">
          <h2>BROSH CRM MCP Gateway</h2>
          <p>Connect your AI assistant to BROSH CRM with one MCP link and OAuth sign-in. Built for ChatGPT, Claude, Cline, VS Code, and other MCP clients with secure OAuth2 CRM automation.</p>
          <div class="hero-install">
            <span class="pill">Simple install</span>
            <a class="chip-link" href="https://mcp.brosh.io" target="_blank" rel="noopener">MCP Link: https://mcp.brosh.io</a>
            <a class="chip-link" href="https://app.brosh.io" target="_blank" rel="noopener">Open CRM</a>
          </div>
          <div class="mcp-link-box">Use this in your client: https://mcp.brosh.io</div>
        </div>

        <div class="details-grid">
          <div class="detail-card">
            <h3>Use Cases First: Real Team Workflows</h3>
            <ul class="detail-list">
              <li>📈 Identify high-intent leads with no recent activity and trigger follow-up actions. Sample: "Find hot leads with score over 80 and no activity in 5 days, then draft next-best outreach for each owner."</li>
              <li>🎯 Keep pipeline hygiene clean by detecting stale stages, missing close dates, and inconsistent deal fields. Sample: "Show opportunities stuck in the same stage for 21+ days and propose updates to stage, value, and close date."</li>
              <li>🧩 Use MCP to revise/add CRM field settings before import. Sample: "Learn CSV columns, add missing fields in BROSH CRM, then import contacts safely."</li>
              <li>✉️ Run direct outreach through MCP email tools. Sample: "Use CRM templates for newsletter sends, or generate tailored product emails per contact and send one-by-one bespoked messages."</li>
              <li>🧾 Build executive KPI snapshots for deals, support load, retention signals, and payments. Sample: "Create a weekly executive summary with pipeline coverage, win-rate trend, overdue invoices, and churn-risk movement."</li>
              <li>🛟 Surface SLA-risk tickets early and summarize recurring issue clusters by account segment. Sample: "List tickets likely to breach SLA in the next 12 hours, grouped by priority, ARR, and root-cause theme."</li>
              <li>🔁 Run repeatable CRM automation playbooks with consistent output formatting for teams. Sample: "Run the Monday revenue ops checklist: stale deals, missing decision-makers, at-risk renewals, and suggested owner actions."</li>
            </ul>
          </div>
          <div class="detail-card">
            <h3>Use Cases By Function</h3>
            <ul class="detail-list">
              <li>🧠 AI Data Enrichment: detect missing CRM fields, research values, and update records. Sample: "Tell me which contacts are missing role, industry, or company size, enrich them, and update each record."</li>
              <li>🎯 Customer Prospecting: discover new target customers from external signals and add them to CRM. Sample: "Scan stock exchange updates and suggest companies that may need our service, collect their details, and create CRM records."</li>
              <li>💼 Sales: score leads, prioritize deals, and forecast revenue by stage. Sample: "Show deals above 50k with no update in 10 days and suggest next action by owner."</li>
              <li>🧱 CSV Import + Field Revision: learn the CSV schema, detect missing fields, then revise/add fields before import. Sample: "Analyze this CSV, create missing contact fields, then import all valid rows into CRM."</li>
              <li>📰 Template Newsletter Send: send newsletters from CRM templates with merge fields via MCP. Sample: "Use newsletter template 42, include dynamic fields, and send to active subscribers."</li>
              <li>✉️ Custom AI Tailored Email: research each customer and send one-by-one personalized product emails. Sample: "Research each account, draft a tailored product message, and send a unique email per contact."</li>
              <li>👥 Customer Success: update account notes and prevent churn with early warnings. Sample: "Find accounts with low activity + unresolved tickets and draft rescue plans."</li>
              <li>📣 Marketing Ops: segment audiences and validate campaign attribution quality. Sample: "Segment fintech leads from EMEA with high intent and export top campaign performers."</li>
              <li>🎫 Support: prioritize tickets by SLA risk and account value. Sample: "List tickets likely to breach SLA in 8 hours sorted by ARR impact."</li>
              <li>📈 Leadership: generate board-ready performance snapshots in seconds. Sample: "Build weekly KPI summary for pipeline, win rate, churn risk, and collections."</li>
            </ul>
          </div>
        </div>

        <div class="info-box">
          <h2 class="section-title">Features</h2>
          <p class="section-sub">Everything you need to run BROSH CRM through MCP with security, speed, and automation.</p>
          <div class="features-grid">
            <div class="feature-card"><span class="feature-icon ic1">🔐</span><h3>Enterprise OAuth2</h3><p>Secure auth, scoped access, and robust session handling.</p></div>
            <div class="feature-card"><span class="feature-icon ic2">📊</span><h3>Full CRUD</h3><p>Create, read, update, and delete records across key CRM tables.</p></div>
            <div class="feature-card"><span class="feature-icon ic3">🤖</span><h3>AI Native</h3><p>Ask in natural language and execute multi-step CRM workflows.</p></div>
            <div class="feature-card"><span class="feature-icon ic4">⚡</span><h3>Zero Config</h3><p>Add the MCP URL, sign in, and start using it in minutes.</p></div>
            <div class="feature-card"><span class="feature-icon ic5">🔄</span><h3>Token Auto Refresh</h3><p>Expired tokens are refreshed automatically when possible.</p></div>
            <div class="feature-card"><span class="feature-icon ic6">📡</span><h3>OpenAI/Claude Ready</h3><p>Works with modern MCP clients and OAuth discovery flows.</p></div>
          </div>
        </div>

        <div class="info-box">
          <h2 class="section-title">Use Cases</h2>
          <p class="section-sub">Common ways teams use BROSH MCP in daily operations.</p>
          <div class="cases-grid">
            <div class="case-card"><h3>AI Data Enrichment</h3><ul><li>Detect records with missing firmographic/contact fields</li><li>Ask AI to search and infer relevant values</li><li>Sample prompt: "Identify missing CRM fields, enrich with researched data, then update each relevant record."</li></ul></div>
            <div class="case-card"><h3>Customer Prospecting</h3><ul><li>Find new prospects from public market and business signals</li><li>Collect company and contact details for outreach</li><li>Sample prompt: "Scan the stock exchange and suggest customers that may need my service/product, get their details, and enter them into the CRM."</li></ul></div>
            <div class="case-card"><h3>Sales Pipeline</h3><ul><li>Score leads and prioritize outreach</li><li>Track stage progression</li><li>Sample prompt: "Show high-intent leads with no follow-up this week and create tasks for reps."</li></ul></div>
            <div class="case-card"><h3>CSV Import With Field Revision</h3><ul><li>Learn CSV headers and compare against CRM schema</li><li>Create or modify missing fields through MCP before import</li><li>Sample prompt: "Review this CSV, add missing contact fields in BROSH CRM, and import the cleaned dataset."</li></ul></div>
            <div class="case-card"><h3>CRM Template Newsletter</h3><ul><li>Use existing CRM templates with dynamic fields</li><li>Send newsletter campaigns directly via MCP send-email tools</li><li>Sample prompt: "Send the monthly newsletter template to all customers with active subscriptions and include account-level merge fields."</li></ul></div>
            <div class="case-card"><h3>Custom AI Tailored Email</h3><ul><li>Research each customer/account before outreach</li><li>Generate and send one-by-one personalized product emails</li><li>Sample prompt: "Do market research for each lead, write a custom product pitch, and send each customer a tailored email via MCP."</li></ul></div>
            <div class="case-card"><h3>Customer Success</h3><ul><li>Review account history instantly</li><li>Update contact and account info</li><li>Sample prompt: "List at-risk accounts and suggest renewal plays based on recent ticket and activity trends."</li></ul></div>
            <div class="case-card"><h3>Support Operations</h3><ul><li>Create and update tickets</li><li>Monitor SLA response times</li><li>Sample prompt: "Find open tickets older than 48 hours grouped by priority and owner."</li></ul></div>
          </div>
        </div>

        <div class="info-box">
          <h2 class="section-title">Who It’s For</h2>
          <p class="section-sub">Built for every role that needs fast CRM action from AI.</p>
          <div class="persona-grid">
            <div class="persona-card"><h3>Sales Teams</h3><ul><li>Update deals from chat</li><li>Access customer context live</li><li>Generate quick reports</li></ul></div>
            <div class="persona-card"><h3>Customer Success</h3><ul><li>Track health and support</li><li>Manage accounts faster</li><li>Reduce manual data entry</li></ul></div>
            <div class="persona-card"><h3>Executives & Ops</h3><ul><li>Get live KPI snapshots</li><li>Ask plain-English questions</li><li>Accelerate decisions</li></ul></div>
          </div>
        </div>

        <div class="info-box">
          <p><strong>Simple Installation</strong></p>
          <div class="mini-steps">
            <div class="mini-step">
              <span class="num">1</span>
              <h4>Add MCP URL</h4>
              <p>Set your MCP server URL to <strong>https://mcp.brosh.io</strong>.</p>
            </div>
            <div class="mini-step">
              <span class="num">2</span>
              <h4>Choose OAuth</h4>
              <p>Authenticate with your BROSH account when prompted.</p>
            </div>
            <div class="mini-step">
              <span class="num">3</span>
              <h4>Start Working</h4>
              <p>Query, create, and update CRM records with natural language.</p>
            </div>
          </div>
        </div>

        <div class="info-box">
          <p><strong>ChatGPT + Claude Setup (Quick)</strong></p>
          <p>1. Create a new connector/app and give it a name (example: <strong>BROSH CRM</strong>).</p>
          <p>2. Paste this MCP URL: <code>https://mcp.brosh.io</code>.</p>
          <p>3. Click <strong>Connect</strong> (or Add), then finish OAuth login.</p>
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
        </div>

        <div class="info-box">
          <p><strong>Pro Prompt Examples</strong></p>
          <p>"Show enterprise opportunities in Proposal stage over 75000 with no activity in 7 days, grouped by owner."</p>
          <p>"Create a follow-up task for each lead scored above 85 this week and assign by territory."</p>
          <p>"Summarize support tickets older than 48 hours by severity, account ARR, and next best action."</p>
        </div>

        <p style="color: #2d3748; font-size: 16px; line-height: 1.6; margin-bottom: 24px; margin-top: 22px;">
          This local server is ready to complete authentication and connect your AI client to BROSH CRM data.
        </p>

        <div class="steps">
          <div class="step">
            <div class="step-number">1</div>
            <div class="step-content">
              <div class="step-title">Click Login Button</div>
              <div class="step-desc">You'll be redirected to BROSH CRM's secure login page</div>
            </div>
          </div>
          <div class="step">
            <div class="step-number">2</div>
            <div class="step-content">
              <div class="step-title">Sign In to BROSH</div>
              <div class="step-desc">Enter your BROSH CRM credentials to authorize access</div>
            </div>
          </div>
          <div class="step">
            <div class="step-number">3</div>
            <div class="step-content">
              <div class="step-title">Automatic Redirect</div>
              <div class="step-desc">You'll be brought back here and see a success message</div>
            </div>
          </div>
        </div>

        <div class="info-box">
          <p><strong>🔒 Secure OAuth 2.0 Flow</strong></p>
          <p>Your credentials are never shared with this application. Authentication happens directly through BROSH's secure servers.</p>
          <p><strong>Scope:</strong> Full access to your BROSH CRM data (contacts, opportunities, accounts, etc.)</p>
        </div>

        <div class="info-box">
          <h2 class="section-title">Benefits of Using MCP</h2>
          <p class="section-sub">Model Context Protocol makes BROSH CRM truly AI-ready for secure, scalable business workflows.</p>
          <ul class="detail-list">
            <li>🔐 Enterprise-grade OAuth2 authentication with automatic token refresh support</li>
            <li>⚡ Fast setup using one MCP URL across ChatGPT, Claude, and VS Code</li>
            <li>📊 Full CRUD access to BROSH CRM data for sales, support, and operations</li>
            <li>🧠 Natural-language automation that reduces manual CRM work</li>
            <li>🚀 Faster decisions through live CRM insights directly in AI conversations</li>
          </ul>
        </div>

        <div class="button-container">
          ${authUrl ? `<a href="${authUrl}" class="login-button">🚀 Login to BROSH CRM</a>` : '<p style="color: #e53e3e;">⚠️ OAuth URL not configured</p>'}
        </div>
      `}
    </div>

    <div class="footer">
      <p><strong>BROSH AI CRM</strong> • Powered by Model Context Protocol</p>
      <p style="margin-top: 8px; font-size: 12px;">Server: http://localhost:${actualPort}/ • Callback: /oauth/callback</p>
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
        }
      });
    })();
  </script>
</body>
</html>`);
        return;
      }
      
      // Logout endpoint
      if (parsedUrl.pathname === '/logout') {
        try {
          if (fs.existsSync(TOKEN_FILE)) {
            fs.unlinkSync(TOKEN_FILE);
          }
          cachedTokens = null;
          console.error('✅ Logged out successfully');
          
          res.writeHead(302, { 'Location': '/' });
          res.end();
        } catch (error) {
          console.error('Logout error:', error);
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Logout failed');
        }
        return;
      }
      
      if (parsedUrl.pathname === '/oauth/callback') {
        const code = parsedUrl.query.code as string;
        const state = parsedUrl.query.state as string;
        const src = parsedUrl.query.src as string;
        const error = parsedUrl.query.error as string;

        console.error(`OAuth callback received: src=${src}, code=${code ? 'present' : 'missing'}, state=${state ? 'present' : 'missing'}`);

        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html; charset=UTF-8' });
          res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM - Authentication Failed</title>
  <link rel="icon" type="image/x-icon" href="https://www.brosh.io/favicon.ico">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 48px;
      max-width: 500px;
      width: 100%;
      text-align: center;
    }
    .icon {
      font-size: 72px;
      margin-bottom: 24px;
      animation: shake 0.5s ease-in-out;
    }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      25% { transform: translateX(-10px); }
      75% { transform: translateX(10px); }
    }
    h1 {
      color: #1a202c;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 16px;
    }
    p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 12px;
    }
    .error-code {
      background: #fed7d7;
      color: #c53030;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: 'Courier New', monospace;
      font-size: 14px;
      margin-top: 24px;
    }
    .footer {
      margin-top: 32px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
      color: #718096;
      font-size: 14px;
    }
    .brosh-logo {
      color: #667eea;
      font-weight: 700;
      font-size: 18px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">❌</div>
    <h1>Authentication Failed</h1>
    <p>We couldn't complete the authentication process.</p>
    <div class="error-code">Error: ${error}</div>
    <div class="footer">
      <div class="brosh-logo">BROSH AI CRM</div>
      <p>Please close this window and try again.</p>
    </div>
  </div>
</body>
</html>`);
          console.error('❌ OAuth error, but server continues running');
          return;
        }

        // Validate state parameter for CSRF protection (unless explicitly skipped)
        if (!BROSH_SKIP_STATE_VALIDATION) {
          if (!state || !validateState(state)) {
            res.writeHead(400, { 'Content-Type': 'text/html; charset=UTF-8' });
            res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM - Security Validation Failed</title>
  <link rel="icon" type="image/x-icon" href="https://www.brosh.io/favicon.ico">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 48px;
      max-width: 500px;
      width: 100%;
      text-align: center;
    }
    .icon {
      font-size: 72px;
      margin-bottom: 24px;
    }
    h1 {
      color: #1a202c;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 16px;
    }
    p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 12px;
    }
    .footer {
      margin-top: 32px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
      color: #718096;
      font-size: 14px;
    }
    .brosh-logo {
      color: #667eea;
      font-weight: 700;
      font-size: 18px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🔒</div>
    <h1>Security Validation Failed</h1>
    <p>The authentication token has expired or is invalid.</p>
    <p>This is a security measure to protect your account.</p>
    <div class="footer">
      <div class="brosh-logo">BROSH AI CRM</div>
      <p>Please close this window and start the authentication process again.</p>
    </div>
  </div>
</body>
</html>`);
            console.error('❌ State validation failed, but server continues running');
            return;
          }
        } else {
          console.error('⚠️  State validation skipped (BROSH_SKIP_STATE_VALIDATION=true)');
        }

        if (code) {
          console.error('✅ Authorization code received, exchanging for tokens...');
          
          try {
            // Exchange code for tokens
            const response = await axios.post(`${BROSH_BASE_URL}/api/oauth2/token/${BROSH_SOURCE}`, {
              code,
              redirect_uri: getRedirectUri(),
              client_id: BROSH_CLIENT_ID,
              client_secret: BROSH_CLIENT_SECRET,
              grant_type: 'authorization_code',
            });

            saveTokens(response.data);
            
            console.error('✅ Token exchange successful!');
            console.error('📄 Token data:', JSON.stringify(response.data, null, 2));
            
            res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
            res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM — Connected</title>
  <link rel="icon" type="image/x-icon" href="https://www.brosh.io/favicon.ico">
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
      padding:52px 44px 44px;
      max-width:500px;width:100%;text-align:center;
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
      width:88px;height:88px;border-radius:50%;
      background:linear-gradient(135deg,var(--brand-1),var(--brand-2));
      box-shadow:0 12px 36px rgba(8,162,161,.48);
      display:flex;align-items:center;justify-content:center;
      margin:0 auto 32px;
      animation:pop .5s .2s cubic-bezier(.34,1.56,.64,1) both;
    }
    @keyframes pop{from{opacity:0;transform:scale(.4)}to{opacity:1;transform:scale(1)}}
    .check-wrap svg{width:42px;height:42px;stroke:#fff;stroke-width:3;fill:none;
      stroke-linecap:round;stroke-linejoin:round}
    .check-path{stroke-dasharray:50;stroke-dashoffset:50;animation:draw .4s .65s ease forwards}
    @keyframes draw{to{stroke-dashoffset:0}}
    h1{
      font-family:'Space Grotesk','Manrope',sans-serif;
      font-size:clamp(24px,4vw,32px);font-weight:700;letter-spacing:-.5px;
      background:linear-gradient(130deg,#104179 0%,#0e7f8f 55%,#ff8a3d 100%);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      margin-bottom:12px;
    }
    .tagline{color:#597095;font-size:15px;font-weight:500;margin-bottom:28px;line-height:1.6}
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      background:var(--ok-bg);color:var(--ok-tx);
      padding:10px 22px;border-radius:50px;
      font-size:14px;font-weight:700;margin-bottom:28px;
    }
    .pill svg{width:16px;height:16px;fill:var(--ok-tx);flex-shrink:0}
    .divider{height:1px;background:#dce8f6;margin:24px 0}
    .hint{
      background:#f1f7ff;border-radius:10px;
      padding:14px 18px;font-size:13px;color:#486581;line-height:1.6;
    }
    .hint a{color:var(--brand-2);font-weight:600;text-decoration:none}
    .hint a:hover{text-decoration:underline}
    .brand{
      margin-top:28px;font-size:12px;font-weight:600;letter-spacing:.05em;
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
    <p class="tagline">Your BROSH CRM account has been authorized.<br>You can now use all CRM tools from your AI assistant.</p>
    <div class="pill">
      <svg viewBox="0 0 20 20"><path d="M10 2a8 8 0 100 16A8 8 0 0010 2zm3.7 6.3l-4 4a1 1 0 01-1.4 0l-2-2a1 1 0 111.4-1.4L9 10.58l3.3-3.3a1 1 0 111.4 1.42z"/></svg>
      Authentication Successful
    </div>
    <div class="divider"></div>
    <div class="hint">You can safely close this window, or <a href="http://localhost:${actualPort}/">view your connection status</a>.</div>
    <div class="brand">BROSH AI CRM &nbsp;·&nbsp; Powered by MCP</div>
  </div>
</body>
</html>`);
            
            console.error('\n✅ Authentication successful! Server continues running...');
            console.error(`🏠 Visit http://localhost:${actualPort}/ to see your OAuth status\n`);
          } catch (error: any) {
            console.error('❌ Token exchange failed:', error.response?.data || error.message);
            res.writeHead(500, { 'Content-Type': 'text/html; charset=UTF-8' });
            res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM - Token Exchange Failed</title>
  <link rel="icon" type="image/x-icon" href="https://www.brosh.io/favicon.ico">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 48px;
      max-width: 500px;
      width: 100%;
      text-align: center;
    }
    .icon { font-size: 72px; margin-bottom: 24px; }
    h1 { color: #1a202c; font-size: 28px; font-weight: 700; margin-bottom: 16px; }
    p { color: #4a5568; font-size: 16px; line-height: 1.6; margin-bottom: 12px; }
    .error-code {
      background: #fed7d7;
      color: #c53030;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: monospace;
      font-size: 14px;
      margin-top: 24px;
      word-break: break-word;
    }
    .footer {
      margin-top: 32px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
      color: #718096;
      font-size: 14px;
    }
    .brosh-logo { color: #667eea; font-weight: 700; font-size: 18px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">⚠️</div>
    <h1>Token Exchange Failed</h1>
    <p>We received the authorization code but couldn't exchange it for access tokens.</p>
    <div class="error-code">${error.message}</div>
    <div class="footer">
      <div class="brosh-logo">BROSH AI CRM</div>
      <p>Please check your terminal for detailed error information and try again.</p>
    </div>
  </div>
</body>
</html>`);
            console.error('❌ Token exchange failed, but server continues running');
          }
          return;
        }
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      } catch (error: any) {
        console.error('❌ Error handling request:', error.message);
        try {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } catch (e) {
          // Response already sent, ignore
        }
      }
    });

    const tryListen = (portToTry: number, attempt: number = 0): void => {
      if (attempt >= 10) {
        console.error(`❌ Could not find an available port after trying ports ${port}-${port + 9}`);
        reject(new Error(`No available ports found`));
        return;
      }

      server.once('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
          console.error(`⚠️  Port ${portToTry} is already in use, trying port ${portToTry + 1}...`);
          tryListen(portToTry + 1, attempt + 1);
        } else {
          console.error('❌ Server error:', err.message);
          reject(err);
        }
      });

      server.listen(portToTry, '0.0.0.0', () => {
        actualPort = portToTry;
        if (portToTry !== port) {
          console.error(`✅ OAuth callback server listening on http://localhost:${portToTry}/oauth/callback`);
          console.error(`   ℹ️  Using port ${portToTry} (default port ${port} was busy)`);
        } else {
          console.error(`✅ OAuth callback server listening on http://localhost:${portToTry}/oauth/callback`);
        }
        console.error(`   Waiting for OAuth callback from BROSH...`);
      });
    };

    tryListen(port);
  });
}

// Define MCP tools
const tools: Tool[] = [
  // OAuth2 Tools
  {
    name: 'brosh_start_oauth',
    description: 'Start OAuth2 authentication flow (Zapier-like). Client ID and secret are auto-generated per installation. Returns login URL with state parameter for CSRF protection. Default scope is "Full" for full access.',
    inputSchema: {
      type: 'object',
      properties: {
        redirect_uri: {
          type: 'string',
          description: 'Redirect URI (default: http://localhost:3000/oauth/callback)',
        },
        port: {
          type: 'number',
          description: 'Local server port for OAuth callback (default: 3000)',
        },
        scope: {
          type: 'string',
          description: 'OAuth scopes (default: Full)',
        },
      },
    },
  },
  {
    name: 'brosh_exchange_token',
    description: 'Exchange OAuth2 authorization code for access token. Usually called automatically after OAuth flow.',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'Authorization code from OAuth flow',
        },
        redirect_uri: {
          type: 'string',
          description: 'OAuth redirect URI (must match the one used in authorization)',
        },
        client_id: {
          type: 'string',
          description: 'OAuth client ID',
        },
        client_secret: {
          type: 'string',
          description: 'OAuth client secret',
        },
        source: {
          type: 'string',
          enum: ['make', 'zapier', 'n8n', 'custom', 'mcp'],
          description: 'Integration source type (default: mcp)',
        },
      },
      required: ['code', 'redirect_uri', 'client_id', 'client_secret'],
    },
  },
  {
    name: 'brosh_refresh_token',
    description: 'Refresh OAuth2 access token using stored refresh token',
    inputSchema: {
      type: 'object',
      properties: {
        force: {
          type: 'boolean',
          description: 'Force refresh even if current token is valid',
        },
      },
    },
  },
  {
    name: 'brosh_validate_token',
    description: 'Validate current access token and return user information',
    inputSchema: {
      type: 'object',
      properties: {
        source: {
          type: 'string',
          enum: ['make', 'zapier', 'n8n', 'custom', 'mcp'],
          description: 'Integration source type (default: mcp)',
        },
      },
    },
  },
  {
    name: 'brosh_logout',
    description: 'Clear stored authentication tokens',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  // CRUD Tools
  {
    name: 'brosh_get_records',
    description: 'Get records by their IDs from BROSH CRM',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          enum: SUPPORTED_TABLES,
          description: 'Table name to query',
        },
        ids: {
          type: 'array',
          items: { type: 'number' },
          description: 'Array of record IDs to retrieve',
        },
        limit: {
          type: 'number',
          description: 'Maximum records to return (1-10000, default: 10)',
          minimum: 1,
          maximum: 10000,
        },
      },
      required: ['table_name', 'ids'],
    },
  },
  {
    name: 'brosh_find_records',
    description: 'Find records with advanced filtering, sorting, and pagination',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          enum: SUPPORTED_TABLES,
          description: 'Table name to query',
        },
        fields: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of fields to return (omit for all fields)',
        },
        filter: {
          type: 'object',
          description: 'Filter criteria',
          properties: {
            id: {
              type: ['string', 'number'],
              description: 'Exact ID match',
            },
            search: {
              type: 'string',
              description: 'Text search on name field (supports % wildcards)',
            },
            where: {
              type: 'object',
              description: 'Field conditions (equality or operator objects)',
            },
          },
        },
        sort: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              field: { type: 'string' },
              direction: {
                type: 'string',
                enum: ['ASC', 'DESC'],
              },
            },
            required: ['field', 'direction'],
          },
          description: 'Sort order for results',
        },
        page_size: {
          type: 'number',
          description: 'Records per page (default: 50)',
        },
        page: {
          type: 'number',
          description: 'Page number (default: 1)',
        },
        limit: {
          type: 'number',
          description: 'Override pagination with max limit (1-10000)',
          minimum: 1,
          maximum: 10000,
        },
      },
      required: ['table_name'],
    },
  },
  {
    name: 'brosh_create_records',
    description: 'Create one or more records in BROSH CRM',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          enum: SUPPORTED_TABLES,
          description: 'Table name to create records in',
        },
        records: {
          type: 'array',
          items: { type: 'object' },
          description: 'Array of record objects to create',
        },
      },
      required: ['table_name', 'records'],
    },
  },
  {
    name: 'brosh_update_records',
    description: 'Update one or more records in BROSH CRM',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          enum: SUPPORTED_TABLES,
          description: 'Table name to update records in',
        },
        records: {
          type: 'array',
          items: {
            type: 'object',
            required: ['id'],
          },
          description: 'Array of record objects with id field to update',
        },
      },
      required: ['table_name', 'records'],
    },
  },
  {
    name: 'brosh_delete_records',
    description: 'Delete one or more records in BROSH CRM (moved to recycle bin for 30 days)',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          enum: SUPPORTED_TABLES,
          description: 'Table name to delete records from',
        },
        ids: {
          type: 'array',
          items: { type: 'number' },
          description: 'Array of record IDs to delete',
        },
      },
      required: ['table_name', 'ids'],
    },
  },
];

// Tool handlers
async function handleStartOAuth(args: any) {
  const clientId = BROSH_CLIENT_ID;
  const clientSecret = BROSH_CLIENT_SECRET;
  const redirectUri = args.redirect_uri || getRedirectUri();
  const port = actualPort;
  const scope = args.scope || 'Full';

  // Read or generate state (don't overwrite existing state)
  let state: string;
  try {
    if (fs.existsSync(STATE_FILE)) {
      const stateData = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      state = stateData.state;
    } else {
      state = generateState();
      saveState(state);
    }
  } catch (error) {
    state = generateState();
    saveState(state);
  }

  // Build login URL with parameters (Zapier-like format)
  const authUrl = new URL(`${BROSH_BASE_URL}/en/login`);
  authUrl.searchParams.set('src', BROSH_SOURCE);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', scope);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');

  // OAuth callback server is already running from main()
  // No need to start a new one

  const message = [
    '🔐 BROSH CRM OAuth2 Authentication',
    '',
    'Client ID: ' + clientId,
    'Client Secret: ' + clientSecret.substring(0, 15) + '...',
    'State: ' + state.substring(0, 12) + '...',
    '',
    '🏠 Landing Page (with login button):',
    `   http://localhost:${actualPort}/`,
    '',
    '🔗 Or copy this URL to log in directly:',
    authUrl.toString(),
    '',
    '✅ OAuth callback server is already running on port ' + port,
    '💡 Authentication will happen automatically when you click the login link',
  ].join('\n');

  return {
    content: [
      {
        type: 'text',
        text: message,
      },
    ],
  };
}

async function handleExchangeToken(args: any) {
  const client = axios.create({ baseURL: BROSH_BASE_URL });
  
  const response = await client.post('/api/oauth2/token/mcp', {
    code: args.code,
    redirect_uri: args.redirect_uri,
    client_id: args.client_id,
    client_secret: args.client_secret,
    grant_type: 'authorization_code',
  });

  saveTokens(response.data);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

async function handleRefreshToken(args: any) {
  const token = await refreshAccessToken();
  
  if (!token) {
    throw new Error('Failed to refresh token. No refresh token available or refresh failed.');
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          message: 'Token refreshed successfully',
          ...cachedTokens
        }, null, 2),
      },
    ],
  };
}

async function handleValidateToken(args: any) {
  const source = args.source || BROSH_SOURCE;
  let token = getAccessToken();
  
  if (!token) {
    throw new Error('No access token available. Please authenticate first using brosh_start_oauth.');
  }

  try {
    const client = createApiClient(token);
    const response = await client.post(`/api/oauth2/me/${source}`, {});

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response.data, null, 2),
        },
      ],
    };
  } catch (error: any) {
    // If token is invalid, try refreshing
    if (error.response?.status === 401) {
      token = await refreshAccessToken();
      if (token) {
        const client = createApiClient(token);
        const response = await client.post(`/api/oauth2/me/${source}`, {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(response.data, null, 2),
            },
          ],
        };
      }
    }
    throw error;
  }
}

async function handleLogout() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      fs.unlinkSync(TOKEN_FILE);
    }
    cachedTokens = null;
    
    return {
      content: [
        {
          type: 'text',
          text: '✅ Logged out successfully. All tokens have been cleared.',
        },
      ],
    };
  } catch (error: any) {
    throw new Error(`Failed to logout: ${error.message}`);
  }
}

async function handleGetRecords(args: any) {
  const client = createApiClient();
  const source = BROSH_SOURCE;
  
  let url = `/api/oauth2/getRecords/${source}/${args.table_name}`;
  if (args.limit) {
    url += `?limit=${args.limit}`;
  }

  const response = await client.post(url, args.ids);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

async function handleFindRecords(args: any) {
  const client = createApiClient();
  const source = BROSH_SOURCE;
  
  let url = `/api/oauth2/findRecords/${source}/${args.table_name}`;
  if (args.limit) {
    url += `?limit=${args.limit}`;
  }

  const body: any = {};
  if (args.fields) body.fields = args.fields;
  if (args.filter) body.filter = args.filter;
  if (args.sort) body.sort = args.sort;
  if (args.page_size) body.page_size = args.page_size;
  if (args.page) body.page = args.page;

  const response = await client.post(url, body);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

async function handleCreateRecords(args: any) {
  const client = createApiClient();
  const source = BROSH_SOURCE;
  
  const response = await client.post(
    `/api/oauth2/create/${source}/${args.table_name}`,
    args.records
  );

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

async function handleUpdateRecords(args: any) {
  const client = createApiClient();
  const source = BROSH_SOURCE;
  
  const response = await client.post(
    `/api/oauth2/update/${source}/${args.table_name}`,
    args.records
  );

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

async function handleDeleteRecords(args: any) {
  const client = createApiClient();
  const source = BROSH_SOURCE;
  
  // Convert IDs array to array of objects with id field
  const deletePayload = args.ids.map((id: number) => ({ id }));
  
  const response = await client.post(
    `/api/oauth2/delete/${source}/${args.table_name}`,
    deletePayload
  );

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(response.data, null, 2),
      },
    ],
  };
}

// Initialize MCP server
const server = new Server(
  {
    name: 'brosh-crm',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const requiresAuth = !['brosh_start_oauth', 'brosh_exchange_token'].includes(name);

  try {
    if (requiresAuth) {
      await ensureValidAccessToken();
    }

    switch (name) {
      case 'brosh_start_oauth':
        return await handleStartOAuth(args);
      case 'brosh_exchange_token':
        return await handleExchangeToken(args);
      case 'brosh_refresh_token':
        return await handleRefreshToken(args);
      case 'brosh_validate_token':
        return await handleValidateToken(args);
      case 'brosh_logout':
        return await handleLogout();
      case 'brosh_get_records':
        return await handleGetRecords(args);
      case 'brosh_find_records':
        return await handleFindRecords(args);
      case 'brosh_create_records':
        return await handleCreateRecords(args);
      case 'brosh_update_records':
        return await handleUpdateRecords(args);
      case 'brosh_delete_records':
        return await handleDeleteRecords(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    // Handle 401 errors by attempting token refresh
    if (error.response?.status === 401 && name !== 'brosh_start_oauth' && name !== 'brosh_exchange_token') {
      const refreshedToken = await refreshAccessToken();
      if (refreshedToken) {
        // Retry the operation with refreshed token
        try {
          switch (name) {
            case 'brosh_validate_token':
              return await handleValidateToken(args);
            case 'brosh_get_records':
              return await handleGetRecords(args);
            case 'brosh_find_records':
              return await handleFindRecords(args);
            case 'brosh_create_records':
              return await handleCreateRecords(args);
            case 'brosh_update_records':
              return await handleUpdateRecords(args);
            case 'brosh_delete_records':
              return await handleDeleteRecords(args);
          }
        } catch (retryError: any) {
          const errorMessage = retryError.response?.data 
            ? JSON.stringify(retryError.response.data, null, 2)
            : retryError.message;
          
          return {
            content: [
              {
                type: 'text',
                text: `Error (after token refresh): ${errorMessage}`,
              },
            ],
            isError: true,
          };
        }
      }
    }
    
    const errorMessage = error.response?.data 
      ? JSON.stringify(error.response.data, null, 2)
      : error.message;
    
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
  console.error('\n❌ Uncaught Exception:', error.message);
  console.error('Stack:', error.stack);
  console.error('⚠️  Server will continue running...\n');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('\n❌ Unhandled Rejection at:', promise);
  console.error('Reason:', reason);
  console.error('⚠️  Server will continue running...\n');
});

// Graceful shutdown on Ctrl+C
let isShuttingDown = false;
process.on('SIGINT', () => {
  if (isShuttingDown) {
    console.error('\n⚠️  Force shutdown...');
    process.exit(0);
  }
  isShuttingDown = true;
  console.error('\n\n👋 Shutting down BROSH CRM MCP server gracefully...');
  console.error('   Press Ctrl+C again to force quit');
  setTimeout(() => {
    console.error('✅ Server stopped');
    process.exit(0);
  }, 1000);
});

// Start server
async function main() {
  // Load existing tokens if available
  const existingTokens = loadTokens();
  const isAuthenticated = existingTokens?.expires_at && existingTokens.expires_at > Date.now();
  
  // Generate initial state if not exists
  if (!fs.existsSync(STATE_FILE)) {
    const state = generateState();
    saveState(state);
  }
  
  // Start OAuth callback server in the background
  const port = 3000;
  console.error('🔐 Starting OAuth callback server...');
  console.error(`🏠 OAuth Status Page: http://localhost:${port}/ (will use alternative port if busy)`);
  
  if (isAuthenticated) {
    console.error('✅ Already authenticated with BROSH CRM');
    const timeRemaining = Math.floor((existingTokens.expires_at! - Date.now()) / 60000);
    console.error(`   Token expires in ${timeRemaining} minutes`);
  } else {
    console.error('⚠️  Not authenticated - please visit the OAuth page to login');
  }
  
  startOAuthCallbackServer(port).catch((error) => {
    console.error('OAuth server error:', error.message);
  });
  
  // Start MCP server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('✅ BROSH AI CRM MCP Server running on stdio');
  // Wait a moment for the server to settle and actualPort to be set
  setTimeout(() => {
    console.error(`💡 Visit http://localhost:${actualPort}/ to manage authentication`);
  }, 100);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

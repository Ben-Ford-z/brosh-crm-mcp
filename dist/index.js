#!/usr/bin/env node
/**
 * BROSH AI CRM MCP Server
 * Provides OAuth2 authentication and full CRUD operations for BROSH CRM
 * Documentation: https://www.brosh.io/page/api-oauth2-documentation
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
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
];
// Environment configuration
const BROSH_BASE_URL = process.env.BROSH_BASE_URL || 'https://app.brosh.io';
const BROSH_SOURCE = (process.env.BROSH_SOURCE || 'mcp');
const BROSH_SKIP_STATE_VALIDATION = process.env.BROSH_SKIP_STATE_VALIDATION === 'true';
function getWritableStorageDir() {
    const primaryDir = path.join(os.homedir(), 'brosh-crm-mcp');
    const fallbackDir = path.join(os.homedir(), '.brosh-crm-mcp2');
    const checkDir = (dir) => {
        try {
            fs.mkdirSync(dir, { recursive: true });
            fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK);
            return true;
        }
        catch {
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
let actualPort = 3000;
const getRedirectUri = () => process.env.BROSH_REDIRECT_URI || `http://localhost:${actualPort}/oauth/callback`;
// Generate or load client ID (random for each installation like Zapier)
function getOrCreateClientId() {
    const envClientId = process.env.BROSH_CLIENT_ID;
    if (envClientId) {
        return envClientId;
    }
    try {
        if (fs.existsSync(CLIENT_ID_FILE)) {
            return fs.readFileSync(CLIENT_ID_FILE, 'utf8').trim();
        }
    }
    catch (error) {
        console.error('Failed to read client ID file:', error);
    }
    // Generate new client ID in format BROSH-{random_number}
    const randomNum = Math.floor(Math.random() * 1000000000000000);
    const clientId = `BROSH-${randomNum}`;
    try {
        fs.writeFileSync(CLIENT_ID_FILE, clientId, 'utf8');
        console.error(`Generated new client ID and saved to .brosh-client-id: ${clientId}`);
    }
    catch (error) {
        console.error('Failed to save client ID:', error);
    }
    return clientId;
}
// Generate or load client secret
function getOrCreateClientSecret() {
    const envSecret = process.env.BROSH_CLIENT_SECRET;
    if (envSecret) {
        return envSecret;
    }
    try {
        if (fs.existsSync(CLIENT_SECRET_FILE)) {
            return fs.readFileSync(CLIENT_SECRET_FILE, 'utf8').trim();
        }
    }
    catch (error) {
        console.error('Failed to read client secret file:', error);
    }
    // Generate new client secret
    const secret = 'BROSH-' + crypto.randomBytes(32).toString('hex');
    try {
        fs.writeFileSync(CLIENT_SECRET_FILE, secret, 'utf8');
        console.error('Generated new client secret and saved to .brosh-client-secret');
    }
    catch (error) {
        console.error('Failed to save client secret:', error);
    }
    return secret;
}
const BROSH_CLIENT_ID = getOrCreateClientId();
const BROSH_CLIENT_SECRET = getOrCreateClientSecret();
// OAuth state management
function generateState() {
    return crypto.randomBytes(32).toString('hex');
}
function saveState(state) {
    try {
        fs.writeFileSync(STATE_FILE, JSON.stringify({ state, timestamp: Date.now() }), 'utf8');
    }
    catch (error) {
        console.error('Failed to save OAuth state:', error);
    }
}
function validateState(state) {
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
        }
        else {
            console.error('State mismatch!');
        }
        return isValid;
    }
    catch (error) {
        console.error('Failed to validate OAuth state:', error);
        return false;
    }
}
// Token management
let cachedTokens = null;
function loadTokens() {
    try {
        if (fs.existsSync(TOKEN_FILE)) {
            const data = fs.readFileSync(TOKEN_FILE, 'utf8');
            cachedTokens = JSON.parse(data);
            return cachedTokens;
        }
    }
    catch (error) {
        console.error('Failed to load tokens:', error);
    }
    return null;
}
function saveTokens(tokens) {
    try {
        // Calculate expiration timestamp if expires_in is provided
        if (tokens.expires_in && !tokens.expires_at) {
            tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
        }
        cachedTokens = tokens;
        fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2), 'utf8');
    }
    catch (error) {
        console.error('Failed to save tokens:', error);
    }
}
function getAccessToken() {
    if (!cachedTokens) {
        cachedTokens = loadTokens();
    }
    return cachedTokens?.access_token || null;
}
async function refreshAccessToken(refreshToken, clientId, clientSecret) {
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
    }
    catch (error) {
        console.error('❌ Token refresh failed:', error.response?.data || error.message);
        return null;
    }
}
// Create axios instance
function createApiClient(accessToken) {
    const token = accessToken || getAccessToken();
    return axios.create({
        baseURL: BROSH_BASE_URL,
        headers: {
            'Content-Type': 'application/json',
            ...(token && { Authorization: `Bearer ${token}` }),
        },
    });
}
// OAuth2 callback server (runs indefinitely)
function startOAuthCallbackServer(port = 3000) {
    return new Promise((resolve, reject) => {
        const server = http.createServer(async (req, res) => {
            try {
                const parsedUrl = url.parse(req.url || '', true);
                // Serve favicon from app.brosh.io
                if (parsedUrl.pathname === '/favicon.ico') {
                    res.writeHead(302, { 'Location': 'https://app.brosh.io/favicon.ico' });
                    res.end();
                    return;
                }
                // Root path - show status/landing page with auto-refresh
                if (parsedUrl.pathname === '/') {
                    let isAuthenticated = false;
                    let tokenData = null;
                    let userData = null;
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
                                    }
                                    else {
                                        isAuthenticated = false;
                                    }
                                }
                                else {
                                    console.error('⚠️  No refresh token available for auto-refresh');
                                    isAuthenticated = false;
                                }
                            }
                            else if (tokenData.expires_at && tokenData.expires_at > Date.now()) {
                                isAuthenticated = true;
                            }
                            else {
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
                                }
                                catch (error) {
                                    console.error('Failed to fetch user info:', error);
                                }
                            }
                        }
                        else {
                            isAuthenticated = false;
                        }
                    }
                    catch (error) {
                        isAuthenticated = false;
                    }
                    // Read current state from file (or generate new one if missing)
                    let currentState;
                    try {
                        if (fs.existsSync(STATE_FILE)) {
                            const stateData = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
                            currentState = stateData.state;
                        }
                        else {
                            currentState = generateState();
                            saveState(currentState);
                        }
                    }
                    catch (error) {
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
  <link rel="icon" type="image/x-icon" href="https://app.brosh.io/favicon.ico">
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
      max-width: 600px;
      width: 100%;
    }
    .header { text-align: center; margin-bottom: 32px; }
    h1 {
      color: #1a202c;
      font-size: 32px;
      font-weight: 700;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .subtitle { color: #718096; font-size: 16px; }
    .content { margin: 32px 0; }
    .steps {
      background: #f7fafc;
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
    }
    .step {
      display: flex;
      margin-bottom: 16px;
      align-items: flex-start;
    }
    .step:last-child { margin-bottom: 0; }
    .step-number {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 14px;
      margin-right: 16px;
      flex-shrink: 0;
    }
    .step-content { flex: 1; }
    .step-title {
      color: #2d3748;
      font-weight: 600;
      font-size: 16px;
      margin-bottom: 4px;
    }
    .step-desc {
      color: #718096;
      font-size: 14px;
      line-height: 1.5;
    }
    .info-box {
      background: #edf2f7;
      border-left: 4px solid #667eea;
      padding: 16px 20px;
      border-radius: 8px;
      margin: 24px 0;
    }
    .info-box p {
      color: #2d3748;
      font-size: 14px;
      line-height: 1.6;
      margin-bottom: 8px;
    }
    .info-box p:last-child { margin-bottom: 0; }
    .info-box strong { color: #1a202c; }
    .button-container { text-align: center; margin-top: 32px; }
    .login-button {
      display: inline-block;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 16px 48px;
      border-radius: 12px;
      font-size: 18px;
      font-weight: 600;
      text-decoration: none;
      box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
      transition: all 0.3s ease;
      border: none;
      cursor: pointer;
    }
    .login-button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    .login-button:active { transform: translateY(0); }
    .logout-button {
      display: inline-block;
      background: #e53e3e;
      color: white;
      padding: 12px 32px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      text-decoration: none;
      margin-left: 12px;
      transition: all 0.3s ease;
    }
    .logout-button:hover {
      background: #c53030;
      transform: translateY(-1px);
    }
    .footer {
      margin-top: 32px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
      text-align: center;
      color: #718096;
      font-size: 14px;
    }
    .status {
      padding: 12px 20px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: center;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .status.authenticated {
      background: #c6f6d5;
      color: #22543d;
    }
    .status.ready {
      background: #bee3f8;
      color: #2c5282;
    }
    .status.warning {
      background: #fef5e7;
      color: #c05621;
    }
    .user-info {
      background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
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
      color: #718096;
      font-size: 14px;
      font-weight: 600;
    }
    .user-info-value {
      color: #2d3748;
      font-size: 14px;
      font-weight: 500;
    }
    .refresh-hint {
      text-align: center;
      color: #718096;
      font-size: 13px;
      margin-top: 16px;
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
        <p style="color: #2d3748; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
          Welcome! This server is waiting to complete your BROSH CRM authentication. 
          Click the button below to log in and authorize access to your CRM data.
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
                    }
                    catch (error) {
                        console.error('Logout error:', error);
                        res.writeHead(500, { 'Content-Type': 'text/plain' });
                        res.end('Logout failed');
                    }
                    return;
                }
                if (parsedUrl.pathname === '/oauth/callback') {
                    const code = parsedUrl.query.code;
                    const state = parsedUrl.query.state;
                    const src = parsedUrl.query.src;
                    const error = parsedUrl.query.error;
                    console.error(`OAuth callback received: src=${src}, code=${code ? 'present' : 'missing'}, state=${state ? 'present' : 'missing'}`);
                    if (error) {
                        res.writeHead(400, { 'Content-Type': 'text/html; charset=UTF-8' });
                        res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM - Authentication Failed</title>
  <link rel="icon" type="image/x-icon" href="https://app.brosh.io/favicon.ico">
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
  <link rel="icon" type="image/x-icon" href="https://app.brosh.io/favicon.ico">
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
                    }
                    else {
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
  <title>BROSH CRM - Authentication Successful</title>
  <link rel="icon" type="image/x-icon" href="https://app.brosh.io/favicon.ico">
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
      animation: slideIn 0.5s ease-out;
    }
    @keyframes slideIn {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .icon {
      font-size: 72px;
      margin-bottom: 24px;
      animation: bounce 0.6s ease-in-out;
    }
    @keyframes bounce {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-20px); }
    }
    h1 {
      color: #1a202c;
      font-size: 32px;
      font-weight: 700;
      margin-bottom: 16px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 12px;
    }
    .success-box {
      background: linear-gradient(135deg, #d4fc79 0%, #96e6a1 100%);
      padding: 20px;
      border-radius: 12px;
      margin: 24px 0;
    }
    .success-text {
      color: #22543d;
      font-weight: 600;
      font-size: 18px;
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
      font-size: 20px;
      margin-bottom: 8px;
    }
    .close-hint {
      background: #edf2f7;
      padding: 12px 20px;
      border-radius: 8px;
      margin-top: 16px;
      color: #2d3748;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">✅</div>
    <h1>Authentication Successful!</h1>
    <div class="success-box">
      <div class="success-text">You're all set! Your BROSH CRM account is now connected.</div>
    </div>
    <p>Your authentication was completed securely.</p>
    <p>You can now access all your CRM data through the MCP interface.</p>
    <div class="close-hint">You can safely close this window or visit <a href="/" style="color: #667eea;">http://localhost:${actualPort}/</a> to see your status.</div>
    <div class="footer">
      <div class="brosh-logo">BROSH AI CRM</div>
      <p>Powered by Model Context Protocol</p>
    </div>
  </div>
</body>
</html>`);
                            console.error('\n✅ Authentication successful! Server continues running...');
                            console.error(`🏠 Visit http://localhost:${actualPort}/ to see your OAuth status\n`);
                        }
                        catch (error) {
                            console.error('❌ Token exchange failed:', error.response?.data || error.message);
                            res.writeHead(500, { 'Content-Type': 'text/html; charset=UTF-8' });
                            res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BROSH CRM - Token Exchange Failed</title>
  <link rel="icon" type="image/x-icon" href="https://app.brosh.io/favicon.ico">
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
            }
            catch (error) {
                console.error('❌ Error handling request:', error.message);
                try {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Internal Server Error');
                }
                catch (e) {
                    // Response already sent, ignore
                }
            }
        });
        const tryListen = (portToTry, attempt = 0) => {
            if (attempt >= 10) {
                console.error(`❌ Could not find an available port after trying ports ${port}-${port + 9}`);
                reject(new Error(`No available ports found`));
                return;
            }
            server.once('error', (err) => {
                if (err.code === 'EADDRINUSE') {
                    console.error(`⚠️  Port ${portToTry} is already in use, trying port ${portToTry + 1}...`);
                    tryListen(portToTry + 1, attempt + 1);
                }
                else {
                    console.error('❌ Server error:', err.message);
                    reject(err);
                }
            });
            server.listen(portToTry, '0.0.0.0', () => {
                actualPort = portToTry;
                if (portToTry !== port) {
                    console.error(`✅ OAuth callback server listening on http://localhost:${portToTry}/oauth/callback`);
                    console.error(`   ℹ️  Using port ${portToTry} (default port ${port} was busy)`);
                }
                else {
                    console.error(`✅ OAuth callback server listening on http://localhost:${portToTry}/oauth/callback`);
                }
                console.error(`   Waiting for OAuth callback from BROSH...`);
            });
        };
        tryListen(port);
    });
}
// Define MCP tools
const tools = [
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
async function handleStartOAuth(args) {
    const clientId = BROSH_CLIENT_ID;
    const clientSecret = BROSH_CLIENT_SECRET;
    const redirectUri = args.redirect_uri || getRedirectUri();
    const port = actualPort;
    const scope = args.scope || 'Full';
    // Read or generate state (don't overwrite existing state)
    let state;
    try {
        if (fs.existsSync(STATE_FILE)) {
            const stateData = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
            state = stateData.state;
        }
        else {
            state = generateState();
            saveState(state);
        }
    }
    catch (error) {
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
async function handleExchangeToken(args) {
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
async function handleRefreshToken(args) {
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
async function handleValidateToken(args) {
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
    }
    catch (error) {
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
    }
    catch (error) {
        throw new Error(`Failed to logout: ${error.message}`);
    }
}
async function handleGetRecords(args) {
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
async function handleFindRecords(args) {
    const client = createApiClient();
    const source = BROSH_SOURCE;
    let url = `/api/oauth2/findRecords/${source}/${args.table_name}`;
    if (args.limit) {
        url += `?limit=${args.limit}`;
    }
    const body = {};
    if (args.fields)
        body.fields = args.fields;
    if (args.filter)
        body.filter = args.filter;
    if (args.sort)
        body.sort = args.sort;
    if (args.page_size)
        body.page_size = args.page_size;
    if (args.page)
        body.page = args.page;
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
async function handleCreateRecords(args) {
    const client = createApiClient();
    const source = BROSH_SOURCE;
    const response = await client.post(`/api/oauth2/create/${source}/${args.table_name}`, args.records);
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify(response.data, null, 2),
            },
        ],
    };
}
async function handleUpdateRecords(args) {
    const client = createApiClient();
    const source = BROSH_SOURCE;
    const response = await client.post(`/api/oauth2/update/${source}/${args.table_name}`, args.records);
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify(response.data, null, 2),
            },
        ],
    };
}
async function handleDeleteRecords(args) {
    const client = createApiClient();
    const source = BROSH_SOURCE;
    // Convert IDs array to array of objects with id field
    const deletePayload = args.ids.map((id) => ({ id }));
    const response = await client.post(`/api/oauth2/delete/${source}/${args.table_name}`, deletePayload);
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
const server = new Server({
    name: 'brosh-crm',
    version: '1.0.0',
}, {
    capabilities: {
        tools: {},
    },
});
// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools,
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
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
    }
    catch (error) {
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
                }
                catch (retryError) {
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
        const timeRemaining = Math.floor((existingTokens.expires_at - Date.now()) / 60000);
        console.error(`   Token expires in ${timeRemaining} minutes`);
    }
    else {
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
//# sourceMappingURL=index.js.map
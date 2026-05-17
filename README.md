# 🚀 BROSH CRM MCP Server

### Official AI-Powered Customer Relationship Management for Claude AI & MCP-Compatible Applications

**The Official Model Context Protocol Server for BROSH AI CRM**

[![npm version](https://badge.fury.io/js/brosh-crm-mcp.svg)](https://www.npmjs.com/package/brosh-crm-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org/)

**Transform your AI assistant into a powerful CRM  smart CRM master and automation hero.** Connect [BROSH AI CRM](https://brosh.io) to Claude Desktop, Cline, or any Model Context Protocol (MCP) compatible application for intelligent customer data management, sales automation, and business intelligence.

Perfect for **sales teams**, **customer success managers**, **marketing automation**, **business owners**, and **developers** building AI-powered CRM workflows.

---

## 💡 Business Benefits

With the BROSH CRM MCP, teams can leverage AI to import and export data from other systems using natural language. This enables:

- **Easy CRM migration** - Import historical data from other CRMs or sources with few natural-language commands.
- **Fast onboarding & setup** - Configure accounts, users, and initial data via conversational prompts.
- **Automation & integrations** - Create integrations, automation rules, and scheduled processes using natural language instructions.
- **Simplified data sync** - Use AI to map, transform, and load external datasets into BROSH CRM without manual scripting.

These capabilities make migrating to BROSH CRM, onboarding new teams, and maintaining integrations much faster and less error-prone.

---


## 🎯 Real-World Use Cases

### 💼 Sales Automation & Pipeline Management
- **Lead qualification** - Automatically score and categorize leads based on engagement
- **Opportunity tracking** - Monitor sales pipeline stages and deal progression
- **Quote & invoice generation** - Create quotes and invoices with pricing from product catalog
- **Win/loss analysis** - Analyze closed deals to improve sales strategies
- **Revenue forecasting** - Predict sales outcomes based on pipeline data

### 👥 Customer Relationship Management
- **360° customer view** - Access complete customer history in seconds
- **Contact enrichment** - Update customer records with new information
- **Account hierarchy** - Manage parent-child company relationships
- **Customer segmentation** - Group customers by behavior, value, or attributes
- **Churn prediction** - Identify at-risk customers for proactive outreach

### 📈 Marketing Campaign Management
- **Campaign tracking** - Monitor campaign performance and ROI
- **Lead nurturing** - Automate follow-up sequences based on engagement
- **Email list management** - Segment contacts for targeted campaigns
- **Attribution analysis** - Track which campaigns generate conversions
- **A/B testing** - Compare campaign variants and optimize messaging

### 🎫 Customer Support Excellence
- **Ticket management** - Create, update, and resolve support tickets
- **SLA monitoring** - Track response times and resolution metrics
- **Knowledge base** - Find solutions to common customer issues
- **Customer satisfaction** - Log feedback and satisfaction scores
- **Support analytics** - Identify trends and improvement opportunities

### 📊 Business Intelligence & Reporting
- **Custom dashboards** - Query data for real-time insights
- **Activity tracking** - Monitor team productivity and customer interactions
- **Data export** - Extract CRM data for external analysis
- **Trend analysis** - Identify patterns in sales, support, and customer data
- **Executive reporting** - Generate summaries for stakeholder meetings

### 🔄 Workflow Automation
- **Data synchronization** - Keep CRM data in sync with other systems
- **Bulk updates** - Modify multiple records simultaneously
- **Scheduled tasks** - Automate routine data maintenance
- **Integration workflows** - Connect CRM with email, calendar, and more
- **Custom triggers** - Execute actions based on CRM events

---

## ✨ Key Features

<table>
<tr>
<td width="50%">

### 🔐 **Enterprise-Grade Security**
- OAuth2 authentication flow
- Automatic token refresh
- CSRF protection
- Encrypted credential storage
- HTTPS API communication

### 📊 **Complete CRM Operations**
- Create, read, update, delete (CRUD)
- Advanced filtering & search
- Sorting & pagination
- Bulk operations
- Real-time data sync

</td>
<td width="50%">

### 🤖 **AI-Native Integration**
- Natural language queries
- Context-aware responses
- Conversational CRM management
- Multi-step workflows
- Intelligent data analysis

### ⚡ **Developer-Friendly**
- Zero configuration setup
- TypeScript support
- Auto port detection
- Built-in OAuth dashboard
- Comprehensive error handling

</td>
</tr>
</table>

---

## 📦 Supported CRM Data Tables

<table>
<tr>
<td width="33%">

**Sales & Revenue**
- 🏢 `accounts` - Companies/Organizations
- 👤 `contacts` - Individual People
- 💰 `opportunities` - Sales Deals
- 📦 `products` - Product Catalog
- 💵 `payments` - Payment Records
- 📄 `invoices` - Invoices & Quotes (use opportunity's `record_type` field)

</td>
<td width="33%">

**Operations & Projects**
- 🎯 `projects` - Project Management
- 🎫 `tickets` - Support Cases
- ⏱️ `timesheet` - Time Tracking
- 📋 `activity` - Activity Logs
- 💱 `currency` - Currency Data

</td>
<td width="33%">

**Marketing & Admin**
- 📢 `campaigns` - Marketing Campaigns
- 👥 `users` - CRM Users
- 🎨 `objects` - Custom Objects
- 📊 `views` - Saved Views
- ⚙️ `menu` / `icon` - UI Config

</td>
</tr>
</table>

---

## 🚀 Quick Start Installation

### Prerequisites
- Node.js 18+ installed
- Claude Desktop, Cline, or any MCP-compatible AI application
- BROSH CRM account ([Sign up free](https://brosh.io))

### Option 1: Claude Desktop (Recommended)

**Step 1:** Install the package
```bash
npm install -g brosh-crm-mcp
```

**Step 2:** Configure Claude Desktop

You can copy the sample config file provided in this repository: `claude_desktop_config.json`

Add to your config file:

<details>
<summary><b>Windows</b> - Click to expand</summary>

File location: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "brosh-crm": {
      "command": "npx",
      "args": ["brosh-crm-mcp"],
      "env": {
        "BROSH_BASE_URL": "https://app.brosh.io",
        "BROSH_SOURCE": "mcp"
      }
    }
  }
}
```
</details>

<details>
<summary><b>macOS</b> - Click to expand</summary>

File location: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "brosh-crm": {
      "command": "npx",
      "args": ["brosh-crm-mcp"],
      "env": {
        "BROSH_BASE_URL": "https://app.brosh.io",
        "BROSH_SOURCE": "mcp"
      }
    }
  }
}
```
</details>

**Step 3:** Restart Claude Desktop

### Option 2: VS Code with Cline Extension

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "brosh-crm": {
      "command": "npx",
      "args": ["brosh-crm-mcp"],
      "env": {
        "BROSH_BASE_URL": "https://app.brosh.io",
        "BROSH_SOURCE": "mcp"
      }
    }
  }
}
```

---

## 🎬 Getting Started (Authentication)

### Step 1: Start the MCP Server

The server starts automatically when you launch your MCP client (Claude Desktop, Cline, etc.).

### Step 2: Authenticate with BROSH CRM

In your AI assistant, say:
```
"Start BROSH CRM authentication"
```

Or use the tool directly:
```
Use the brosh_start_oauth tool
```

### Step 3: Complete OAuth Flow

1. **Open the OAuth URL** provided by the assistant (http://localhost:3000/)
2. **Click the login button** on the status dashboard
3. **Sign in** with your BROSH CRM credentials
4. **Authorize** the application to access your CRM data
5. **You're ready!** The assistant confirms successful authentication

### Step 4: Start Using CRM Commands

Now you can ask your AI assistant natural language queries:

```
"Show me all contacts created this month"
"Find high-value opportunities in my sales pipeline"
"Create a new contact for John Smith at Acme Corp"
"What are my open support tickets?"
"Update the status of opportunity #123 to 'Closed Won'"
```

---

## 📚 Comprehensive Tool Reference

### 🔑 Authentication & Session Management

| Tool | Purpose | Example Use |
|------|---------|-------------|
| `brosh_start_oauth` | Begin OAuth2 authentication | First-time setup |
| `brosh_refresh_token` | Manually refresh access token | Token expired errors |
| `brosh_validate_token` | Check authentication status | Verify connection |
| `brosh_logout` | Clear stored credentials | Switch accounts |

### 📊 Data Query & Search Operations

| Tool | Purpose | Key Features |
|------|---------|--------------|
| `brosh_find_records` | Advanced record search | Filtering, sorting, pagination, wildcards |
| `brosh_get_records` | Fetch by specific IDs | Bulk retrieval, field selection |

### ✏️ Data Management Operations

| Tool | Purpose | Capabilities |
|------|---------|--------------|
| `brosh_create_records` | Add new records | Bulk creation, validation |
| `brosh_update_records` | Modify existing records | Partial updates, bulk edits |
| `brosh_delete_records` | Remove records | Soft delete (30-day recovery) |

---

## 💡 Practical Usage Examples

### 🔍 Sales Intelligence & Lead Management

**Find hot leads from this quarter:**
```typescript
brosh_find_records({
  table_name: "contacts",
  filter: {
    where: {
      lead_score: { ">": 80 },
      created_date: { ">=": "2026-04-01" }
    }
  },
  sort: [{ field: "lead_score", direction: "DESC" }],
  limit: 20
})
```

**Search for contacts at specific company:**
```typescript
brosh_find_records({
  table_name: "contacts",
  filter: {
    search: "Acme%"  // Wildcard search for company name
  },
  fields: ["id", "name", "email", "phone", "company"]
})
```

**Track sales pipeline by stage:**
```typescript
brosh_find_records({
  table_name: "opportunities",
  filter: {
    where: {
      stage: "Proposal Sent",
      amount: { ">": 10000 }
    }
  },
  sort: [{ field: "expected_close_date", direction: "ASC" }]
})
```

### ➕ Customer Data Management

**Create new contact with complete profile:**
```typescript
brosh_create_records({
  table_name: "contacts",
  records: [
    {
      name: "Sarah Johnson",
      email: "sarah.johnson@example.com",
      phone: "+1-555-0123",
      company: "Tech Innovations Inc",
      title: "VP of Sales",
      lead_source: "Website",
      lead_score: 85,
      tags: ["enterprise", "decision-maker"]
    }
  ]
})
```

**Bulk import contacts:**
```typescript
brosh_create_records({
  table_name: "contacts",
  records: [
    { name: "Contact 1", email: "c1@example.com" },
    { name: "Contact 2", email: "c2@example.com" },
    { name: "Contact 3", email: "c3@example.com" }
    // ... up to hundreds of contacts
  ]
})
```

### ✏️ Data Updates & Enrichment

**Update contact with meeting notes:**
```typescript
brosh_update_records({
  table_name: "contacts",
  records: [
    {
      id: 123,
      last_contact_date: "2026-05-14",
      notes: "Discussed Q2 expansion plans. Follow up in 2 weeks.",
      next_action: "Send proposal",
      lead_score: 90
    }
  ]
})
```

**Update opportunity stage and amount:**
```typescript
brosh_update_records({
  table_name: "opportunities",
  records: [
    {
      id: 456,
      stage: "Negotiation",
      amount: 75000,
      probability: 75,
      expected_close_date: "2026-06-30"
    }
  ]
})
```

**Bulk status update for campaign contacts:**
```typescript
brosh_update_records({
  table_name: "contacts",
  records: [
    { id: 1, campaign_status: "Engaged" },
    { id: 2, campaign_status: "Engaged" },
    { id: 3, campaign_status: "Engaged" }
  ]
})
```

### 📊 Business Analytics & Reporting

**Get monthly sales summary:**
```typescript
brosh_find_records({
  table_name: "opportunities",
  filter: {
    where: {
      stage: "Closed Won",
      close_date: { ">=": "2026-05-01", "<=": "2026-05-31" }
    }
  },
  fields: ["id", "name", "amount", "close_date", "owner"]
})
```

**Analyze support ticket trends:**
```typescript
brosh_find_records({
  table_name: "tickets",
  filter: {
    where: {
      status: "Open",
      priority: { "in": ["High", "Critical"] }
    }
  },
  sort: [{ field: "created_date", direction: "ASC" }]
})
```

**Track campaign performance:**
```typescript
brosh_find_records({
  table_name: "campaigns",
  filter: {
    where: {
      status: "Active",
      start_date: { ">=": "2026-01-01" }
    }
  },
  fields: ["id", "name", "budget", "leads_generated", "roi"]
})
```

### 🎫 Customer Support Workflows

**Create support ticket:**
```typescript
brosh_create_records({
  table_name: "tickets",
  records: [
    {
      subject: "Login Issues - Enterprise Account",
      description: "Customer unable to access dashboard",
      priority: "High",
      status: "Open",
      contact_id: 789,
      category: "Technical Support"
    }
  ]
})
```

**Update ticket resolution:**
```typescript
brosh_update_records({
  table_name: "tickets",
  records: [
    {
      id: 321,
      status: "Resolved",
      resolution: "Password reset completed. User access restored.",
      resolved_date: "2026-05-14T15:30:00Z"
    }
  ]
})
```

### 🗑️ Data Cleanup & Management

**Archive old opportunities:**
```typescript
brosh_delete_records({
  table_name: "opportunities",
  ids: [101, 102, 103, 104]
})
// Note: Records move to recycle bin for 30 days
```

**Remove duplicate contacts:**
```typescript
brosh_delete_records({
  table_name: "contacts",
  ids: [555, 556]  // IDs identified as duplicates
})
```

### 📄 Invoice & Quote Management

**Create a quote for a potential customer:**
```typescript
brosh_create_records({
  table_name: "invoices",
  records: [
    {
      record_type: "quote",  // Use "quote" for quotes, "invoice" for invoices
      customer_id: 123,
      quote_number: "Q-2026-001",
      issue_date: "2026-05-17",
      valid_until: "2026-06-17",
      items: [
        {
          product_id: 456,
          description: "Professional Services Package",
          quantity: 1,
          unit_price: 5000,
          total: 5000
        }
      ],
      subtotal: 5000,
      tax: 500,
      total: 5500,
      status: "Draft"
    }
  ]
})
```

**Convert a quote to an invoice:**
```typescript
brosh_update_records({
  table_name: "invoices",
  records: [
    {
      id: 789,
      record_type: "invoice",  // Change from "quote" to "invoice"
      invoice_number: "INV-2026-001",
      status: "Sent",
      issue_date: "2026-05-17",
      due_date: "2026-06-17"
    }
  ]
})
```

**Find all unpaid invoices:**
```typescript
brosh_find_records({
  table_name: "invoices",
  filter: {
    where: {
      record_type: "invoice",
      status: { "in": ["Sent", "Overdue"] },
      due_date: { "<": "2026-05-17" }
    }
  },
  sort: [{ field: "due_date", direction: "ASC" }],
  fields: ["id", "invoice_number", "customer_id", "total", "due_date", "status"]
})
```

**Track pending quotes:**
```typescript
brosh_find_records({
  table_name: "invoices",
  filter: {
    where: {
      record_type: "quote",
      status: { "in": ["Sent", "Pending"] }
    }
  },
  sort: [{ field: "valid_until", direction: "ASC" }]
})
```

---

## ⚙️ Advanced Configuration

### Environment Variables

Customize server behavior with these optional environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BROSH_BASE_URL` | `https://app.brosh.io` | BROSH CRM API endpoint |
| `BROSH_SOURCE` | `mcp` | Integration identifier |
| `BROSH_REDIRECT_URI` | Auto-generated | OAuth callback URL |
| `BROSH_CLIENT_ID` | Auto-generated | OAuth client identifier |
| `BROSH_CLIENT_SECRET` | Auto-generated | OAuth client secret |
| `BROSH_SKIP_STATE_VALIDATION` | `false` | Skip CSRF validation (dev only) |

### Generated Files

The server creates these files in your working directory:

```
📁 Project Directory
  ├── .brosh-client-id         # Auto-generated OAuth client ID
  ├── .brosh-client-secret     # Auto-generated OAuth secret
  ├── .brosh-tokens.json       # Access & refresh tokens
  └── .brosh-oauth-state.json  # CSRF protection state
```

⚠️ **Security Notice:** Add these files to `.gitignore`:

```gitignore
.brosh-*
```

### Custom OAuth Configuration

For advanced users who need custom OAuth settings:

```json
{
  "mcpServers": {
    "brosh-crm": {
      "command": "npx",
      "args": ["brosh-crm-mcp"],
      "env": {
        "BROSH_BASE_URL": "https://app.brosh.io",
        "BROSH_SOURCE": "mcp",
        "BROSH_CLIENT_ID": "your-custom-client-id",
        "BROSH_CLIENT_SECRET": "your-custom-secret",
        "BROSH_REDIRECT_URI": "http://localhost:3000/oauth/callback"
      }
    }
  }
}
```

---

## 🎨 OAuth Status Dashboard

Access the built-in web dashboard at **http://localhost:3000/**

### Features:
- ✅ **Live authentication status** - See if you're connected
- 👤 **User profile display** - View logged-in user info
- ⏱️ **Token expiration** - Monitor token validity
- 🔄 **Auto-refresh indicator** - Track automatic token renewal
- 🔐 **Login/Logout controls** - Manage authentication
- 📊 **Session information** - Debug connection issues

### Port Management

🔌 **Automatic port detection** - If port 3000 is busy, the server automatically tries:
- Port 3001
- Port 3002
- ... up to 10 alternative ports

The terminal output shows which port is actually being used:
```
✅ OAuth callback server listening on http://localhost:3001/oauth/callback
   ℹ️  Using port 3001 (default port 3000 was busy)
```

---

## 🔒 Enterprise Security Features

### OAuth 2.0 Authentication
- ✅ Industry-standard authorization protocol
- ✅ No password sharing with third-party applications
- ✅ Granular permission scopes
- ✅ Revocable access tokens

### CSRF Protection
- ✅ State parameter validation
- ✅ Time-limited authentication requests (10 minutes)
- ✅ Single-use authorization codes

### Data Security
- ✅ HTTPS-only API communication
- ✅ Encrypted token storage
- ✅ Automatic token rotation
- ✅ Secure credential file permissions

### Access Management
- ✅ Token expiration (60 minutes)
- ✅ Auto-refresh before expiration
- ✅ Manual logout capability
- ✅ Session timeout protection

---

## 🔧 Troubleshooting Guide

### Common Issues & Solutions

<details>
<summary><b>❌ "Port 3000 already in use"</b></summary>

**Solution:** The server automatically finds an available port. Check terminal output:
```
✅ OAuth callback server listening on http://localhost:3001/oauth/callback
```
Use the displayed port number.

</details>

<details>
<summary><b>❌ "Authentication Failed" or "Token Expired"</b></summary>

**Steps to resolve:**
1. Visit http://localhost:3000/ (or your actual port)
2. Click "Logout" to clear old tokens
3. Click "Login to BROSH CRM"
4. Complete authentication flow again

**For manual refresh:**
```
Use brosh_refresh_token tool
```

</details>

<details>
<summary><b>❌ "ERR_SSL_PROTOCOL_ERROR" in browser</b></summary>

**Cause:** Browser attempting HTTPS connection

**Solution:** Use `http://` (not `https://`):
- ✅ Correct: `http://localhost:3000`
- ❌ Wrong: `https://localhost:3000`

The local OAuth server uses HTTP only.

</details>

<details>
<summary><b>❌ "Invalid redirect_uri" error</b></summary>

**Cause:** Redirect URI mismatch

**Solution:**
1. Check actual port in terminal output
2. Verify OAuth callback URL matches
3. Restart server if needed
4. Re-authenticate

</details>

<details>
<summary><b>❌ "MCP server tools not showing up"</b></summary>

**Checklist:**
- [ ] Package installed: `npm list -g brosh-crm-mcp`
- [ ] Config file syntax valid (check JSON)
- [ ] Claude Desktop / Cline restarted
- [ ] No errors in MCP server logs

**Reload config:**
- Claude Desktop: Restart application
- VS Code: Reload window (Ctrl/Cmd + R)

</details>

<details>
<summary><b>❌ "Cannot find module" errors</b></summary>

**Solution:**
```bash
# Reinstall dependencies
npm install -g brosh-crm-mcp

# Or use npx to fetch latest
npx brosh-crm-mcp
```

</details>

<details>
<summary><b>❌ Rate limiting or API errors</b></summary>

**Tips:**
- Use pagination for large datasets (`page_size`, `limit`)
- Implement delays between bulk operations
- Check BROSH CRM API status
- Verify your account permissions

</details>

### Debug Mode

Enable verbose logging:

```json
{
  "mcpServers": {
    "brosh-crm": {
      "command": "npx",
      "args": ["brosh-crm-mcp"],
      "env": {
        "DEBUG": "brosh:*",
        "NODE_ENV": "development"
      }
    }
  }
}
```

### Getting Help

🆘 **Need assistance?**

1. **GitHub Issues:** [Report a bug or request feature](https://github.com/Ben-Ford-z/brosh-crm-mcp/issues)
2. **BROSH Support:** support@brosh.io
3. **Documentation:** [BROSH API Docs](https://www.brosh.io/page/api-oauth2-documentation)
4. **Community:** [Model Context Protocol Forum](https://modelcontextprotocol.io)

---

## 🚀 Performance & Best Practices

### Optimization Tips

**✅ DO:**
- Use field selection to return only needed data
- Implement pagination for large result sets
- Cache frequently accessed data
- Use bulk operations for multiple records
- Filter queries to reduce payload size

**❌ DON'T:**
- Request all fields when you only need a few
- Fetch thousands of records without pagination
- Make excessive API calls in loops
- Store sensitive data in plain text
- Share OAuth tokens across applications

### Example: Efficient Data Retrieval

```typescript
// ❌ Inefficient - Gets all fields for all contacts
brosh_find_records({
  table_name: "contacts",
  limit: 1000
})

// ✅ Efficient - Only gets needed fields with pagination
brosh_find_records({
  table_name: "contacts",
  fields: ["id", "name", "email"],
  page_size: 50,
  page: 1
})
```

---

---

## 📊 Feature Comparison Matrix

| Feature | BROSH CRM MCP | Traditional CRM UI | Direct API | Other Integrations |
|---------|:-------------:|:------------------:|:----------:|:------------------:|
| Natural Language Interface | ✅ | ❌ | ❌ | ⚠️ Limited |
| Zero Configuration Setup | ✅ | ❌ | ❌ | ❌ |
| OAuth2 Security | ✅ | ✅ | ⚠️ Manual | ✅ |
| Auto Token Refresh | ✅ | ✅ | ❌ | ⚠️ Varies |
| All CRM Tables Access | ✅ | ✅ | ✅ | ⚠️ Limited |
| Bulk Operations | ✅ | ⚠️ Limited | ✅ | ⚠️ Limited |
| Advanced Filtering | ✅ | ✅ | ✅ | ⚠️ Basic |
| Real-time Status Dashboard | ✅ | ✅ | ❌ | ❌ |
| TypeScript Support | ✅ | ❌ | ⚠️ Optional | ⚠️ Varies |
| Conversational Queries | ✅ | ❌ | ❌ | ❌ |
| Multi-step Workflows | ✅ | ⚠️ Manual | ❌ | ⚠️ Limited |
| Context-Aware Operations | ✅ | ❌ | ❌ | ❌ |
| Learning Curve | 🟢 Low | 🔴 High | 🔴 High | 🟡 Medium |

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Is this official software from BROSH?</b></summary>

**Yes!** This is the **official** Model Context Protocol (MCP) server for BROSH AI CRM, developed in collaboration with BROSH AI. It integrates seamlessly with BROSH AI CRM's OAuth2 API and is fully supported.

</details>

<details>
<summary><b>Do I need a BROSH CRM account?</b></summary>

**Yes.** You need an active BROSH CRM account to authenticate and access your CRM data. Sign up at [brosh.io](https://brosh.io) if you don't have one.

</details>

<details>
<summary><b>Is my data secure?</b></summary>

**Yes.** The MCP server uses:
- Industry-standard OAuth2 authentication
- HTTPS for all API communication
- Local token storage (never shared with third parties)
- CSRF protection
- Automatic token rotation

Your BROSH CRM credentials are never stored or transmitted by the MCP server.

</details>

<details>
<summary><b>What AI assistants are compatible?</b></summary>

Any application that supports the Model Context Protocol (MCP), including:
- ✅ Claude Desktop (Anthropic)
- ✅ Cline (VS Code Extension)
- ✅ Custom MCP clients
- ✅ Future MCP-compatible applications

</details>

<details>
<summary><b>Can I use this in production?</b></summary>

**Yes**, but with considerations:
- Test thoroughly in a development environment first
- Implement proper error handling
- Monitor API rate limits
- Backup your data regularly
- Review the MIT license terms

</details>

<details>
<summary><b>What's the rate limit?</b></summary>

Rate limits are determined by BROSH CRM's API policies. Contact BROSH support for specific limits on your account tier. The MCP server implements automatic retry logic for transient failures.

</details>

<details>
<summary><b>Can I contribute to this project?</b></summary>

**Absolutely!** Contributions are welcome:
- Report bugs via GitHub Issues
- Suggest features in GitHub Discussions
- Submit pull requests
- Improve documentation
- Share usage examples

See the [Contributing](#-development--contributing) section for details.

</details>

<details>
<summary><b>How do I report security issues?</b></summary>

**Do NOT** post security vulnerabilities in public issues. Instead:
1. Email: security@[project-domain]
2. Use GitHub's private vulnerability reporting
3. Provide detailed reproduction steps
4. Allow time for investigation and patching

</details>

<details>
<summary><b>Does this work offline?</b></summary>

**No.** The MCP server requires an internet connection to:
- Authenticate with BROSH CRM OAuth servers
- Make API requests to BROSH CRM
- Refresh access tokens

However, the OAuth status dashboard (http://localhost:3000/) works offline for viewing cached status.

</details>

<details>
<summary><b>What Node.js version do I need?</b></summary>

**Node.js 18 or higher** is required. Check your version:
```bash
node --version
```

To update Node.js, visit [nodejs.org](https://nodejs.org/).

</details>

<details>
<summary><b>Can I use this with multiple BROSH accounts?</b></summary>

Yes, but not simultaneously. To switch accounts:
1. Use the `brosh_logout` tool
2. Re-authenticate with `brosh_start_oauth`
3. Login with different BROSH credentials

</details>

<details>
<summary><b>Is there a usage cost?</b></summary>

The MCP server itself is **free and open-source** (MIT License). However:
- BROSH CRM may have subscription costs
- Claude AI may have usage costs
- Normal internet data charges apply

</details>

---

## 🎯 Use Case: Complete Sales Workflow Example

Here's a real-world example of using BROSH CRM MCP for a complete sales cycle:

### 1️⃣ **Lead Discovery**
```
"Find all leads from technology companies created in the last 7 days with a lead score above 70"
```

### 2️⃣ **Lead Qualification**
```
"Update lead #456 with notes from discovery call: interested in enterprise plan, 50 employees, decision timeline Q3 2026"
```

### 3️⃣ **Opportunity Creation**
```
"Create a new opportunity for Acme Corp: Enterprise Plan, $50,000 annual value, expected close date June 30th"
```

### 4️⃣ **Pipeline Tracking**
```
"Show me all opportunities in the proposal stage worth more than $25,000"
```

### 5️⃣ **Deal Progression**
```
"Update opportunity #789 to 'Negotiation' stage, increase close probability to 75%, add note: waiting on legal review"
```

### 6️⃣ **Win Analysis**
```
"Find all closed-won deals from this quarter and show the average deal size"
```

**Result:** This entire workflow happens conversationally with your AI assistant - no forms, no clicking, no context switching! 🎉

---

## 👥 Who Should Use This?

### 🎯 Sales Teams & Account Executives
- Quickly access customer data during calls
- Update deal stages and notes instantly
- Track sales pipeline without switching apps
- Generate reports through natural conversation

### 💼 Customer Success Managers
- Monitor customer health scores
- Track support ticket resolution
- Update account information in real-time
- Analyze customer engagement patterns

### 📊 Business Owners & Executives
- Ask questions about business metrics
- Get instant CRM insights
- Generate executive summaries
- Make data-driven decisions faster

### 🎨 Marketing Professionals
- Segment customers for campaigns
- Track campaign performance
- Manage lead nurturing workflows
- Analyze marketing ROI

### 👨‍💻 Developers & Automation Engineers
- Build AI-powered CRM workflows
- Create custom integrations
- Automate repetitive tasks
- Develop internal tools

### 🔧 IT Administrators
- Manage user accounts
- Configure CRM settings
- Monitor system activity
- Ensure data security

---

## 🌟 Why Choose BROSH CRM MCP?

### vs. Traditional CRM Interfaces
- 💬 **Natural language** instead of clicking through menus
- ⚡ **Instant answers** instead of waiting for reports
- 🤖 **AI-powered insights** instead of manual analysis
- 🔄 **Conversational workflows** instead of form-filling

### vs. Other CRM Integrations
- 🚀 **Zero configuration** - Works out of the box
- 🔒 **Enterprise security** - OAuth2 + token encryption
- 📦 **Complete coverage** - Full CRUD for all tables
- 🎯 **Purpose-built** - Designed for MCP and AI assistants

### vs. Direct API Access
- 🛠️ **No coding required** - Natural language interface
- 📚 **Built-in best practices** - Pagination, error handling
- 🔐 **Managed authentication** - Auto token refresh
- 📖 **Rich documentation** - Examples and use cases

---

## 🛠️ Development & Contributing

### Local Development

```bash
# Clone repository
git clone https://github.com/Ben-Ford-z/brosh-crm-mcp.git
cd brosh-crm-mcp

# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode with auto-reload
npm run dev

# Test locally
npm link
```

### Project Structure

```
brosh-crm-mcp/
├── src/
│   └── index.ts          # Main MCP server implementation
├── dist/                 # Compiled JavaScript (generated)
├── .github/
│   └── workflows/
│       └── ci.yml        # CI/CD pipeline
├── README.md             # This file
├── CHANGELOG.md          # Version history
├── LICENSE               # MIT License
└── package.json          # Package configuration
```

### Contributing

We welcome contributions! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow TypeScript best practices
- Add tests for new features
- Update documentation
- Follow semantic versioning
- Write clear commit messages

---

## 📄 License & Legal

### License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

- [@modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk) - MIT License
- [axios](https://www.npmjs.com/package/axios) - MIT License
- [TypeScript](https://www.typescriptlang.org/) - Apache 2.0 License

### Disclaimer

This is the official MCP server for BROSH AI CRM. Use in accordance with BROSH AI CRM's terms of service. The authors are not responsible for data loss, security issues, or API misuse. Always backup your data and test in a development environment first.

---

## 🔗 Resources & Links

### Official Documentation
- 📚 [BROSH CRM Website](https://brosh.io)
- 📖 [BROSH API Documentation](https://www.brosh.io/page/api-oauth2-documentation)
- 🤖 [Model Context Protocol](https://modelcontextprotocol.io)
- 💬 [Claude AI](https://claude.ai)

### Package Links
- 📦 [npm Package](https://www.npmjs.com/package/brosh-crm-mcp)
- 💻 [GitHub Repository](https://github.com/Ben-Ford-z/brosh-crm-mcp)
- 🐛 [Issue Tracker](https://github.com/Ben-Ford-z/brosh-crm-mcp/issues)
- 📝 [Changelog](CHANGELOG.md)

### Community & Support
- 💬 **BROSH Support:** support@brosh.io
- 🐛 **Report Issues:** [GitHub Issues](https://github.com/Ben-Ford-z/brosh-crm-mcp/issues)
- 💡 **Feature Requests:** [GitHub Discussions](https://github.com/Ben-Ford-z/brosh-crm-mcp/discussions)
- 📣 **Announcements:** Watch the repository for updates

### Related Projects
- [Claude Desktop](https://claude.ai/desktop) - AI assistant for desktop
- [Cline](https://github.com/cline/cline) - VS Code AI extension
- [Model Context Protocol](https://github.com/modelcontextprotocol) - MCP specification

---

## 🏷️ Keywords & Topics

**AI & Machine Learning:** artificial intelligence, claude ai, ai assistant, conversational ai, natural language processing, llm integration, ai automation, chatbot, intelligent assistant

**CRM & Sales:** customer relationship management, crm software, sales automation, lead management, pipeline management, customer data, contact management, opportunity tracking, sales intelligence

**Integration & APIs:** rest api, oauth2, api integration, mcp server, model context protocol, sdk, web services, api client, automation platform

**Business Tools:** business intelligence, workflow automation, data management, productivity tools, enterprise software, saas integration, business automation

**Development:** typescript, node.js, npm package, open source, developer tools, cli tool, backend integration

---

<div align="center">

### ⭐ Star This Repository

If you find this tool useful, please consider giving it a star on GitHub!

**Made with ❤️ for the AI + CRM community**

[⬆ Back to Top](#-brosh-crm-mcp-server)

</div>

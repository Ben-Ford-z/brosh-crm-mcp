# Publishing Guide

This guide explains how to publish the BROSH CRM MCP package to GitHub and npm.

## Prerequisites

1. **GitHub Account** - Create a repository at https://github.com/new
2. **npm Account** - Sign up at https://www.npmjs.com/signup
3. **Git** - Install from https://git-scm.com/
4. **Node.js** - Install from https://nodejs.org/ (v18 or higher)

## Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `brosh-crm-mcp`
3. Description: "Model Context Protocol server for BROSH AI CRM"
4. Choose Public or Private
5. **Don't** initialize with README (we already have one)
6. Click "Create repository"

## Step 2: Update package.json

Replace `Ben-Ford-z` in `package.json` with your GitHub username:

```json
"repository": {
  "type": "git",
  "url": "https://github.com/Ben-Ford-z/brosh-crm-mcp.git"
}
```

Also update the same in `README.md`.

## Step 3: Push to GitHub

From the `brosh-crm-mcp` directory:

```bash
# Initialize git repository
git init

# Add all files
git add .

# Commit
git commit -m "Initial release v1.0.0"

# Add remote (replace Ben-Ford-z with your GitHub username)
git remote add origin https://github.com/Ben-Ford-z/brosh-crm-mcp.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## Step 4: Build the Package

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build
```

This creates the `dist/` folder with compiled JavaScript.

## Step 5: Test Locally

Before publishing, test the package locally:

```bash
# Create a link
npm link

# In another project, test it
npm link brosh-crm-mcp

# Run the server
npx brosh-crm-mcp
```

## Step 6: Publish to npm

```bash
# Login to npm (first time only)
npm login

# Publish the package
npm publish
```

If the package name is already taken, you can:
- Choose a different name in `package.json`
- Or publish under a scope: `@your-username/brosh-crm-mcp`

### Publishing Under a Scope

In `package.json`:
```json
{
  "name": "@your-username/brosh-crm-mcp",
  ...
}
```

Then publish with:
```bash
npm publish --access public
```

## Step 7: Create GitHub Release

1. Go to your repository on GitHub
2. Click "Releases" → "Create a new release"
3. Tag version: `v1.0.0`
4. Release title: `v1.0.0 - Initial Release`
5. Copy content from CHANGELOG.md
6. Click "Publish release"

This triggers the GitHub Actions workflow to auto-publish to npm.

## Step 8: Set up npm Token for GitHub Actions (Optional)

To enable automatic publishing on releases:

1. Get npm token:
   - Go to https://www.npmjs.com/settings/Ben-Ford-z/tokens
   - Click "Generate New Token" → "Classic Token"
   - Select "Automation"
   - Copy the token

2. Add to GitHub Secrets:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `NPM_TOKEN`
   - Value: paste the npm token
   - Click "Add secret"

Now when you create a new release on GitHub, it automatically publishes to npm!

## Updating the Package

### For bug fixes (1.0.0 → 1.0.1)
```bash
npm version patch
git push && git push --tags
npm publish
```

### For new features (1.0.0 → 1.1.0)
```bash
npm version minor
git push && git push --tags
npm publish
```

### For breaking changes (1.0.0 → 2.0.0)
```bash
npm version major
git push && git push --tags
npm publish
```

## Making the Package Easy to Find

1. **Add topics on GitHub:**
   - Go to repository → Settings → Topics
   - Add: `mcp`, `model-context-protocol`, `brosh`, `crm`, `oauth2`, `claude-ai`, `typescript`

2. **Update npm keywords** in `package.json` (already done)

3. **Create shields/badges** in README.md (already done)

4. **Share on:**
   - Model Context Protocol community
   - BROSH AI social media
   - Developer forums

## Support Users

Monitor these for issues and questions:
- GitHub Issues: https://github.com/Ben-Ford-z/brosh-crm-mcp/issues
- npm package page: https://www.npmjs.com/package/brosh-crm-mcp
- MCP community channels

## Maintenance Checklist

- [ ] Update dependencies regularly (`npm outdated`, `npm update`)
- [ ] Review and respond to issues on GitHub
- [ ] Test with latest Node.js versions
- [ ] Update documentation as needed
- [ ] Keep CHANGELOG.md current
- [ ] Monitor npm download statistics

## Useful Commands

```bash
# Check package size before publishing
npm pack --dry-run

# View what will be published
npm publish --dry-run

# Check for outdated dependencies
npm outdated

# Update dependencies
npm update

# Security audit
npm audit
npm audit fix
```

## Resources

- [npm Publishing Guide](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Model Context Protocol](https://modelcontextprotocol.io)

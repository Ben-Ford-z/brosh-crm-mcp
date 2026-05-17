# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-14

### Added
- Initial release of BROSH CRM MCP server
- OAuth2 authentication with auto-generated client credentials
- Full CRUD operations for all CRM tables (accounts, contacts, opportunities, etc.)
- Auto token refresh mechanism
- Built-in OAuth callback server with status dashboard
- Dynamic port handling (auto-finds available ports)
- TypeScript support with full type definitions
- Comprehensive error handling and retry logic
- Security features: CSRF protection, token encryption
- Support for filtering, sorting, and pagination
- Compatible with Claude Desktop, Cline, and other MCP clients

### Security
- OAuth state parameter for CSRF protection
- Secure local token storage
- HTTPS API communication

## [Unreleased]

### Planned
- Custom object support
- Webhook integration
- Batch operations optimization
- Extended filtering capabilities

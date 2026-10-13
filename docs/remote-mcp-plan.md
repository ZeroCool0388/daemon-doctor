# Daemon Doctor: remote MCP over the relay

Goal: a cloud MCP client (Grok Bot) talks directly to Daemon Doctor on the Mac via the Cloudflare relay. No inbound ports on the Mac.

## Relay (Worker + Durable Object)
- `POST /v1/macs/<mac_id>/mcp` — Streamable HTTP MCP endpoint (JSON-RPC over POST, JSON responses; `GET` returns 405; support `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`). Mcp-Session-Id header optional/echoed.
- Auth: `Authorization: Bearer <token>`. DO stores SHA-256 of token only. Constant-time compare. 401 otherwise.
- `GET /v1/macs/<mac_id>/mcp-link` (WebSocket upgrade, auth with Mac's existing device credential or the link secret) — Mac keeps an outbound WebSocket to the DO (hibernation API). DO forwards each JSON-RPC request with an id, waits for the reply (timeout ~15 s).
- Mac offline / timeout: return a JSON-RPC result with isError tool content "Mac unreachable, last seen <ISO time>" (for tools/call), or error for other methods. DO records last_seen on every message/ping.
- Token registration: `PUT /v1/macs/<mac_id>/mcp-token` authenticated by the Mac's link credential, body = token hash. Rotation replaces it.
- Zero cost: free Workers + DO (SQLite-backed) only.

## Mac (Go)
- New `daemon-doctor mcp-token` command: generates 32 random bytes (base64url), registers hash with relay, prints token once.
- Daemon runs an MCP link goroutine when `relay.url` is set — independent of phone pairing (registers its own mac_id + link secret if not paired). Reconnects with backoff; heartbeat.
- Requests dispatched to the existing MCP server/tool handlers (same code path as stdio `daemon-doctor mcp`), so run_fix keeps single-use offers, allowlist, re-check, repeated-failure lockout, and requires `control.allow_fixes`.
- Config: `relay.mcp_link: true` (default false).

## Tests
- Relay vitest: auth (missing/bad/good token), initialize/tools/list, forwarding round trip, offline timeout message with last_seen.
- Go: token generation/hash, link dispatch with fake WebSocket, reconnect.

## Docs
README section "Remote MCP", neutral wording, security notes (token is a full-access credential to read status and request allowlisted fixes; rotate with `mcp-token`).

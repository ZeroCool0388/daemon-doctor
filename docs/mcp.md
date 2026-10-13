# Use with Cursor, Codex or Claude Desktop

Daemon Doctor provides five local MCP tools: `list_services`,
`get_service_details`, `recent_events`, `list_offered_fixes` and `run_fix`.
The official Go MCP SDK serves them over stdio. Live tools talk to the
already-running daemon through a private Unix socket; no HTTP listener,
cloud API or LLM call is added to the monitor.

## Build and try the demo

```sh
go build -o bin/daemon-doctor ./cmd/daemon-doctor
```

Use the absolute path to that binary in your client configuration. The examples
below use `/absolute/path/to/daemon-doctor` as a placeholder.

`mcp --demo` needs no local config, socket, accounts, keys, network or Mac.
It uses the same fictional services, checks, rules and fake controller as the
terminal replay. It begins with an offered force restart of Example Desktop
App. `list_services` advances its scripted scenes; other reads leave the
fake clock alone. Later scenes cover network loss/recovery, an unwatched CPU
hog and three bridge incidents. Offers expire against this fake clock.

Ask the client to list offered fixes, choose the desktop-app offer, then run
that exact offer. The fake controller repairs it and the result says `Fixed`.
A second call refuses replay. Restarting the MCP demo starts a fresh replay.
An offered restart of the stopped Example Mail has no launcher in this demo;
its recheck returns `Didn't work`. Nothing on the real machine is signalled.
Demo fixes are enabled automatically because their controller is fake.

### Cursor

Add this entry to `.cursor/mcp.json` for the project, or `~/.cursor/mcp.json`
for your user, merging with existing entries:

```json
{
  "mcpServers": {
    "daemon-doctor-demo": {
      "command": "/absolute/path/to/daemon-doctor",
      "args": ["mcp", "--demo"]
    }
  }
}
```

### Claude Desktop

Use the same `mcpServers` entry in Claude Desktop's configuration file
(on macOS, `~/Library/Application Support/Claude/claude_desktop_config.json`).
Use the client's developer/settings controls to reload the configuration.

### Codex

Merge into `~/.codex/config.toml`:

```toml
[mcp_servers.daemon_doctor_demo]
command = "/absolute/path/to/daemon-doctor"
args = ["mcp", "--demo"]

[mcp_servers.daemon_doctor_demo.tools.run_fix]
approval_mode = "prompt"
```

The equivalent registration command is:

```sh
codex mcp add daemon_doctor_demo -- /absolute/path/to/daemon-doctor mcp --demo
```

## Connect to the running monitor

The daemon and client must both use the new binary and the same config.
Replace demo arguments with `["mcp"]`, or with
`["mcp", "--config", "/absolute/path/to/config.yaml"]` for a custom config.
The MCP process reads config only; it does not open the log for writing,
create a phone identity or start a second monitor.

Default daemon settings:

```yaml
control:
  enabled: true
  allow_fixes: false
```

The socket is `<state_dir>/control/control.sock`; when `state_dir` is omitted,
that is `control/control.sock` beside the config. Its dedicated directory must
be owned by the current user with mode `0700`; the socket is mode `0600`.
Unix socket path lengths are limited by the OS; use a short state directory.
The daemon refuses to overwrite regular files, symlinks or an active socket.
It removes its own socket on clean shutdown and replaces stale sockets after
unclean shutdown. Disabling `control.enabled` disables this interface.

Read tools return the last completed monitor cycle and its `sampled_at` time.
They do not sample processes or advance failure streaks. Service rows include
check outcomes and open alerts. Events are returned newest first from the
current and rotated log, default 20 and maximum 50. Secret-looking strings
are blanked using the existing log redactor; this is not a guarantee that
all personal data is removed. The selected LLM client receives local health
and log text, so use a client you trust with those data.

A missing socket produces a clear daemon/control-unavailable tool error.
An initial request before the first successful cycle reports that no check
has completed. `list_offered_fixes` includes the daemon's `fixes_enabled` flag;
the MCP client's separate execution flag must also be enabled to run one.

## Enable live fixes only with per-call approval

**MCP annotations are advisory. There is no standard `needs-confirmation`
annotation that guarantees a prompt.** The server cannot verify that a person
clicked Allow. The host client must enforce approval for every `run_fix` call.
Do not enable live fixes in a client with automatic approval or unrestricted
execution. For protection independent of a client, use signed phone approvals.

To opt in, set `control.allow_fixes: true` in the daemon config and restart the
daemon using the new binary. Add `--allow-fixes` to the live MCP client's args.
Both gates are required. Leave the live configuration read-only until you have
verified the client's approval setting. For Codex, use:

```toml
[mcp_servers.daemon_doctor]
command = "/absolute/path/to/daemon-doctor"
args = ["mcp", "--allow-fixes"]

[mcp_servers.daemon_doctor.tools.run_fix]
approval_mode = "prompt"
```

Keep Cursor's MCP tool confirmation enabled and avoid auto-run for this tool.
In Claude Desktop, approve the individual offered fix without granting blanket
permission. Client policy and version affect the approval UI; verify it locally
with the demo before enabling live fixes.

The local socket trusts processes running as your user. It is not an isolation
boundary against malicious software already running under that account.

## Fix safeguards

- Only actions that the daemon actually offered from its local allowlist are
  accepted. No command text, shell, arbitrary arguments or unknown RPC methods.
- Each offer contains a random id, alert id, service id, fix id, message and
  expiry. Expiry is the existing ten-minute approval window.
- Acceptance rechecks the incident in the same daemon. Recovered incidents,
  host holds, changed allowlists and the existing three-incidents-in-an-hour
  rule withdraw offers. A withdrawn offer requires a fresh alert; it does not
  automatically renew. Offers from a previous daemon instance are unusable.
- Consume is serialized across processes and durably saved before execution.
  All alternative actions for the same alert burn together. Other offers for
  that service retire when an action is attempted. Failed/cancelled execution
  does not restore the token. Optional `service` must match before consume.
- Fixes use the existing controller, then recheck. Results include `fixed`,
  `message` and `detail`; a failed action is never reported as a successful fix.
- Accepted/refused local approvals and actual fix events record `source=mcp`.
  Phone and CLI fix events record their respective sources. The phone signing,
  pairing and relay protocol are unchanged.
- Requests and connections are bounded: 64 KiB request lines, 32 connections,
  a one-minute timeout and bounded event output. If a client loses its response
  after acceptance, execution may still have happened; inspect status/events
  before requesting any new action. Do not retry a consumed offer.

## Plan review and delivery

The original plan's local socket, stdio transport, allowlist and shared rule
engine fit the existing code. Implementation resolves four gaps: advisory
approval annotations, read calls changing monitor state, stale/alternative
offers surviving incident changes, and socket ownership/shutdown races.
The offer store lives in `internal/offers` to avoid a package cycle between
the doctor and control server. It uses a locked, atomic JSON snapshot in the
private control directory, independently of phone identity and nonces.

No new service charges are introduced by this interface. LLM client/account
charges remain whatever your selected client already requires.

## References

- [Official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk)
- [MCP tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations)
- [Cursor MCP configuration](https://cursor.com/docs/mcp)
- [Connect Claude Desktop to a local MCP server](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
- [Codex MCP configuration](https://developers.openai.com/codex/mcp)
- [Codex per-tool approval settings](https://developers.openai.com/codex/config-reference)

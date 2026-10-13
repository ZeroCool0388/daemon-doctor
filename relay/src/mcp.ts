// Remote MCP shares the per-Mac mailbox object. Only the Mac executes tools.
const LIMIT = 64 * 1024;
const HASH = /^[a-f0-9]{64}$/;
const TIMEOUT = 15_000;
type RPC = { jsonrpc: string; id?: string | number | null; method: string; params?: unknown };
type Pending = { ws: WebSocket; rpcID: string | number | null; finish: (reply?: unknown) => void };

export async function tokenHash(token: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function authenticated(request: Request, hash: string | undefined): Promise<boolean> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!/^Bearer [A-Za-z0-9_-]{43}$/.test(auth)) return false;
  const actual = await tokenHash(auth.slice(7));
  // Both values are fixed-size SHA-256 digests; compare without early exit.
  const expected = hash ?? "0".repeat(64);
  let diff = 0;
  for (let i = 0; i < 64; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0 && hash !== undefined;
}

async function body(request: Request): Promise<unknown> {
  if (Number(request.headers.get("Content-Length")) > LIMIT) throw new Error("body too large");
  const reader = request.body?.getReader();
  if (!reader) throw new Error("JSON required");
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > LIMIT) { await reader.cancel(); throw new Error("body too large"); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(bytes));
}

export class RemoteMCP {
  private readonly pending = new Map<string, Pending>();
  constructor(private readonly ctx: DurableObjectState) {}

  async fetch(route: string, request: Request): Promise<Response> {
    if (route === "mcp-link" && request.method === "PUT") {
      // First registration claims a random Mac id; subsequent registrations must
      // prove possession of the existing secret and cannot replace its hash.
      let parsed: unknown;
      try { parsed = await body(request); } catch { return new Response("invalid body", { status: 400 }); }
      const hash = (parsed as { secret_hash?: unknown } | null)?.secret_hash;
      if (typeof hash !== "string" || !HASH.test(hash)) return new Response("invalid hash", { status: 400 });
      const ok = await this.ctx.storage.transaction(async txn => {
        const stored = await txn.get<string>("mcp_link_hash");
        if (!await authenticated(request, stored ?? hash) || (stored !== undefined && stored !== hash)) return false;
        await txn.put("mcp_link_hash", hash);
        return true;
      });
      return ok ? Response.json({ registered: true }) : unauthorized();
    }
    const key = route === "mcp" ? "mcp_token_hash" : "mcp_link_hash";
    if (!await authenticated(request, await this.ctx.storage.get<string>(key))) return unauthorized();
    if (route === "mcp-token") {
      if (request.method !== "PUT") return method("PUT");
      let parsed: unknown;
      try { parsed = await body(request); } catch { return new Response("invalid body", { status: 400 }); }
      const hash = (parsed as { token_hash?: unknown } | null)?.token_hash;
      if (typeof hash !== "string" || !HASH.test(hash)) return new Response("invalid hash", { status: 400 });
      await this.ctx.storage.put("mcp_token_hash", hash);
      return Response.json({ registered: true });
    }
    if (route === "mcp-link") {
      if (request.method !== "GET") return method("GET, PUT");
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("upgrade required", { status: 426 });
      for (const old of this.ctx.getWebSockets("mcp")) {
        await this.closed(old);
        old.close(1000, "link replaced");
      }
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1], ["mcp"]);
      this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'));
      await this.ctx.storage.put("mcp_last_seen", new Date().toISOString());
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (request.method !== "POST") return method("POST");
    const session = request.headers.get("Mcp-Session-Id");
    const headers: Record<string, string> = session ? { "Mcp-Session-Id": session } : {};
    let rpc: RPC;
    try {
      const value = await body(request);
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
      rpc = value as RPC;
      if (rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string" ||
          (rpc.id !== undefined && typeof rpc.id !== "string" && typeof rpc.id !== "number" && rpc.id !== null)) throw new Error();
    } catch {
      return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid request" } }, { status: 400, headers });
    }
    const ws = this.ctx.getWebSockets("mcp").find(socket => socket.readyState === 1);
    const id = crypto.randomUUID();
    if (rpc.id === undefined) {
      if (ws) { try { ws.send(JSON.stringify({ id, request: rpc, deadline_unix_ms: Date.now() + 14_000 })); } catch { /* Notification has no reply. */ } }
      return new Response(null, { status: 202, headers });
    }
    if (this.pending.size >= 64) return Response.json({ jsonrpc: "2.0", id: rpc.id, error: { code: -32000, message: "Too many pending requests" } }, { headers });
    let response: unknown;
    if (ws) {
      response = await new Promise(resolve => {
        const timer = setTimeout(() => finish(), TIMEOUT);
        const finish = (reply?: unknown) => {
          clearTimeout(timer);
          this.pending.delete(id);
          resolve(reply);
        };
        this.pending.set(id, { ws, rpcID: rpc.id!, finish });
        try { ws.send(JSON.stringify({ id, request: rpc, deadline_unix_ms: Date.now() + 14_000 })); } catch { finish(); }
      });
    }
    if (response === undefined) {
      const message = `Mac unreachable, last seen ${await this.lastSeen(ws)}`;
      response = rpc.method === "tools/call"
        ? { jsonrpc: "2.0", id: rpc.id, result: { isError: true, content: [{ type: "text", text: message }] } }
        : { jsonrpc: "2.0", id: rpc.id, error: { code: -32000, message } };
    }
    return Response.json(response, { headers });
  }

  private async lastSeen(ws?: WebSocket): Promise<string> {
    const automatic = ws && this.ctx.getWebSocketAutoResponseTimestamp(ws);
    const stored = await this.ctx.storage.get<string>("mcp_last_seen");
    return automatic && (!stored || automatic.toISOString() > stored) ? automatic.toISOString() : stored ?? "never";
  }

  async message(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    await this.ctx.storage.put("mcp_last_seen", new Date().toISOString());
    if (typeof message !== "string" || message.length > LIMIT * 2) { ws.close(1009, "invalid frame"); return; }
    try {
      const frame = JSON.parse(message);
      const item = this.pending.get(frame.id);
      if (item && item.ws === ws && frame.response?.id === item.rpcID && frame.response?.jsonrpc === "2.0" &&
          ("result" in frame.response || "error" in frame.response)) item.finish(frame.response);
    } catch { /* Ignore malformed replies; the request remains bounded by timeout. */ }
  }

  async closed(ws: WebSocket): Promise<void> {
    const seen = await this.lastSeen(ws);
    if (seen !== "never") await this.ctx.storage.put("mcp_last_seen", seen);
    for (const item of this.pending.values()) if (item.ws === ws) item.finish();
  }
}

function unauthorized(): Response {
  return new Response("unauthorized", { status: 401, headers: { "WWW-Authenticate": "Bearer" } });
}
function method(allow: string): Response {
  return new Response("method not allowed", { status: 405, headers: { Allow: allow } });
}

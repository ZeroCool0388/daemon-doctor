import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";
import { RemoteMCP } from "./mcp";
import { NoopPush } from "./push";

const MAX_BODY = 4096;
const MAX_PAGE = 100;
const BOXES = new Set(["pairing", "alerts", "approvals", "results"]);

type Stored = Record<string, unknown>;

interface EventRow extends Record<string, SqlStorageValue> {
  id: number;
  kind: string;
  body: string;
}

// Mailbox is one Mac's queue. It stores JSON and forwards it.
// It does not check signatures and it does not run commands.
export class Mailbox extends DurableObject {
  private readonly mcp: RemoteMCP;
  private readonly sockets = new Set<WebSocket>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.mcp = new RemoteMCP(ctx);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        body TEXT NOT NULL
      )`);
      // Polls filter by kind and then id. Without this index SQLite walks
      // every rowid greater than `after`, including other kinds.
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS events_kind_id ON events(kind, id)");
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const macID = parts[2] ?? "";
    const box = parts[3] ?? "";
    if (box === "mcp" || box === "mcp-link" || box === "mcp-token") {
      return this.mcp.fetch(box, request);
    }
    if (box === "ws") {
      return this.socket(request);
    }
    if (!BOXES.has(box)) {
      return text("not found", 404);
    }
    if (request.method === "GET") {
      return this.list(box, url);
    }
    if (request.method === "POST") {
      return this.store(macID, box, request);
    }
    return text("method not allowed", 405);
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    await this.mcp.message(ws, message);
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    ws.close([1005, 1006, 1015].includes(code) ? 1000 : code, reason);
    await this.mcp.closed(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.mcp.closed(ws);
  }

  private async store(macID: string, kind: string, request: Request): Promise<Response> {
    const declared = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > MAX_BODY) {
      return text("body too large", 413);
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > MAX_BODY) {
      return text("body too large", 413);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return text("json object required", 400);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return text("json object required", 400);
    }
    const body = JSON.stringify(parsed);
    const row = this.ctx.storage.sql.exec<{ id: number }>(
      "INSERT INTO events (kind, body) VALUES (?, ?) RETURNING id",
      kind,
      body,
    ).next().value;
    const id = Number(row?.id ?? 0);
    const record = { id, kind, body: parsed as Stored };
    this.broadcast(record);
    if (kind === "alerts") {
      const fields = parsed as Stored;
      const alertID = typeof fields.alert_id === "string" ? fields.alert_id : "";
      const message = typeof fields.message === "string" ? fields.message : "";
      await new NoopPush().deliver(macID, alertID, message);
      return json({ stored: true, push: "stub", id });
    }
    return json({ stored: true, id });
  }

  private list(kind: string, url: URL): Response {
    const after = Math.max(0, Math.floor(Number(url.searchParams.get("after") ?? "0") || 0));
    const requested = Number(url.searchParams.get("limit") ?? MAX_PAGE);
    if (!Number.isSafeInteger(requested) || requested < 1) {
      return text("bad limit", 400);
    }
    const limit = Math.min(requested, MAX_PAGE);
    const events = [];
    const rows = this.ctx.storage.sql.exec<EventRow>(
      "SELECT id, kind, body FROM events WHERE kind = ? AND id > ? ORDER BY id ASC LIMIT ?",
      kind,
      after,
      limit + 1,
    );
    for (const row of rows) {
      events.push({
        id: Number(row.id),
        kind: row.kind,
        body: JSON.parse(row.body) as Stored,
      });
    }
    const hasMore = events.length > limit;
    if (hasMore) events.pop();
    return json({ events, next_after: events.at(-1)?.id ?? after, has_more: hasMore });
  }

  private socket(request: Request): Response {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return text("upgrade required", 426);
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.sockets.add(server);
    const drop = () => {
      this.sockets.delete(server);
    };
    server.addEventListener("close", drop);
    server.addEventListener("error", drop);
    return new Response(null, { status: 101, webSocket: client });
  }

  private broadcast(record: { id: number; kind: string; body: Stored }): void {
    const frame = JSON.stringify(record);
    for (const socket of this.sockets) {
      try {
        socket.send(frame);
      } catch {
        this.sockets.delete(socket);
      }
    }
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function text(body: string, status: number): Response {
  return new Response(body, { status, headers: { "content-type": "text/plain" } });
}

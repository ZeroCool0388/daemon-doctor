import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";
import { RemoteMCP } from "./mcp";
import { NoopPush } from "./push";

const MAX_BODY = 4096;
const MAX_PAGE = 100;
const RETAIN_MS = 24 * 60 * 60 * 1000;
const RETAIN_PER_KIND = 50;
const BOXES = new Set(["pairing", "alerts", "approvals", "results"]);

// Rows at this age are dropped on the next write. Null created_at (rows from
// before the column existed) is not aged out; the per-kind cap keeps the newest 50.
const DELETE_OLD_SQL = "DELETE FROM events WHERE created_at <= ?";
const DELETE_CAP_SQL = "DELETE FROM events WHERE kind = ? AND id < ?";

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
      if (!columnExists(this.ctx.storage.sql, "created_at")) {
        this.ctx.storage.sql.exec("ALTER TABLE events ADD COLUMN created_at INTEGER");
      }
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS events_created_at ON events(created_at)");
      this.migrateAlertIds();
      this.prune(Date.now());
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
    const fields = storedObject(parsed);
    const alertID = kind === "alerts" && typeof fields.alert_id === "string" ? fields.alert_id : "";
    const nowMs = Date.now();
    if (alertID !== "") {
      const existing = this.ctx.storage.sql
        .exec<{ id: number }>("SELECT id FROM events WHERE alert_id = ? LIMIT 1", alertID)
        .next().value;
      if (existing !== undefined) {
        this.prune(nowMs);
        return json({ stored: true, id: Number(existing.id) });
      }
    }
    const body = JSON.stringify(parsed);
    const row = this.ctx.storage.sql
      .exec<{ id: number }>(
        "INSERT INTO events (kind, body, created_at, alert_id) VALUES (?, ?, ?, ?) RETURNING id",
        kind,
        body,
        nowMs,
        alertID === "" ? null : alertID,
      )
      .next().value;
    this.prune(nowMs);
    const id = Number(row?.id ?? 0);
    const record = { id, kind, body: fields };
    this.broadcast(record);
    if (kind === "alerts") {
      const message = typeof fields.message === "string" ? fields.message : "";
      await new NoopPush().deliver(macID, alertID, message);
      return json({ stored: true, push: "stub", id });
    }
    return json({ stored: true, id });
  }

  // A timed-out alert post can already be stored. Later posts of that alert_id
  // must not add another row. Multiple NULLs stay allowed for other kinds.
  private migrateAlertIds(): void {
    const sql = this.ctx.storage.sql;
    if (!columnExists(sql, "alert_id")) {
      sql.exec("ALTER TABLE events ADD COLUMN alert_id TEXT");
    }
    const rows = sql.exec<{ id: number; body: string; alert_id: string | null }>(
      "SELECT id, body, alert_id FROM events WHERE kind = 'alerts'",
    );
    const keeper = new Map<string, number>();
    const pending: { id: number; alertID: string; stored: string | null }[] = [];
    for (const row of rows) {
      const stored = row.alert_id === null || row.alert_id === "" ? "" : row.alert_id;
      const alertID = stored !== "" ? stored : alertIdFromBody(row.body);
      const id = Number(row.id);
      pending.push({ id, alertID, stored: row.alert_id });
      if (alertID === "") {
        continue;
      }
      const previous = keeper.get(alertID);
      if (previous === undefined || id > previous) {
        keeper.set(alertID, id);
      }
    }
    for (const row of pending) {
      if (row.alertID !== "" && keeper.get(row.alertID) !== row.id) {
        sql.exec("DELETE FROM events WHERE id = ?", row.id);
      }
    }
    for (const row of pending) {
      if (row.alertID !== "" && keeper.get(row.alertID) === row.id && row.stored !== row.alertID) {
        sql.exec("UPDATE events SET alert_id = ? WHERE id = ?", row.alertID, row.id);
      }
    }
    // A partial index is not a candidate for `alert_id = ?`, because the bound
    // value is not known to be non-empty. Multiple NULLs remain distinct.
    sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS events_alert_id ON events(alert_id)");
  }

  private prune(nowMs: number): void {
    this.ctx.storage.sql.exec(DELETE_OLD_SQL, nowMs - RETAIN_MS);
    for (const kind of BOXES) {
      const threshold = this.ctx.storage.sql
        .exec<{ id: number }>(
          "SELECT id FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1 OFFSET ?",
          kind,
          RETAIN_PER_KIND - 1,
        )
        .next().value;
      if (threshold === undefined) {
        continue;
      }
      this.ctx.storage.sql.exec(DELETE_CAP_SQL, kind, Number(threshold.id));
    }
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

function storedObject(value: object): Stored {
  const fields: Stored = {};
  for (const [key, entry] of Object.entries(value)) {
    fields[key] = entry;
  }
  return fields;
}

function alertIdFromBody(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return "";
    }
    const alertID = storedObject(parsed).alert_id;
    return typeof alertID === "string" ? alertID : "";
  } catch {
    return "";
  }
}

function columnExists(sql: SqlStorage, name: string): boolean {
  for (const row of sql.exec<{ name: string }>("PRAGMA table_info(events)")) {
    if (row.name === name) {
      return true;
    }
  }
  return false;
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

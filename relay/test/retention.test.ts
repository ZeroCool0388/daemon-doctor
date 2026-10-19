import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const DAY_MS = 24 * 60 * 60 * 1000;

// Delete statements Mailbox uses on writes. The plan assertions track these strings.
const DELETE_OLD_SQL = "DELETE FROM events WHERE created_at <= ?";
const DELETE_CAP_SQL = "DELETE FROM events WHERE kind = ? AND id < ?";

// The Mac poll in Mailbox.list. Kept here so the plan assertion tracks that query.
const POLL_SQL =
  "SELECT id, kind, body FROM events WHERE kind = ? AND id > ? ORDER BY id ASC LIMIT ?";

function mac(n: number): string {
  return n.toString(16).padStart(32, "a");
}

function box(id: string, kind: string): string {
  return `https://relay.example.invalid/v1/macs/${id}/${kind}`;
}

function alertId(n: number, pad: string): string {
  return n.toString(16).padStart(32, pad);
}

function plans(sql: SqlStorage, query: string, ...bindings: SqlStorageValue[]): string[] {
  const explained = sql.exec<{ detail: string }>(`EXPLAIN QUERY PLAN ${query}`, ...bindings);
  const details: string[] = [];
  for (const row of explained) {
    details.push(row.detail);
  }
  return details;
}

async function withSql<T>(id: string, fn: (sql: SqlStorage) => T | Promise<T>): Promise<T> {
  const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
  return runInDurableObject(stub, async (_instance, state) => fn(state.storage.sql));
}

function countKind(sql: SqlStorage, kind: string): number {
  const row = sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM events WHERE kind = ?", kind).next().value;
  return Number(row?.n ?? 0);
}

async function post(id: string, kind: string, body: unknown): Promise<Response> {
  return SELF.fetch(box(id, kind), { method: "POST", body: JSON.stringify(body) });
}

describe("mailbox query plan", () => {
  it("searches the poll with events_kind_id", async () => {
    const id = mac(1);
    await SELF.fetch(`https://relay.example.invalid/v1/macs/${id}/pairing`);
    const details = await withSql(id, (sql) => plans(sql, POLL_SQL, "pairing", 0, 101));
    const joined = details.join("\n");
    expect(joined).toContain("SEARCH");
    expect(joined).toContain("INDEX events_kind_id");
    expect(joined).not.toContain("SCAN");
  });

  it("deletes aged rows and over-cap rows by index", async () => {
    const id = mac(5);
    await SELF.fetch(box(id, "pairing"));
    const found = await withSql(id, (sql) => ({
      age: plans(sql, DELETE_OLD_SQL, 0).join("\n"),
      cap: plans(sql, DELETE_CAP_SQL, "alerts", 1).join("\n"),
    }));
    expect(found.age).toContain("SEARCH");
    expect(found.age).toContain("INDEX events_created_at");
    expect(found.age).not.toContain("SCAN");
    expect(found.cap).toContain("SEARCH");
    expect(found.cap).toContain("INDEX events_kind_id");
    expect(found.cap).not.toContain("SCAN");
  });
});

describe("mailbox retention", () => {
  it("prunes a 24h-old row on the next write", async () => {
    const id = mac(2);
    const fresh = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const stale = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    expect((await post(id, "alerts", { alert_id: fresh, message: "fresh" })).status).toBe(200);
    await withSql(id, (sql) => {
      sql.exec(
        "INSERT INTO events (kind, body, created_at) VALUES (?, ?, ?)",
        "alerts",
        JSON.stringify({ alert_id: stale, message: "old" }),
        Date.now() - DAY_MS,
      );
    });
    expect((await post(id, "approvals", { fix_id: "restart" })).status).toBe(200);
    const page = (await (await SELF.fetch(box(id, "alerts"))).json()) as {
      events: { body: { alert_id?: string } }[];
    };
    const ids = page.events.map((event) => event.body.alert_id);
    expect(ids).toContain(fresh);
    expect(ids).not.toContain(stale);
  });

  it("keeps the newest 50 rows per kind and leaves other kinds", async () => {
    const id = mac(4);
    for (let n = 0; n < 10; n++) {
      expect((await post(id, "approvals", { n })).status).toBe(200);
    }
    for (let n = 0; n < 51; n++) {
      expect((await post(id, "alerts", { alert_id: alertId(n, "e"), message: "n" })).status).toBe(200);
    }
    const alerts = (await (await SELF.fetch(`${box(id, "alerts")}?limit=100`)).json()) as {
      events: { body: { alert_id?: string } }[];
    };
    const approvals = (await (await SELF.fetch(`${box(id, "approvals")}?limit=100`)).json()) as {
      events: unknown[];
    };
    expect(alerts.events).toHaveLength(50);
    expect(approvals.events).toHaveLength(10);
    const ids = alerts.events.map((event) => event.body.alert_id);
    expect(ids).toContain(alertId(50, "e"));
    expect(ids).not.toContain(alertId(0, "e"));
  });

  it("does not delete on an empty poll", async () => {
    const id = mac(3);
    const keep = "cccccccccccccccccccccccccccccccc";
    const stale = "dddddddddddddddddddddddddddddddd";
    expect((await post(id, "alerts", { alert_id: keep, message: "keep" })).status).toBe(200);
    await withSql(id, (sql) => {
      sql.exec(
        "INSERT INTO events (kind, body, created_at) VALUES (?, ?, ?)",
        "alerts",
        JSON.stringify({ alert_id: stale, message: "old" }),
        Date.now() - DAY_MS,
      );
    });
    const before = await withSql(id, (sql) => countKind(sql, "alerts"));
    const polled = await SELF.fetch(`${box(id, "alerts")}?after=0`);
    expect(polled.status).toBe(200);
    const after = await withSql(id, (sql) => countKind(sql, "alerts"));
    expect(before).toBe(2);
    expect(after).toBe(before);
  });

  it("caps a pre-migration backlog when the object wakes", async () => {
    const id = mac(6);
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      for (let n = 0; n < 80; n++) {
        sql.exec(
          "INSERT INTO events (kind, body, created_at) VALUES (?, ?, NULL)",
          "alerts",
          JSON.stringify({ alert_id: alertId(n, "1"), message: "old" }),
        );
      }
      for (let n = 0; n < 10; n++) {
        sql.exec(
          "INSERT INTO events (kind, body, created_at) VALUES (?, ?, NULL)",
          "results",
          JSON.stringify({ n }),
        );
      }
    });
    await evictDurableObject(stub);
    const alerts = (await (await SELF.fetch(`${box(id, "alerts")}?limit=100`)).json()) as {
      events: { body: { alert_id?: string } }[];
    };
    const results = (await (await SELF.fetch(`${box(id, "results")}?limit=100`)).json()) as {
      events: unknown[];
    };
    expect(alerts.events).toHaveLength(50);
    expect(results.events).toHaveLength(10);
    const ids = alerts.events.map((event) => event.body.alert_id);
    expect(ids).toContain(alertId(79, "1"));
    expect(ids).not.toContain(alertId(0, "1"));
  });
});

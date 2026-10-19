import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  ALERT_LOOKUP_SQL,
  CAP_PROBE_SQL,
  DELETE_CAP_SQL,
  DELETE_OLD_SQL,
  POLL_SQL,
  SCHEMA_VERSION,
} from "../src/mailbox";

const DAY_MS = 24 * 60 * 60 * 1000;

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

function schemaVersion(sql: SqlStorage): number | null {
  try {
    const row = sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").next().value;
    if (row === undefined) {
      return null;
    }
    return Number(row.value);
  } catch {
    return null;
  }
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
      probe: plans(sql, CAP_PROBE_SQL, "alerts", 49).join("\n"),
      lookup: plans(sql, ALERT_LOOKUP_SQL, "abcdef0123456789abcdef0123456789").join("\n"),
    }));
    expect(found.age).toContain("SEARCH");
    expect(found.age).toContain("INDEX events_created_at");
    expect(found.age).not.toContain("SCAN");
    expect(found.cap).toContain("SEARCH");
    expect(found.cap).toContain("INDEX events_kind_id");
    expect(found.cap).not.toContain("SCAN");
    expect(found.probe).toContain("SEARCH");
    expect(found.probe).toContain("INDEX events_kind_id");
    expect(found.probe).not.toContain("SCAN");
    expect(found.lookup).toContain("SEARCH");
    expect(found.lookup).toContain("INDEX events_alert_id");
    expect(found.lookup).not.toContain("SCAN");
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

  it("migrates the original three-column table once", async () => {
    const id = mac(6);
    const dup = "a".repeat(32);
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("DROP TABLE IF EXISTS events");
      sql.exec("DROP TABLE IF EXISTS meta");
      sql.exec(`CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        body TEXT NOT NULL
      )`);
      for (let n = 0; n < 40; n++) {
        sql.exec(
          "INSERT INTO events (kind, body) VALUES (?, ?)",
          "alerts",
          JSON.stringify({ alert_id: alertId(n, "9"), message: "filler" }),
        );
      }
      sql.exec(
        "INSERT INTO events (kind, body) VALUES (?, ?)",
        "alerts",
        JSON.stringify({ alert_id: dup, message: "old-dup" }),
      );
      for (let n = 40; n < 60; n++) {
        sql.exec(
          "INSERT INTO events (kind, body) VALUES (?, ?)",
          "alerts",
          JSON.stringify({ alert_id: alertId(n, "9"), message: "filler" }),
        );
      }
      sql.exec(
        "INSERT INTO events (kind, body) VALUES (?, ?)",
        "alerts",
        JSON.stringify({ alert_id: dup, message: "new-dup" }),
      );
      for (let n = 0; n < 3; n++) {
        sql.exec("INSERT INTO events (kind, body) VALUES (?, ?)", "approvals", JSON.stringify({ n }));
      }
      sql.exec("INSERT INTO events (kind, body) VALUES (?, ?)", "pairing", JSON.stringify({ hello: true }));
      sql.exec("INSERT INTO events (kind, body) VALUES (?, ?)", "results", JSON.stringify({ ok: true }));
    });
    await evictDurableObject(stub);
    const alertResponse = await SELF.fetch(`${box(id, "alerts")}?limit=100`);
    expect(alertResponse.status).toBe(200);
    const alerts = (await alertResponse.json()) as {
      events: { body: { alert_id?: string; message?: string } }[];
    };
    expect(alerts.events).toHaveLength(50);
    const copies = alerts.events.filter((event) => event.body.alert_id === dup);
    expect(copies).toHaveLength(1);
    expect(copies[0]?.body.message).toBe("new-dup");
    const approvals = (await (await SELF.fetch(`${box(id, "approvals")}?limit=100`)).json()) as { events: unknown[] };
    const pairing = (await (await SELF.fetch(`${box(id, "pairing")}?limit=100`)).json()) as { events: unknown[] };
    const results = (await (await SELF.fetch(`${box(id, "results")}?limit=100`)).json()) as { events: unknown[] };
    expect(approvals.events).toHaveLength(3);
    expect(pairing.events).toHaveLength(1);
    expect(results.events).toHaveLength(1);
    const indexName = await withSql(id, (sql) => {
      const row = sql
        .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'events_alert_id'")
        .next().value;
      return row?.name ?? "";
    });
    expect(indexName).toBe("events_alert_id");
    expect(await withSql(id, schemaVersion)).toBe(SCHEMA_VERSION);
  });

  it("does not delete or migrate again on a cold poll", async () => {
    const id = mac(10);
    const keep = "c".repeat(32);
    const stale = "d".repeat(32);
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
    const before = await runInDurableObject(stub, async (instance, state) => {
      const posted = await instance.fetch(
        new Request(box(id, "alerts"), {
          method: "POST",
          body: JSON.stringify({ alert_id: keep, message: "keep" }),
        }),
      );
      if (posted.status !== 200) {
        throw new Error(`post ${posted.status}`);
      }
      const sql = state.storage.sql;
      sql.exec(
        "INSERT INTO events (kind, body, created_at, alert_id) VALUES (?, ?, ?, NULL)",
        "alerts",
        JSON.stringify({ alert_id: stale, message: "stale" }),
        Date.now() - DAY_MS,
      );
      const backfill = sql
        .exec<{ alert_id: string | null }>("SELECT alert_id FROM events WHERE body LIKE ?", '%"message":"stale"%')
        .next().value?.alert_id;
      return { version: schemaVersion(sql), rows: countKind(sql, "alerts"), backfill: backfill ?? null };
    });
    expect(before.version).toBe(SCHEMA_VERSION);
    expect(before.rows).toBe(2);
    expect(before.backfill).toBeNull();
    await evictDurableObject(stub);
    const polled = await SELF.fetch(`${box(id, "alerts")}?after=0`);
    expect(polled.status).toBe(200);
    const after = await withSql(id, (sql) => ({
      version: schemaVersion(sql),
      rows: countKind(sql, "alerts"),
      backfill: sql
        .exec<{ alert_id: string | null }>(
          "SELECT alert_id FROM events WHERE body LIKE ?",
          '%"message":"stale"%',
        )
        .next().value?.alert_id,
    }));
    expect(after.version).toBe(before.version);
    expect(after.rows).toBe(before.rows);
    expect(after.backfill ?? null).toBeNull();
    const page = (await polled.json()) as { events: { body: { message?: string } }[] };
    expect(page.events.map((event) => event.body.message).sort()).toEqual(["keep", "stale"]);
  });

  it("does not ack an alert id that retention just removed", async () => {
    const id = mac(12);
    const alertID = "b".repeat(32);
    const first = (await (await post(id, "alerts", { alert_id: alertID, message: "one" })).json()) as { id: number };
    await withSql(id, (sql) => {
      sql.exec("UPDATE events SET created_at = ? WHERE id = ?", Date.now() - DAY_MS, first.id);
    });
    const secondResponse = await post(id, "alerts", { alert_id: alertID, message: "retry" });
    expect(secondResponse.status).toBe(200);
    const second = (await secondResponse.json()) as { id: number; stored: boolean };
    expect(second.stored).toBe(true);
    const page = (await (await SELF.fetch(box(id, "alerts"))).json()) as {
      events: { id: number; body: { message?: string } }[];
    };
    expect(page.events.map((event) => event.id)).toContain(second.id);
    expect(page.events.map((event) => event.id)).not.toContain(first.id);
    expect(page.events.find((event) => event.id === second.id)?.body.message).toBe("retry");
  });

  it("ignores a repeated alert id", async () => {
    const id = mac(7);
    const alertID = "abcdef0123456789abcdef0123456789";
    const first = (await (await post(id, "alerts", { alert_id: alertID, message: "one" })).json()) as {
      id: number;
      stored: boolean;
      push?: string;
    };
    expect(first.stored).toBe(true);
    expect(first.push).toBe("stub");

    const opened = await SELF.fetch(box(id, "ws"), { headers: { Upgrade: "websocket" } });
    expect(opened.status).toBe(101);
    const socket = opened.webSocket;
    expect(socket).toBeTruthy();
    socket?.accept();
    const frames: string[] = [];
    socket?.addEventListener("message", (event) => {
      frames.push(String(event.data));
    });

    const secondResponse = await post(id, "alerts", { alert_id: alertID, message: "retry" });
    expect(secondResponse.status).toBe(200);
    const second = (await secondResponse.json()) as { id: number; stored: boolean; push?: string };
    expect(second.stored).toBe(true);
    expect(second.id).toBe(first.id);
    expect(second.push).toBeUndefined();

    const other = "fedcba9876543210fedcba9876543210";
    const followed = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no websocket frame")), 2000);
      socket?.addEventListener("message", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    expect((await post(id, "alerts", { alert_id: other, message: "two" })).status).toBe(200);
    await followed;
    expect(frames).toHaveLength(1);
    expect(JSON.parse(frames[0] ?? "{}")).toMatchObject({ body: { message: "two" } });
    socket?.close();

    const page = (await (await SELF.fetch(box(id, "alerts"))).json()) as {
      events: { id: number; body: { message?: string } }[];
    };
    expect(page.events.map((event) => event.id)).toEqual([first.id, expect.any(Number)]);
    expect(page.events[0]?.body.message).toBe("one");
    expect(page.events).toHaveLength(2);
  });

  it("looks up an alert id on events_alert_id", async () => {
    const id = mac(8);
    await SELF.fetch(box(id, "pairing"));
    const joined = (await withSql(id, (sql) => plans(sql, ALERT_LOOKUP_SQL, "abcdef0123456789abcdef0123456789"))).join(
      "\n",
    );
    expect(joined).toContain("SEARCH");
    expect(joined).toContain("INDEX events_alert_id");
    expect(joined).not.toContain("SCAN");
  });
});

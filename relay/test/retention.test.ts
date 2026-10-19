import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

// The Mac poll in Mailbox.list. Kept here so the plan assertion tracks that query.
const POLL_SQL =
  "SELECT id, kind, body FROM events WHERE kind = ? AND id > ? ORDER BY id ASC LIMIT ?";

function mac(n: number): string {
  return n.toString(16).padStart(32, "a");
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
});

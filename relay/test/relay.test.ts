import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

function mac(n: number): string {
  return n.toString(16).padStart(32, "0");
}

function url(id: string, box: string): string {
  return `https://relay.example.invalid/v1/macs/${id}/${box}`;
}

describe("health", () => {
  it("answers GET /health with ok", async () => {
    const res = await SELF.fetch("https://relay.example.invalid/health");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ ok: true });
  });

  it("refuses POST /health", async () => {
    const res = await SELF.fetch("https://relay.example.invalid/health", { method: "POST", body: "{}" });
    expect(res.status).toBe(405);
  });
});

describe("mailbox", () => {
  it("bounds backlog pages and can restart from zero", async () => {
    const id = mac(20);
    const body = JSON.stringify({ pad: "x".repeat(4000) });
    // More than the per-kind cap. Each page must stay under the Mac client's 1 MiB limit.
    for (let n = 0; n < 60; n++) {
      const posted = await SELF.fetch(url(id, "approvals"), { method: "POST", body });
      expect(posted.status).toBe(200);
    }
    for (let restart = 0; restart < 2; restart++) {
      let after = 0;
      let count = 0;
      let more = true;
      while (more) {
        const response = await SELF.fetch(`${url(id, "approvals")}?after=${after}&limit=10000`);
        const raw = await response.text();
        expect(new TextEncoder().encode(raw).byteLength).toBeLessThan(1024 * 1024);
        const page = JSON.parse(raw) as { events: { id: number }[]; next_after: number; has_more: boolean };
        expect(page.events.length).toBeLessThanOrEqual(100);
        expect(page.events[0].id).toBeGreaterThan(after);
        expect(page.next_after).toBe(page.events.at(-1)?.id);
        count += page.events.length;
        after = page.next_after;
        more = page.has_more;
      }
      expect(count).toBe(50);
    }
    const first = (await (await SELF.fetch(`${url(id, "approvals")}?limit=3`)).json()) as { events: unknown[]; has_more: boolean };
    expect(first.events).toHaveLength(3);
    expect(first.has_more).toBe(true);
    expect((await SELF.fetch(`${url(id, "approvals")}?limit=0`)).status).toBe(400);
  }, 15000);
  it("forwards an approval unchanged", async () => {
    const body = {
      mac_id: mac(1),
      alert_id: "abcdef0123456789abcdef0123456789",
      fix_id: "restart",
      nonce: "0123456789abcdef0123456789abcdef",
      expires_unix: 1_700_000_000,
      public_key: "phone",
      signature: "sig",
    };
    const id = mac(1);
    const posted = await SELF.fetch(url(id, "approvals"), {
      method: "POST",
      body: JSON.stringify(body),
    });
    expect(posted.status).toBe(200);
    const listed = await SELF.fetch(url(id, "approvals"));
    expect(listed.status).toBe(200);
    const page = (await listed.json()) as { events: { id: number; kind: string; body: typeof body }[] };
    expect(page.events).toHaveLength(1);
    expect(page.events[0].kind).toBe("approvals");
    expect(page.events[0].body.fix_id).toBe("restart");
    expect(page.events[0].body.signature).toBe("sig");
  });

  it("stores the same approval twice", async () => {
    const id = mac(2);
    const body = JSON.stringify({ fix_id: "restart", nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
    const first = await SELF.fetch(url(id, "approvals"), { method: "POST", body });
    const second = await SELF.fetch(url(id, "approvals"), { method: "POST", body });
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    const firstID = ((await first.json()) as { id: number }).id;
    const page = (await (await SELF.fetch(`${url(id, "approvals")}?after=${firstID}`)).json()) as {
      events: { id: number }[];
    };
    expect(page.events).toHaveLength(1);
    expect(page.events[0].id).toBeGreaterThan(firstID);
  });

  it("rejects a body over 4096 bytes", async () => {
    const body = JSON.stringify({ pad: "a".repeat(5000) });
    const res = await SELF.fetch(url(mac(3), "alerts"), { method: "POST", body });
    expect(res.status).toBe(413);
  });

  it("has no command route", async () => {
    const res = await SELF.fetch("https://relay.example.invalid/v1/exec", {
      method: "POST",
      body: JSON.stringify({ command: "restart" }),
    });
    expect(res.status).toBe(404);
  });

  it("stores a smuggled command and does not run it", async () => {
    const body = { fix_id: "restart", command: "touch marker" };
    const id = mac(4);
    const posted = await SELF.fetch(url(id, "approvals"), {
      method: "POST",
      body: JSON.stringify(body),
    });
    expect(posted.status).toBe(200);
    const stored = (await posted.json()) as { stored: boolean; id: number };
    expect(stored.stored).toBe(true);
    const page = (await (await SELF.fetch(`${url(id, "approvals")}?after=${stored.id - 1}`)).json()) as {
      events: { body: { command?: string } }[];
    };
    const found = page.events.find((event) => event.body.command === "touch marker");
    expect(found).toBeTruthy();
  });

  it("reports a push stub for an alert", async () => {
    const res = await SELF.fetch(url(mac(5), "alerts"), {
      method: "POST",
      body: JSON.stringify({ alert_id: "abcdef0123456789abcdef0123456789", message: "Example Desktop App has stopped." }),
    });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as { push?: string };
    expect(payload.push).toBe("stub");
  });

  it("rejects a mac id that is not 32 hex characters", async () => {
    const res = await SELF.fetch("https://relay.example.invalid/v1/macs/not-a-mac/alerts", {
      method: "POST",
      body: JSON.stringify({ alert_id: "x" }),
    });
    expect(res.status).toBe(400);
  });

  it("pushes a stored alert over the outbound websocket", async () => {
    const id = mac(6);
    const opened = await SELF.fetch(url(id, "ws"), { headers: { Upgrade: "websocket" } });
    expect(opened.status).toBe(101);
    const socket = opened.webSocket;
    expect(socket).toBeTruthy();
    socket?.accept();
    const next = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no websocket frame")), 2000);
      socket?.addEventListener("message", (event) => {
        clearTimeout(timer);
        resolve(String(event.data));
      });
    });
    const posted = await SELF.fetch(url(id, "alerts"), {
      method: "POST",
      body: JSON.stringify({ alert_id: "abcdef0123456789abcdef0123456789", message: "still down" }),
    });
    expect(posted.status).toBe(200);
    const frame = JSON.parse(await next) as { kind: string; body: { message: string } };
    expect(frame.kind).toBe("alerts");
    expect(frame.body.message).toBe("still down");
    socket?.close();
  });
});

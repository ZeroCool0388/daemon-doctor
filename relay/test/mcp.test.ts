import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { identity, ownerID, ownerProof } from "./mcp-identity";
import { tokenHash } from "../src/mcp";

const macID = ownerID;
const origin = `https://relay.example.invalid/v1/macs/${macID}`;
const secret = "S".repeat(43);
const token = "T".repeat(43);
async function setup() {
  for (const [route, body] of [
    ["mcp-link", ownerProof],
    ["mcp-token", { token_hash: await tokenHash(token) }],
  ] as const) {
    const res = await SELF.fetch(`${origin}/${route}`, { method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify(body) });
    expect(res.status).toBe(200);
  }
}
async function call(method: string, auth: string | undefined = token) {
  return SELF.fetch(`${origin}/mcp`, { method: "POST", headers: auth ? { Authorization: `Bearer ${auth}`, "Mcp-Session-Id": "client-session" } : {}, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method }) });
}

describe("remote MCP Worker and Durable Object", () => {
  it("routes authenticated requests over a hibernating Mac socket", async () => {
    await setup();
    expect((await call("ping", "bad" )).status).toBe(401);
    expect((await SELF.fetch(`${origin}/mcp`, { method: "POST", body: "{}" })).status).toBe(401);
    expect((await SELF.fetch(`${origin}/mcp-link`, { headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` } })).status).toBe(401);
    const upgrade = await SELF.fetch(`${origin}/mcp-link`, { headers: { Upgrade: "websocket", Authorization: `Bearer ${secret}` } });
    expect(upgrade.status).toBe(101);
    const ws = upgrade.webSocket!;
    ws.accept();
    ws.addEventListener("message", event => {
      const frame = JSON.parse(event.data as string);
      if (frame.type === "pong") return;
      const result = frame.request.method === "initialize" ? { serverInfo: { name: "daemon-doctor", version: "1" }, protocolVersion: "2025-11-25", capabilities: { tools: {} } } : { tools: [{ name: "list_services" }] };
      ws.send(JSON.stringify({ id: frame.id, response: { jsonrpc: "2.0", id: frame.request.id, result } }));
    });
    try {
      for (const method of ["initialize", "tools/list"]) {
        const res = await call(method);
        expect(res.headers.get("Mcp-Session-Id")).toBe("client-session");
        expect(await res.json()).toMatchObject({ jsonrpc: "2.0", id: 1, result: {} });
      }
      const pong = new Promise<string>(resolve => ws.addEventListener("message", event => { if (event.data === '{"type":"pong"}') resolve(event.data as string); }));
      ws.send('{"type":"ping"}');
      expect(await pong).toBe('{"type":"pong"}');
      expect((await SELF.fetch(`${origin}/mcp`, { headers: { Authorization: `Bearer ${token}` } })).status).toBe(405);
    } finally { ws.close(1000); }
  });

  it("reports last_seen for an offline Mac", async () => {
    const owner = await identity(await tokenHash(secret));
    const id = owner.id;
    const base = `https://relay.example.invalid/v1/macs/${id}`;
    await SELF.fetch(`${base}/mcp-link`, { method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify(owner.proof) });
    await SELF.fetch(`${base}/mcp-token`, { method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify({ token_hash: await tokenHash(token) }) });
    const res = await SELF.fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: "call", method: "tools/call" }) });
    expect(await res.json()).toEqual({ jsonrpc: "2.0", id: "call", result: { isError: true, content: [{ type: "text", text: "Mac unreachable, last seen never" }] } });
  });
});

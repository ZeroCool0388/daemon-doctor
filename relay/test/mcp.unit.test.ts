import { afterEach, describe, expect, it, vi } from "vitest";
import { identity, ownerID, ownerProof } from "./mcp-identity";
import { RemoteMCP, tokenHash } from "../src/mcp";

const token = "T".repeat(43);
const secret = "S".repeat(43);
function request(route: string, method = "POST", auth: string | null = token, payload?: unknown): Request {
  return new Request(`https://relay.example.invalid/v1/macs/${ownerID}/${route}`, {
    method, headers: { ...(auth ? { Authorization: `Bearer ${auth}` } : {}), "Content-Type": "application/json", "Mcp-Session-Id": "session" },
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  });
}
function fake() {
  const values = new Map<string, unknown>();
  const sockets: WebSocket[] = [];
  const storage = {
    get: async <T>(key: string) => values.get(key) as T | undefined,
    put: async (key: string, value: unknown) => { values.set(key, value); },
    delete: async (key: string) => values.delete(key),
    transaction: async <T>(fn: (txn: unknown) => Promise<T>) => fn(storage),
  };
  const ctx = {
    storage, getWebSockets: () => sockets,
    getWebSocketAutoResponseTimestamp: () => null,
  } as unknown as DurableObjectState;
  return { values, sockets, mcp: new RemoteMCP(ctx) };
}
async function registered() {
  const f = fake();
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, ownerProof))).status).toBe(200);
  expect((await f.mcp.fetch("mcp-token", request("mcp-token", "PUT", secret, { token_hash: await tokenHash(token) }))).status).toBe(200);
  return f;
}
const rpc = (method: string, id: number | string = 7) => ({ jsonrpc: "2.0", id, method });
afterEach(() => vi.useRealTimers());

describe("remote MCP", () => {
  it("requires the registered bearer token and stores only hashes", async () => {
    const f = await registered();
    for (const auth of [null, "B".repeat(43), secret]) {
      expect((await f.mcp.fetch("mcp", request("mcp", "POST", auth, rpc("ping")))).status).toBe(401);
    }
    expect((await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping")))).status).toBe(200);
    expect([...f.values.values()]).not.toContain(token);
    expect([...f.values.values()]).not.toContain(secret);
    expect((await f.mcp.fetch("mcp-link", request("mcp-link", "GET", token))).status).toBe(401);
    expect((await f.mcp.fetch("mcp-token", request("mcp-token", "PUT", token, { token_hash: await tokenHash(token) }))).status).toBe(401);
  });

  it("refuses link takeover and rotates the MCP token", async () => {
    const f = await registered();
    const other = "N".repeat(43);
    expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", other, { secret_hash: await tokenHash(other) }))).status).toBe(401);
    expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, { ...ownerProof, secret_hash: await tokenHash(other) }))).status).toBe(401);
    expect((await f.mcp.fetch("mcp-token", request("mcp-token", "PUT", secret, { token_hash: await tokenHash(other) }))).status).toBe(200);
    expect((await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping")))).status).toBe(401);
    expect((await f.mcp.fetch("mcp", request("mcp", "POST", other, rpc("ping")))).status).toBe(200);
    // Credential persistence is independent of an in-memory DO instance.
    const ctx = { storage: { get: async (key: string) => f.values.get(key) }, getWebSockets: () => [], getWebSocketAutoResponseTimestamp: () => null } as unknown as DurableObjectState;
    const restarted = new RemoteMCP(ctx);
    expect((await restarted.fetch("mcp", request("mcp", "POST", other, rpc("ping")))).status).toBe(200);
  });

  it("forwards initialize and tools/list and echoes optional session id", async () => {
    const f = await registered();
    let socket: WebSocket;
    socket = { readyState: 1, send: (raw: string) => {
      const frame = JSON.parse(raw);
      const result = frame.request.method === "initialize" ? { protocolVersion: "2025-11-25", serverInfo: { name: "daemon-doctor", version: "1" }, capabilities: { tools: {} } } : { tools: [{ name: "list_services" }] };
      void f.mcp.message(socket, JSON.stringify({ id: frame.id, response: { jsonrpc: "2.0", id: frame.request.id, result } }));
    } } as unknown as WebSocket;
    f.sockets.push(socket);
    for (const method of ["initialize", "tools/list"]) {
      const res = await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc(method)));
      expect(res.headers.get("Mcp-Session-Id")).toBe("session");
      const reply = await res.json() as any;
      expect(reply.id).toBe(7);
      expect(reply.result[method === "initialize" ? "serverInfo" : "tools"]).toBeDefined();
    }
    const res = await f.mcp.fetch("mcp", new Request("https://relay.example.invalid/mcp", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify(rpc("tools/list")) }));
    expect(res.headers.get("Mcp-Session-Id")).toBeNull();
  });

  it("correlates concurrent identical client ids by relay ids", async () => {
    const f = await registered();
    const frames: any[] = [];
    const socket = { readyState: 1, send: (raw: string) => frames.push(JSON.parse(raw)) } as unknown as WebSocket;
    f.sockets.push(socket);
    const calls = [f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping"))), f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping")))];
    await vi.waitFor(() => expect(frames).toHaveLength(2));
    expect(frames[0].id).not.toBe(frames[1].id);
    // Replies from another socket or with a mismatched JSON-RPC id are ignored.
    await f.mcp.message({} as WebSocket, JSON.stringify({ id: frames[0].id, response: { jsonrpc: "2.0", id: 7, result: {} } }));
    await f.mcp.message(socket, JSON.stringify({ id: frames[0].id, response: { jsonrpc: "2.0", id: 8, result: {} } }));
    for (let i = 1; i >= 0; i--) await f.mcp.message(socket, JSON.stringify({ id: frames[i].id, response: { jsonrpc: "2.0", id: 7, result: { index: i } } }));
    expect(await (await calls[0]).json()).toMatchObject({ result: { index: 0 } });
    expect(await (await calls[1]).json()).toMatchObject({ result: { index: 1 } });
  });

  it("reports offline last_seen and tool errors", async () => {
    const f = await registered();
    const seen = "2026-10-13T10:00:00.000Z";
    f.values.set("mcp_last_seen", seen);
    const res = await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("tools/call")));
    expect(await res.json()).toEqual({ jsonrpc: "2.0", id: 7, result: { isError: true, content: [{ type: "text", text: `Mac unreachable, last seen ${seen}` }] } });
    const ping = await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping")));
    expect(await ping.json()).toMatchObject({ error: { code: -32000, message: `Mac unreachable, last seen ${seen}` } });
  });

  it("times out a silent Mac and records the last message time", async () => {
    const f = await registered();
    let sent!: () => void;
    const forwarded = new Promise<void>(resolve => { sent = resolve; });
    const socket = { readyState: 1, send: sent } as unknown as WebSocket;
    f.sockets.push(socket);
    await f.mcp.message(socket, "{}");
    const seen = f.values.get("mcp_last_seen");
    vi.useFakeTimers();
    const call = f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("tools/call")));
    await forwarded;
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await (await call).json()).toMatchObject({ result: { isError: true, content: [{ text: `Mac unreachable, last seen ${seen}` }] } });
  });

  it("ends pending calls when the link closes", async () => {
    const f = await registered();
    let sent!: () => void;
    const forwarded = new Promise<void>(resolve => { sent = resolve; });
    const socket = { readyState: 1, send: sent } as unknown as WebSocket;
    f.sockets.push(socket);
    const call = f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("tools/call")));
    await forwarded;
    await f.mcp.closed(socket);
    expect(await (await call).json()).toMatchObject({ result: { isError: true } });
  });

  it("accepts notifications and rejects unsupported HTTP methods and invalid bodies", async () => {
    const f = await registered();
    const res = await f.mcp.fetch("mcp", request("mcp", "POST", token, { jsonrpc: "2.0", method: "notifications/initialized" }));
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
    expect((await f.mcp.fetch("mcp", request("mcp", "GET"))).status).toBe(405);
    for (const value of [[], null, { jsonrpc: "2.0", method: "ping", id: {} }, { method: "ping" }]) {
      expect((await f.mcp.fetch("mcp", request("mcp", "POST", token, value))).status).toBe(400);
    }
    expect((await f.mcp.fetch("mcp", request("mcp", "POST", token, { ...rpc("ping"), params: "x".repeat(65_536) }))).status).toBe(400);
  });
});

it("refuses squatting, forged proofs and legacy unverified credentials", async () => {
  const f = fake();
  const attackerSecret = "A".repeat(43);
  const attacker = await identity(await tokenHash(attackerSecret));
  // Signing with the attacker's own key cannot enroll the victim's endpoint.
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", attackerSecret, attacker.proof))).status).toBe(401);
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, { secret_hash: ownerProof.secret_hash }))).status).toBe(401);
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, { ...ownerProof, signature: attacker.proof.signature }))).status).toBe(401);
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", attackerSecret, { ...ownerProof, secret_hash: attacker.proof.secret_hash }))).status).toBe(401);
  expect(f.values.has("mcp_link_hash")).toBe(false);
  const wrongID = request("mcp-link", "PUT", secret, ownerProof);
  expect((await f.mcp.fetch("mcp-link", new Request(wrongID.url.replace(ownerID, "0".repeat(32)), wrongID))).status).toBe(401);
  // Old deployments' hash-only enrollments are not accepted as verified owners.
  f.values.set("mcp_link_hash", ownerProof.secret_hash);
  f.values.set("mcp_token_hash", await tokenHash(token));
  expect((await f.mcp.fetch("mcp-token", request("mcp-token", "PUT", secret, { token_hash: await tokenHash(token) }))).status).toBe(401);
  expect((await f.mcp.fetch("mcp", request("mcp", "POST", token, rpc("ping")))).status).toBe(401);
  // Verified ownership can reclaim an old unsigned squatter's registration.
  f.values.set("mcp_link_hash", attacker.proof.secret_hash);
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, ownerProof))).status).toBe(200);
  expect(f.values.get("mcp_identity_key")).toBe(ownerProof.public_key);
  expect(f.values.get("mcp_link_hash")).toBe(ownerProof.secret_hash);
  expect(f.values.has("mcp_token_hash")).toBe(false);
  expect((await f.mcp.fetch("mcp-link", request("mcp-link", "PUT", secret, ownerProof))).status).toBe(200);
});

it("forwards each client's protocol header unchanged, including omission", async () => {
  const f = await registered();
  const frames: any[] = [];
  const socket = { readyState: 1, send: (data: string) => {
    const frame = JSON.parse(data);
    frames.push(frame);
    void f.mcp.message(socket as WebSocket, JSON.stringify({ id: frame.id, response: { jsonrpc: "2.0", id: frame.request.id, result: {} } }));
  } } as unknown as WebSocket;
  f.sockets.push(socket);
  for (const version of ["2025-11-25", "2026-07-28", ""]) {
    const req = request("mcp", "POST", token, rpc("tools/list"));
    if (version) req.headers.set("MCP-Protocol-Version", version);
    req.headers.set("Mcp-Method", "tools/list");
    expect((await f.mcp.fetch("mcp", req)).status).toBe(200);
    expect(frames.at(-1).protocol_version).toBe(version);
    expect(frames.at(-1).mcp_headers).toEqual({ "mcp-method": "tools/list" });
    expect(frames.at(-1).request).toEqual(rpc("tools/list"));
    const notification = request("mcp", "POST", token, { jsonrpc: "2.0", method: "notifications/initialized" });
    if (version) notification.headers.set("MCP-Protocol-Version", version);
    expect((await f.mcp.fetch("mcp", notification)).status).toBe(202);
    expect(frames.at(-1).protocol_version).toBe(version);
  }
});

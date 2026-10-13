import { Mailbox } from "./mailbox";

export { Mailbox };

const MAC_ID = /^[a-f0-9]{32}$/;

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      if (request.method !== "GET") {
        return new Response("method not allowed", { status: 405, headers: { Allow: "GET" } });
      }
      return Response.json({ ok: true });
    }
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 4 || parts[0] !== "v1" || parts[1] !== "macs") {
      return new Response("not found", { status: 404 });
    }
    if (!MAC_ID.test(parts[2])) {
      return new Response("bad mac id", { status: 400 });
    }
    const box = parts[3];
    if (box !== "mcp" && box !== "mcp-link" && box !== "mcp-token" && box !== "ws" && box !== "pairing" && box !== "alerts" && box !== "approvals" && box !== "results") {
      return new Response("not found", { status: 404 });
    }
    const id = env.MAILBOX.idFromName(parts[2]);
    return env.MAILBOX.get(id).fetch(request);
  },
};

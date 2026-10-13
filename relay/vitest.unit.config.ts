import { defineConfig } from "vitest/config";

// Fast protocol tests with fake DO storage/sockets; no workerd listener needed.
export default defineConfig({ test: { include: ["test/mcp.unit.test.ts"], environment: "node" } });

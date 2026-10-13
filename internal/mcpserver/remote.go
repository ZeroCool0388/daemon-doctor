package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type requestBackend struct {
	context context.Context
	backend control.Backend
}

func (b requestBackend) Call(_ context.Context, r control.Request) (any, error) {
	// Legacy MCP sessions detach the SDK handler context. Never use that detached
	// context for backend execution: the forwarded deadline governs it. An
	// authorized fix can finish within that deadline after a socket disconnect.
	if err := b.context.Err(); err != nil {
		return nil, err
	}
	return b.backend.Call(b.context, r)
}

// RemoteDispatch serves sessionless JSON MCP in memory: no TCP listener is used.
// The SDK handles protocol validation, schemas and the existing tool handlers.
func RemoteDispatch(backend control.Backend, allowFixes bool) func(context.Context, json.RawMessage, http.Header) json.RawMessage {
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return New(requestBackend{context: req.Context(), backend: backend}, allowFixes)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, PropagateRequestCancellation: true})
	return func(ctx context.Context, raw json.RawMessage, headers http.Header) json.RawMessage {
		if ctx.Err() != nil {
			return nil
		}
		req := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", bytes.NewReader(raw)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for name, values := range headers {
			key := strings.ToLower(name)
			if key == "mcp-protocol-version" || key == "mcp-method" || key == "mcp-name" || strings.HasPrefix(key, "mcp-param-") {
				req.Header[name] = append([]string(nil), values...)
			}
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code == http.StatusAccepted {
			return nil
		}
		reply := out.Body.Bytes()
		if len(reply) > relay.MCPMaxBytes {
			var rpc struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
			}
			_ = json.Unmarshal(raw, &rpc)
			result := map[string]any{"jsonrpc": "2.0", "id": rpc.ID}
			message := "MCP response exceeds the 64 KiB limit; request fewer events or one service"
			if rpc.Method == "tools/call" {
				result["result"] = map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": message}}}
			} else {
				result["error"] = map[string]any{"code": -32603, "message": message}
			}
			data, _ := json.Marshal(result)
			return data
		}
		if json.Valid(reply) {
			return append(json.RawMessage(nil), reply...)
		}
		// Convert an SDK HTTP validation error without reflecting untrusted content.
		var rpc struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal(raw, &rpc)
		data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "error": map[string]any{"code": -32600, "message": "Invalid MCP request"}})
		return data
	}
}

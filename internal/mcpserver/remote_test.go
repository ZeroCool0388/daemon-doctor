package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
)

func remoteCall(t *testing.T, dispatch func(context.Context, json.RawMessage) json.RawMessage, method string, params any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 42, "method": method, "params": params})
	reply := dispatch(context.Background(), raw)
	var out map[string]any
	if err := json.Unmarshal(reply, &out); err != nil {
		t.Fatalf("reply %s: %v", reply, err)
	}
	if out["id"] != float64(42) {
		t.Fatal("id changed")
	}
	if out["error"] != nil {
		t.Fatalf("RPC error: %v", out)
	}
	return out["result"].(map[string]any)
}

func TestRemoteMCPProtocolAndSharedFixHandlers(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			backend, err := demo.NewMCP()
			if err != nil {
				t.Fatal(err)
			}
			dispatch := RemoteDispatch(backend, allow)
			init := remoteCall(t, dispatch, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
			if init["serverInfo"].(map[string]any)["name"] != "daemon-doctor" {
				t.Fatal("wrong server")
			}
			if reply := dispatch(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); len(reply) != 0 {
				t.Fatalf("notification reply %s", reply)
			}
			remoteCall(t, dispatch, "ping", map[string]any{})
			list := remoteCall(t, dispatch, "tools/list", map[string]any{})
			if len(list["tools"].([]any)) != 5 {
				t.Fatal("wrong tools")
			}
			read := remoteCall(t, dispatch, "tools/call", map[string]any{"name": "list_services", "arguments": map[string]any{}})
			if read["isError"] == true {
				t.Fatal("read failed")
			}
			offers := remoteCall(t, dispatch, "tools/call", map[string]any{"name": "list_offered_fixes", "arguments": map[string]any{}})
			id := offers["structuredContent"].(map[string]any)["offers"].([]any)[0].(map[string]any)["offer_id"]
			params := map[string]any{"name": "run_fix", "arguments": map[string]any{"offer_id": id}}
			fix := remoteCall(t, dispatch, "tools/call", params)
			if allow {
				if fix["isError"] == true || fix["structuredContent"].(map[string]any)["fixed"] != true {
					t.Fatal("fix failed")
				}
				if replay := remoteCall(t, dispatch, "tools/call", params); replay["isError"] != true {
					t.Fatal("replayed fix")
				}
			} else if fix["isError"] != true {
				t.Fatal("disabled fix accepted")
			}
		})
	}
}

type largeRemoteBackend struct{}

func (largeRemoteBackend) Call(context.Context, control.Request) (any, error) {
	return map[string]any{"value": strings.Repeat("x", 65*1024)}, nil
}
func TestRemoteMCPResponseLimitIsToolError(t *testing.T) {
	result := remoteCall(t, RemoteDispatch(largeRemoteBackend{}, false), "tools/call", map[string]any{"name": "list_services", "arguments": map[string]any{}})
	if result["isError"] != true {
		t.Fatal("oversized response was not a tool error")
	}
}

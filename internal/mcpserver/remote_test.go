package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
)

func remoteCall(t *testing.T, dispatch func(context.Context, json.RawMessage, http.Header) json.RawMessage, method string, params any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 42, "method": method, "params": params})
	reply := dispatch(context.Background(), raw, remoteHeaders("2025-11-25", method, ""))
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
			if reply := dispatch(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), remoteHeaders("2025-11-25", "notifications/initialized", "")); len(reply) != 0 {
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

type remoteBackendFunc func(context.Context, control.Request) (any, error)

func (f remoteBackendFunc) Call(ctx context.Context, request control.Request) (any, error) {
	return f(ctx, request)
}

func remoteParams(version, tool string) map[string]any {
	args := map[string]any{}
	if tool == "run_fix" {
		args["offer_id"] = "offered"
	}
	if tool == "get_service_details" {
		args["id"] = "example"
	}
	params := map[string]any{"name": tool, "arguments": args}
	if version == "2026-07-28" {
		params["_meta"] = map[string]any{mcp.MetaKeyProtocolVersion: version, mcp.MetaKeyClientCapabilities: map[string]any{}, mcp.MetaKeyClientInfo: map[string]any{"name": "test", "version": "1"}}
	}
	return params
}

func TestRemoteMCPBindsAllBackendCallsToLinkContext(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		for _, tool := range []string{"list_services", "get_service_details", "recent_events", "list_offered_fixes", "run_fix"} {
			t.Run(version+"/"+tool, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				started := make(chan context.Context, 1)
				backend := remoteBackendFunc(func(callCtx context.Context, _ control.Request) (any, error) {
					started <- callCtx
					<-callCtx.Done()
					return nil, callCtx.Err()
				})
				dispatch := RemoteDispatch(backend, true)
				raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": remoteParams(version, tool)})
				done := make(chan struct{})
				go func() { dispatch(ctx, raw, remoteHeaders(version, "tools/call", tool)); close(done) }()
				select {
				case callCtx := <-started:
					if callCtx.Done() != ctx.Done() {
						t.Error("backend did not receive the original link context")
					}
					deadline, ok := callCtx.Deadline()
					want, _ := ctx.Deadline()
					if !ok || !deadline.Equal(want) {
						t.Error("backend deadline lost")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("backend never started")
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("SDK session close hung after link cancellation")
				}
			})
		}
	}
}

func TestRemoteMCPDeadlineStopsBackendAndExpiredFixNeverStarts(t *testing.T) {
	var calls atomic.Int32
	backend := remoteBackendFunc(func(ctx context.Context, _ control.Request) (any, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	dispatch := RemoteDispatch(backend, true)
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": remoteParams("2025-11-25", "run_fix")})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { dispatch(ctx, raw, remoteHeaders("2025-11-25", "tools/call", "run_fix")); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline hung session shutdown")
	}
	if calls.Load() != 1 || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("backend deadline was lost")
	}
	// The same request must never execute if it reaches dispatch after expiry.
	dispatch(ctx, raw, remoteHeaders("2025-11-25", "tools/call", "run_fix"))
	if calls.Load() != 1 {
		t.Fatal("expired fix reached backend")
	}
}

func remoteHeaders(version, method, name string) http.Header {
	headers := make(http.Header)
	if version != "" {
		headers.Set("MCP-Protocol-Version", version)
	}
	if version == "2026-07-28" {
		headers.Set("Mcp-Method", method)
		if name != "" {
			headers.Set("Mcp-Name", name)
		}
	}
	return headers
}

func TestRemoteMCPNegotiatedVersionAndMetadataAgree(t *testing.T) {
	backend, err := demo.NewMCP()
	if err != nil {
		t.Fatal(err)
	}
	dispatch := RemoteDispatch(backend, false)
	// Current protocol discovers supported versions rather than using initialize.
	version := "2026-07-28"
	params := remoteParams(version, "list_services")
	discover, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]any{"_meta": params["_meta"]}})
	var discovered struct {
		Result struct {
			SupportedVersions []string `json:"supportedVersions"`
		}
		Error any
	}
	reply := dispatch(context.Background(), discover, remoteHeaders(version, "server/discover", ""))
	if err := json.Unmarshal(reply, &discovered); err != nil || discovered.Error != nil || !slices.Contains(discovered.Result.SupportedVersions, version) {
		t.Fatalf("discovery failed: %s %v", reply, err)
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params})
	var out struct {
		Result *struct {
			IsError bool `json:"isError"`
		}
		Error *struct{ Code int }
	}
	if err := json.Unmarshal(dispatch(context.Background(), raw, remoteHeaders(version, "tools/call", "list_services")), &out); err != nil || out.Error != nil || out.Result == nil || out.Result.IsError {
		t.Fatalf("negotiated call failed: %+v %v", out, err)
	}
	for _, header := range []string{"2025-11-25", ""} {
		if err := json.Unmarshal(dispatch(context.Background(), raw, remoteHeaders(header, "tools/call", "list_services")), &out); err != nil || out.Error == nil {
			t.Fatalf("header mismatch accepted: %+v %v", out, err)
		}
	}
}

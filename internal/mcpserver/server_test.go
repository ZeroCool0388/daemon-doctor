package mcpserver

import (
	"context"
	"encoding/json"
	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
	"time"
)

func connect(t *testing.T, allow bool) (context.Context, *mcp.ClientSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	b, err := demo.NewMCP()
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := New(b, allow).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return ctx, cs
}

func decoded(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestToolSchemasAndAnnotations(t *testing.T) {
	ctx, cs := connect(t, true)
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 5 {
		t.Fatalf("tools %d", len(list.Tools))
	}
	for _, tool := range list.Tools {
		schema := tool.InputSchema.(map[string]any)
		if schema["type"] != "object" {
			t.Fatalf("schema %v", schema)
		}
		if tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("open-world annotation")
		}
		if tool.Name == "run_fix" {
			if tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.IdempotentHint {
				t.Fatal("unsafe fix annotations")
			}
			required := schema["required"].([]any)
			if len(required) != 1 || required[0] != "offer_id" {
				t.Fatalf("fix schema %v", schema)
			}
		} else if !tool.Annotations.ReadOnlyHint || *tool.Annotations.DestructiveHint {
			t.Fatal("read-only annotations")
		}
	}
}

func TestReadToolsAndFixedReplay(t *testing.T) {
	ctx, cs := connect(t, true)
	for _, p := range []*mcp.CallToolParams{{Name: "get_service_details", Arguments: map[string]any{"id": "example-desktop-app"}}, {Name: "recent_events", Arguments: map[string]any{"limit": 2}}, {Name: "list_services"}} {
		res, err := cs.CallTool(ctx, p)
		if err != nil || res.IsError {
			t.Fatalf("%s: %v %v", p.Name, res, err)
		}
		if len(decoded(t, res)) == 0 {
			t.Fatal("no structured result")
		}
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_offered_fixes"})
	if err != nil || res.IsError {
		t.Fatal(res, err)
	}
	items := decoded(t, res)["offers"].([]any)
	if len(items) != 1 {
		t.Fatalf("offers %v", items)
	}
	id := items[0].(map[string]any)["offer_id"]
	params := &mcp.CallToolParams{Name: "run_fix", Arguments: map[string]any{"offer_id": id, "service": "example-desktop-app"}}
	res, err = cs.CallTool(ctx, params)
	if err != nil || res.IsError || decoded(t, res)["fixed"] != true {
		t.Fatalf("fix %v %v", res, err)
	}
	res, err = cs.CallTool(ctx, params)
	if err != nil || !res.IsError {
		t.Fatalf("replay %v %v", res, err)
	}
}

func TestInvalidInputsAndReadOnlyGate(t *testing.T) {
	ctx, cs := connect(t, false)
	for _, p := range []*mcp.CallToolParams{
		{Name: "run_fix", Arguments: map[string]any{}},
		{Name: "run_fix", Arguments: map[string]any{"offer_id": "anything"}},
		{Name: "get_service_details", Arguments: map[string]any{"id": "unknown"}},
		{Name: "recent_events", Arguments: map[string]any{"limit": -1}},
		{Name: "list_services", Arguments: map[string]any{"argv": []string{"anything"}}},
	} {
		res, err := cs.CallTool(ctx, p)
		if err == nil && !res.IsError {
			t.Fatalf("accepted %v: %v", p, res)
		}
	}
}

package cli

import (
	"bytes"
	"context"
	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Run the actual CLI in a child so stdio framing and stdout cleanliness are tested.
func TestMCPProcess(t *testing.T) {
	if os.Getenv("DD_MCP_TEST_CHILD") == "1" {
		os.Exit(Run([]string{"daemon-doctor", "mcp", "--demo"}, os.Stdin, os.Stdout, os.Stderr))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPProcess$")
	cmd.Env = append(os.Environ(), "DD_MCP_TEST_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err, stderr.String())
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil || len(list.Tools) != 5 {
		t.Fatalf("stdio tools %v %v; %s", list, err, stderr.String())
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_services"})
	if err != nil || res.IsError {
		t.Fatalf("stdio read %v %v", res, err)
	}
}

func TestMCPFlags(t *testing.T) {
	for _, args := range [][]string{{"mcp", "--demo", "--config", "unused"}, {"mcp", "extra"}, {"mcp", "--bogus"}} {
		var out, err bytes.Buffer
		if code := Run(append([]string{"daemon-doctor"}, args...), bytes.NewReader(nil), &out, &err); code != 2 {
			t.Fatalf("%v code %d: %s", args, code, err.String())
		}
	}
}

func TestLiveMCPSocketRoundTrip(t *testing.T) {
	if cfg := os.Getenv("DD_MONITOR_TEST_CONFIG"); cfg != "" {
		os.Exit(Run([]string{"daemon-doctor", "run", "--config", cfg}, os.Stdin, os.Stdout, os.Stderr))
	}
	if cfg := os.Getenv("DD_MCP_LIVE_TEST_CONFIG"); cfg != "" {
		os.Exit(Run([]string{"daemon-doctor", "mcp", "--allow-fixes", "--config", cfg}, os.Stdin, os.Stdout, os.Stderr))
	}
	// Short paths keep the Unix socket below macOS's path limit.
	dir, err := os.MkdirTemp("/tmp", "ddlive-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Mkdir(filepath.Join(dir, "plugins"), 0700); err != nil {
		t.Fatal(err)
	}
	plugin := `id: fictional-sync
name: Fictional Sync
process:
  match: fictional-daemon-doctor-test-process
checks:
  - type: process_running
fixes:
  restart:
    kind: restart
`
	if err = os.WriteFile(filepath.Join(dir, "plugins", "example.yaml"), []byte(plugin), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(cfg, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 100ms\nstate_dir: state\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	monitor := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLiveMCPSocketRoundTrip$")
	monitor.Env = append(os.Environ(), "DD_MONITOR_TEST_CONFIG="+cfg)
	if err = monitor.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = monitor.Process.Signal(os.Interrupt)
		if err := monitor.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "state", "control", "control.sock")); !os.IsNotExist(err) {
			t.Error("monitor did not clean up socket")
		}
	}()
	socket := filepath.Join(dir, "state", "control", "control.sock")
	c := &control.Client{Path: socket}
	ready := false
	for range 100 {
		if data, e := c.Call(ctx, control.Request{Method: "offers"}); e == nil {
			if len(data.(map[string]any)["offers"].([]any)) == 1 {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("temporary monitor did not offer the fictional fix")
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLiveMCPSocketRoundTrip$")
	cmd.Env = append(os.Environ(), "DD_MCP_LIVE_TEST_CONFIG="+cfg)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "live-test", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for _, p := range []*mcp.CallToolParams{{Name: "list_services"}, {Name: "get_service_details", Arguments: map[string]any{"id": "fictional-sync"}}, {Name: "recent_events"}, {Name: "list_offered_fixes"}} {
		res, e := cs.CallTool(ctx, p)
		if e != nil || res.IsError {
			t.Fatalf("real socket tool %s %v %v", p.Name, res, e)
		}
	}
	data, err := c.Call(ctx, control.Request{Method: "offers"})
	if err != nil {
		t.Fatal(err)
	}
	id := data.(map[string]any)["offers"].([]any)[0].(map[string]any)["offer_id"]
	// The client opts in, but daemon remains read-only. Neither RPC nor MCP may act.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_fix", Arguments: map[string]any{"offer_id": id}})
	if err != nil || !res.IsError {
		t.Fatalf("daemon gate bypassed: %v %v", res, err)
	}
	events, err := logbook.Read(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for _, e := range events {
		if e.Kind == "fix" {
			t.Fatal("read-only daemon executed fix")
		}
		if e.Kind == "approval" && e.Source == "mcp" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("daemon refusal not audited")
	}
}

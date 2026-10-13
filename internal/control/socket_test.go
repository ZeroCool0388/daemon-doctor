package control_test

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serve(t *testing.T) (string, *control.Server) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ddctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	b, err := demo.NewMCP()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	s, err := control.Listen(path, b)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	return path, s
}

func TestSocketToolsPermissionsAndReplay(t *testing.T) {
	path, _ := serve(t)
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
	c := &control.Client{Path: path}
	ctx := context.Background()
	for _, r := range []control.Request{{Method: "service", ID: "example-desktop-app"}, {Method: "events", Limit: 100}} {
		if _, err := c.Call(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	data, err := c.Call(ctx, control.Request{Method: "offers"})
	if err != nil {
		t.Fatal(err)
	}
	items := data.(map[string]any)["offers"].([]any)
	if len(items) == 0 {
		t.Fatal("no demo offer")
	}
	id := items[0].(map[string]any)["offer_id"].(string)
	res, err := c.Call(ctx, control.Request{Method: "run_fix", OfferID: id})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["fixed"] != true {
		t.Fatalf("fix: %v", res)
	}
	if _, err = c.Call(ctx, control.Request{Method: "run_fix", OfferID: id}); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay: %v", err)
	}
	if _, err = c.Call(ctx, control.Request{Method: "shell"}); err == nil {
		t.Fatal("unknown method allowed")
	}
}

func TestMalformedRequestsRefused(t *testing.T) {
	path, _ := serve(t)
	for _, request := range []string{`{"method":"shell"}`, `{"method":"status","argv":["echo"]}`, `{"method":"status"} {}`, `{"method":"run_fix"}`, strings.Repeat("x", control.MaxRequestBytes+1)} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte(request + "\n"))
		scan := bufio.NewScanner(conn)
		if !scan.Scan() {
			t.Fatal("no refusal response", scan.Err())
		}
		var res map[string]any
		if err = json.Unmarshal(scan.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res["error"] == nil {
			t.Fatalf("allowed malformed request %v", res)
		}
		conn.Close()
	}
}

func TestSocketOwnershipCleanupAndUnsafePaths(t *testing.T) {
	path, s := serve(t)
	b, _ := demo.NewMCP()
	if other, err := control.Listen(path, b); err == nil {
		other.Close()
		t.Fatal("second server stole socket")
	}
	s.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket not removed")
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := control.Listen(path, b); err == nil {
		other.Close()
		t.Fatal("regular file replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep" {
		t.Fatal("regular file overwritten")
	}
}

func TestMissingSocketClearErrorAndSecretBlanking(t *testing.T) {
	c := &control.Client{Path: filepath.Join(t.TempDir(), "missing")}
	if _, err := c.Call(context.Background(), control.Request{Method: "status"}); err == nil || !strings.Contains(err.Error(), "daemon control socket unavailable") {
		t.Fatalf("missing: %v", err)
	}
	data, err := control.Sanitize(map[string]any{"detail": "token=fictional-secret", "nested": []string{"password=fictional"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fictional") {
		t.Fatalf("secret not blanked %s", data)
	}
	var v any
	if err = json.Unmarshal(data, &v); err != nil {
		t.Fatal("blanking broke JSON", err)
	}
}

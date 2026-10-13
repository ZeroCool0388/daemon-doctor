package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadExample(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != 30*time.Second {
		t.Fatalf("interval %s", cfg.Interval)
	}
	if !strings.HasSuffix(cfg.PluginsDir, string(filepath.Separator)+"plugins") {
		t.Fatalf("plugins dir %s", cfg.PluginsDir)
	}
	if cfg.LogPath != filepath.Clean("/tmp/daemon-doctor/events.jsonl") {
		t.Fatalf("log path %s", cfg.LogPath)
	}
	if cfg.RelayURL != "" {
		t.Fatalf("example relay URL %q", cfg.RelayURL)
	}
}

func TestRejectsBadIntervalAndUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 0s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected interval to be rejected")
	}
	if err := os.WriteFile(path, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\ntoken: secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}

func TestRelayURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay:\n  url: https://your-relay.example.workers.dev\nstate_dir: state\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RelayURL != "https://your-relay.example.workers.dev" {
		t.Fatalf("relay URL %q", cfg.RelayURL)
	}
	if cfg.StateDir != filepath.Join(dir, "state") {
		t.Fatalf("state dir %s", cfg.StateDir)
	}
	for _, raw := range []string{
		"relay_url: https://user:secret@relay.example.invalid\n",
		"relay_url: file:///tmp/relay\n",
		"relay_url: relay.example.invalid\n",
	} {
		text := "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\n" + raw
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
}

func TestNestedRelayConfig(t *testing.T) {
	for _, tc := range []struct {
		name, ext, body string
		wantError       bool
	}{
		{"yaml", ".yaml", "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay:\n  url: https://your-relay.example.workers.dev/\n", false},
		{"toml", ".toml", "plugins_dir = 'plugins'\nlog_path = 'events.jsonl'\ninterval = '30s'\n[relay]\nurl = 'https://your-relay.example.workers.dev'\n", false},
		{"legacy", ".yaml", "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay_url: https://your-relay.example.workers.dev\n", false},
		{"conflict", ".yaml", "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay_url: https://your-relay.example.workers.dev\nrelay:\n  url: https://your-relay.example.workers.dev\n", true},
		{"unknown yaml", ".yaml", "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay:\n  endpoint: https://your-relay.example.workers.dev\n", true},
		{"unknown toml", ".toml", "plugins_dir = 'plugins'\nlog_path = 'events.jsonl'\ninterval = '30s'\n[relay]\nendpoint = 'https://your-relay.example.workers.dev'\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config"+tc.ext)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.wantError {
				if err == nil {
					t.Fatal("accepted invalid config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.RelayURL != "https://your-relay.example.workers.dev" {
				t.Fatalf("relay URL %q", cfg.RelayURL)
			}
		})
	}
}

func TestControlDefaultsAndOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	for _, tc := range []struct {
		extra          string
		enabled, fixes bool
	}{
		{"", true, false}, {"control:\n  enabled: false\n", false, false}, {"control:\n  allow_fixes: true\n", true, true},
	} {
		if err := os.WriteFile(path, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nstate_dir: state\n"+tc.extra), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ControlEnabled != tc.enabled || cfg.ControlAllowFixes != tc.fixes || cfg.ControlSocket != filepath.Join(dir, "state", "control", "control.sock") {
			t.Fatalf("control config %+v", cfg)
		}
	}
}

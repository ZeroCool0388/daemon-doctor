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

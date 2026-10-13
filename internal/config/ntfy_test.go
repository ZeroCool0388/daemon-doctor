package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/notify"
)

func TestNtfySetupYAMLAndTOML(t *testing.T) {
	for _, ext := range []string{"yaml", "toml"} {
		t.Run(ext, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config."+ext)
			body := "# keep this comment\nplugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\ncontrol:\n  allow_fixes: true\nnotify:\n  ntfy:\n    server: https://notify.example.invalid\n    enabled: true\n"
			if ext == "toml" {
				body = "plugins_dir = 'plugins'\nlog_path = 'events.jsonl'\ninterval = '30s'\n[control]\nallow_fixes = true\n[notify.ntfy]\nserver = 'https://notify.example.invalid'\nenabled = true\n"
			}
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			link, err := SetupNtfy(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil || !cfg.Ntfy.Enabled || !cfg.ControlAllowFixes || cfg.Ntfy.Server != "https://notify.example.invalid" {
				t.Fatal("setup changed existing configuration")
			}
			if len(cfg.Ntfy.Topic) != 43 || link != cfg.Ntfy.Server+"/"+cfg.Ntfy.Topic {
				t.Fatal("subscribe link or topic incorrect")
			}
			stat, err := os.Stat(path)
			if err != nil || stat.Mode().Perm() != 0600 {
				t.Fatal("private config permissions incorrect")
			}
			encoded, _ := os.ReadFile(path)
			if ext == "yaml" && !strings.Contains(string(encoded), "keep this comment") {
				t.Fatal("YAML comment removed")
			}
			previous := cfg.Ntfy.Topic
			if _, err := SetupNtfy(path); err != nil {
				t.Fatal(err)
			}
			cfg, err = Load(path)
			if err != nil || cfg.Ntfy.Topic == previous {
				t.Fatal("setup did not generate a new topic")
			}
		})
	}
}

func TestNtfySetupRejectsCheckoutAndPreservesInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: invalid\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := SetupNtfy(path); err == nil {
		t.Fatal("invalid config accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != string(original) {
		t.Fatal("invalid config was changed")
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := SetupNtfy(path); err == nil || !strings.Contains(err.Error(), "outside a Git checkout") {
		t.Fatal("topic could be written into a checkout")
	}
	// A symlink outside the checkout must not allow a write into it.
	link := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := SetupNtfy(link); err == nil {
		t.Fatal("symlink bypassed checkout check")
	}
}

func TestNtfyConfigValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	prefix := "plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\n"
	topic, err := notify.GenerateTopic()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		extra string
		bad   bool
	}{
		{"", false},
		{"notify:\n  ntfy:\n    enabled: true\n    topic: " + topic + "\n", false},
		{"notify:\n  ntfy:\n    enabled: true\n", true},
		{"notify:\n  ntfy:\n    topic: 'bad/path'\n", true},
		{"notify:\n  ntfy:\n    server: https://user:password@notify.example.invalid\n", true},
		{"notify:\n  ntfy:\n    unknown: value\n", true},
	} {
		if err := os.WriteFile(path, []byte(prefix+tc.extra), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if (err != nil) != tc.bad {
			t.Fatal("incorrect ntfy validation")
		}
		if err == nil && cfg.Ntfy.Server != notify.DefaultServer {
			t.Fatal("missing default server")
		}
		if err != nil && strings.Contains(err.Error(), topic) {
			t.Fatal("config error leaked topic")
		}
	}
}

func TestNtfyTopicCannotLeakThroughConfigErrors(t *testing.T) {
	topic, err := notify.GenerateTopic()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, tc := range []struct{ ext, body string }{
		{"yaml", "notify:\n  ntfy:\n    topic: &private " + topic + "\nplugins_dir: plugins\nlog_path: events.jsonl\ninterval: *private\n"},
		{"toml", "plugins_dir='plugins'\nlog_path='events.jsonl'\ninterval='30s'\n[notify.ntfy]\ntopic = " + topic + "\n"},
	} {
		path := filepath.Join(dir, "config."+tc.ext)
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || strings.Contains(err.Error(), topic) {
			t.Fatal("config parse or validation error disclosed topic")
		}
	}
}

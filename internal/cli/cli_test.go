package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	plugDir := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "plugins", "example-desktop-app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugDir, "example-desktop-app.yaml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "events.jsonl")
	cfg := "plugins_dir: plugins\nlog_path: " + logPath + "\ninterval: 30s\n"
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStatusReportsMissingProcess(t *testing.T) {
	path := writeFixture(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"daemon-doctor", "status", "--config", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "example-desktop-app") || !strings.Contains(stdout.String(), "not running") {
		t.Fatalf("stdout: %s", stdout.String())
	}
	logPath := filepath.Join(filepath.Dir(path), "events.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"kind":"check"`)) {
		t.Fatalf("log: %s", data)
	}
}

func TestFixDryRunAndDeclinedPrompt(t *testing.T) {
	path := writeFixture(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"daemon-doctor", "fix", "--config", path, "--service", "example-desktop-app", "--action", "restart", "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Dry run") {
		t.Fatalf("stdout: %s", stdout.String())
	}

	path = writeFixture(t)
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--service", "example-desktop-app", "--action", "force-restart"}, strings.NewReader("n\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Fix not run.") {
		t.Fatalf("stdout: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "events.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("declined fix should not open the log, stat err %v", err)
	}
}

func TestSmuggledFixIsRefused(t *testing.T) {
	path := writeFixture(t)
	marker := filepath.Join(t.TempDir(), "marker")
	var stdout, stderr bytes.Buffer
	action := "restart; touch " + marker
	code := Run([]string{"daemon-doctor", "fix", "--config", path, "--service", "example-desktop-app", "--action", action, "--yes"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected a non-zero exit")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("smuggled command created a file")
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"daemon-doctor"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"daemon-doctor", "help"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("help code %d", code)
	}
	if !strings.Contains(stdout.String(), "dry-run") {
		t.Fatalf("stdout: %s", stdout.String())
	}
}

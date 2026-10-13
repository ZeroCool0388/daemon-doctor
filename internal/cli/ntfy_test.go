package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/config"
)

func TestNtfySetupCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := Run([]string{"doctor", "ntfy-setup", "--config", path}, strings.NewReader(""), &out, &stderr)
	cfg, err := config.Load(path)
	if code != 0 || err != nil || !cfg.Ntfy.Enabled || strings.TrimSpace(out.String()) != cfg.Ntfy.Server+"/"+cfg.Ntfy.Topic || strings.Count(out.String(), "\n") != 1 || stderr.Len() != 0 {
		t.Fatal("setup command failed")
	}
	if _, err := os.Stat(filepath.Join(dir, "events.jsonl")); !os.IsNotExist(err) {
		t.Fatal("setup wrote a log")
	}
	out.Reset()
	stderr.Reset()
	if Run([]string{"doctor", "ntfy-setup", "extra"}, nil, &out, &stderr) != 2 {
		t.Fatal("unexpected setup argument accepted")
	}
}

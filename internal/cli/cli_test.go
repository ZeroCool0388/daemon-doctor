package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/security"
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

func TestUnwatchedStopFlag(t *testing.T) {
	path := writeFixture(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"daemon-doctor", "fix", "--config", path, "--service", "example-desktop-app", "--process", "ExampleTool", "--action", "stop"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--process", "ExampleTool", "--action", "restart"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}

	logPath := filepath.Join(filepath.Dir(path), "events.jsonl")
	line := []byte("{\"time\":\"2026-01-02T21:00:00Z\",\"kind\":\"alert\",\"service_id\":\"unwatched\",\"alert_kind\":\"cpu_hog\",\"message\":\"A process that is not on the watched list (ExampleTool) has used 90% of the CPU for 5 minutes.\",\"offer_fix\":true,\"action\":\"stop\",\"process\":\"ExampleTool\"}\n")
	if err := os.WriteFile(logPath, line, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--process", "ExampleTool;rm", "--action", "stop", "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("stdout %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--process", "other-tool", "--action", "stop", "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "not approved") {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--process", "ExampleTool", "--action", "stop", "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Dry run") {
		t.Fatalf("stdout %s", stdout.String())
	}
}

func TestPairPrintsPayloadWithoutPrivateKey(t *testing.T) {
	path := writeFixture(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"daemon-doctor", "pair", "--config", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "payload daemon-doctor:1:") || !strings.Contains(text, "\n") {
		t.Fatalf("stdout: %s", text)
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.PrivateKey == "" || strings.Contains(text, file.PrivateKey) {
		t.Fatal("pair output contains the private key")
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(path), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode %o", info.Mode().Perm())
	}

	payload := strings.TrimPrefix(strings.Split(text, "\n")[0], "payload ")
	_, pairingCode, _, _, err := security.ParsePayload(strings.TrimSpace(payload))
	if err != nil {
		t.Fatal(err)
	}
	phone, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.AcceptPairing(time.Now(), pairingCode, phone); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "pair", "--list", "--config", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("list code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), security.Fingerprint(phone)) {
		t.Fatalf("stdout %s", stdout.String())
	}
}

func TestFixApprovalFile(t *testing.T) {
	path := writeFixture(t)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"daemon-doctor", "pair", "--config", path}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	payload := strings.TrimPrefix(strings.Split(stdout.String(), "\n")[0], "payload ")
	_, pairingCode, _, _, err := security.ParsePayload(strings.TrimSpace(payload))
	if err != nil {
		t.Fatal(err)
	}
	phonePub, phonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := sec.AcceptPairing(now, pairingCode, phonePub); err != nil {
		t.Fatal(err)
	}
	alertID := security.NewID()
	if err := sec.RecordAlert(security.Raised{
		ID:        alertID,
		ServiceID: "example-desktop-app",
		Actions:   []string{"restart"},
		At:        now,
	}); err != nil {
		t.Fatal(err)
	}
	signed, err := security.Sign(phonePriv, security.Approval{
		MacID:   sec.MacID(),
		AlertID: alertID,
		FixID:   "restart",
		Nonce:   security.NewID(),
		Expires: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := security.MarshalApproval(signed)
	if err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(filepath.Dir(path), "approval.json")
	if err := os.WriteFile(approvalPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Run([]string{"daemon-doctor", "fix", "--config", path, "--approval", approvalPath, "--service", "example-desktop-app"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--approval", approvalPath, "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Dry run") {
		t.Fatalf("code %d stdout %s stderr %s", code, stdout.String(), stderr.String())
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["command"] = "touch marker"
	smuggled, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "marker")
	obj["command"] = "touch " + marker
	smuggled, err = json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(approvalPath, smuggled, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"daemon-doctor", "fix", "--config", path, "--approval", approvalPath, "--dry-run"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("stdout %s", stdout.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("smuggled command created a file")
	}
}

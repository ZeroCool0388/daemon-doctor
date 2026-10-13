package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/config"
	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
)

type tokenTransport func(*http.Request) (*http.Response, error)

func (f tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMCPTokenCommandPrintsOnceOnlyAfterRegistration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins_dir: plugins\nlog_path: events.jsonl\ninterval: 30s\nrelay:\n  url: https://relay.example.invalid\n  mcp_link: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	var registeredHash string
	var requests int
	status := 200
	http.DefaultTransport = tokenTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if len(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) != 43 {
			t.Error("missing link credential")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if strings.HasSuffix(r.URL.Path, "/mcp-token") {
			registeredHash = body["token_hash"]
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"registered":true}`)), Request: r}, nil
	})
	var out, stderr bytes.Buffer
	if code := Run([]string{"doctor", "mcp-token", "--config", path}, strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	token := strings.TrimSpace(out.String())
	if len(token) != 43 || strings.Count(out.String(), "\n") != 1 || registeredHash != relay.MCPTokenHash(token) || requests != 2 {
		t.Fatal("token output/registration")
	}
	for _, name := range []string{"identity.json", "mcp-link.secret"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || bytes.Contains(data, []byte(token)) {
			t.Fatal("plaintext token saved", err)
		}
	}
	sec, err := security.Open(dir)
	if err != nil || len(sec.Phones()) != 0 {
		t.Fatal("unexpected pairing", err)
	}
	out.Reset()
	stderr.Reset()
	status = 401
	if code := Run([]string{"doctor", "mcp-token", "--config", path}, strings.NewReader(""), &out, &stderr); code != 1 || out.Len() != 0 {
		t.Fatal("failed command exposed token")
	}
}

func TestAttachRemoteRelayCreatesIdentityWithoutPairing(t *testing.T) {
	cfg := config.Config{StateDir: t.TempDir(), RelayURL: "https://relay.example.invalid", RelayMCPLink: true}
	d := &doctor.Doctor{}
	if err := attachRelay(d, cfg); err != nil {
		t.Fatal(err)
	}
	sec, err := security.Open(cfg.StateDir)
	if err != nil || len(sec.Phones()) != 0 {
		t.Fatal("identity without pairing", err)
	}
}

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/skip2/go-qrcode"
)

func TestPairPNGAndConfiguredRelay(t *testing.T) {
	path := writeFixture(t)
	dir := filepath.Dir(path)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/pairing") || r.URL.Query().Get("after") != "0" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(dir, "pending.json"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		var pending struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(data, &pending); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{map[string]any{"id": 1, "kind": "pairing", "body": map[string]string{"code": pending.Code, "public_key": base64.RawURLEncoding.EncodeToString(pub)}}}})
	}))
	defer srv.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nrelay:\n  url: " + srv.URL + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pairing.png")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"daemon-doctor", "pair", "--config", path, "--out", out}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	payload := strings.TrimPrefix(strings.Split(stdout.String(), "\n")[0], "payload ")
	id, code, relayURL, key, err := security.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id != sec.MacID() || !bytes.Equal(key, sec.PublicKey()) || relayURL != srv.URL || code == "" {
		t.Fatal("pairing payload differs from configured identity or relay")
	}
	if len(sec.Phones()) != 1 || !bytes.Equal(sec.Phones()[0], pub) {
		t.Fatal("phone was not paired")
	}
	if !strings.Contains(stdout.String(), "paired "+security.Fingerprint(pub)) || !strings.Contains(stdout.String(), "█") {
		t.Fatalf("missing terminal QR or pairing confirmation: %s", stdout.String())
	}
	checkPairPNG(t, out, payload)
}

func checkPairPNG(t *testing.T, path, payload string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("PNG permissions %o", info.Mode().Perm())
	}
	code, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	bitmap := code.Bitmap()
	size := img.Bounds().Dx()
	if size != 512 || img.Bounds().Dy() != size {
		t.Fatalf("PNG bounds %v", img.Bounds())
	}
	// Compare each module's centre to the matrix for the printed payload.
	for y, row := range bitmap {
		for x, dark := range row {
			r, g, b, _ := img.At((2*x+1)*size/(2*len(row)), (2*y+1)*size/(2*len(bitmap))).RGBA()
			if (r == 0 && g == 0 && b == 0) != dark {
				t.Fatalf("PNG module %d,%d differs from payload", x, y)
			}
		}
	}
}

func TestPairPNGLocalAndOutputErrors(t *testing.T) {
	path := writeFixture(t)
	out := filepath.Join(filepath.Dir(path), "pairing.png")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"daemon-doctor", "pair", "--config", path, "--out", out}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	payload := strings.TrimPrefix(strings.Split(stdout.String(), "\n")[0], "payload ")
	checkPairPNG(t, out, payload)
	original, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := security.WriteQRPNG(payload, out); err == nil {
		t.Fatal("overwrote existing PNG")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(original, after) {
		t.Fatal("existing file changed")
	}
	pendingPath := filepath.Join(filepath.Dir(path), "pending.json")
	pending, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"daemon-doctor", "pair", "--config", path, "--out", out}, strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("accepted an existing output file")
	}
	unchanged, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending, unchanged) {
		t.Fatal("failed output replaced the active pairing code")
	}
	for _, args := range [][]string{
		{"--list", "--out", out},
		{"--out", filepath.Join(filepath.Dir(path), "missing", "pairing.png")},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(append([]string{"daemon-doctor", "pair", "--config", path}, args...), strings.NewReader(""), &stdout, &stderr); code == 0 {
			t.Fatal("accepted invalid output arguments")
		}
	}
}

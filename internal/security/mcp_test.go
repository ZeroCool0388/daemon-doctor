package security

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMCPLinkSecretPersistsIndependentlyOfPairing(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.MCPLinkSecret()
	if err != nil || len(secret) != 43 {
		t.Fatal("secret generation", err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := reopened.MCPLinkSecret()
	if err != nil || secret != again {
		t.Fatal("secret did not persist", err)
	}
	st, err := os.Stat(filepath.Join(dir, "mcp-link.secret"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("credential permissions", err)
	}
	if len(reopened.Phones()) != 0 {
		t.Fatal("requires phone pairing")
	}
}

func TestMCPConcurrentIdentityAndLinkSecret(t *testing.T) {
	dir := t.TempDir()
	type result struct {
		id, secret string
		err        error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func() {
			s, err := LoadOrCreate(dir)
			if err != nil {
				results <- result{err: err}
				return
			}
			secret, err := s.MCPLinkSecret()
			results <- result{id: s.MacID(), secret: secret, err: err}
		}()
	}
	var first result
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if i == 0 {
			first = r
		} else if r.id != first.id || r.secret != first.secret {
			t.Fatal("competing credentials created")
		}
	}
}

func TestMCPRegistrationSignsExistingKeyAndBindsEndpoint(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	private := ed25519.NewKeyFromSeed(seed)
	s := &Store{macID: NewID(), private: private, public: private.Public().(ed25519.PublicKey)}
	oldPhoneID := s.MacID()
	var vector struct {
		MacID string `json:"mac_id"`
		MCPLinkRegistration
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mcp-registration-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	proof := s.MCPRegistration(strings.Repeat("S", 43))
	if s.MCPMacID() != vector.MacID || proof != vector.MCPLinkRegistration {
		t.Fatal("cross-language enrollment vector mismatch")
	}
	if s.MacID() != oldPhoneID || s.MCPMacID() == oldPhoneID {
		t.Fatal("phone identity changed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || !ed25519.Verify(s.PublicKey(), MCPRegistrationMessage(s.MCPMacID(), proof.PublicKey, proof.SecretHash), signature) {
		t.Fatal("ownership signature invalid")
	}
	if ed25519.Verify(s.PublicKey(), MCPRegistrationMessage(oldPhoneID, proof.PublicKey, proof.SecretHash), signature) {
		t.Fatal("signature not bound to remote id")
	}
	if ed25519.Verify(s.PublicKey(), MCPRegistrationMessage(s.MCPMacID(), proof.PublicKey, strings.Repeat("a", 64)), signature) {
		t.Fatal("signature not bound to link hash")
	}
	reopened, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	regenerated, err := Open(reopened.dir)
	if err != nil || regenerated.MCPMacID() != reopened.MCPMacID() {
		t.Fatal("remote id not stable", err)
	}
}

func TestRemoteAlertContextCancelsCrossProcessLockWait(t *testing.T) {
	s, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(s.dir, "state.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RecordAlertContext(ctx, Raised{ID: NewID()}) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Fatal("alert file lock hung request")
	}
}

package security

import (
	"os"
	"path/filepath"
	"testing"
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

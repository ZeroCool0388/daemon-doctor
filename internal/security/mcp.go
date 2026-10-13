package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MCPLinkSecret is separate from phone pairing secrets and MCP client tokens.
// The shared state lock allows the daemon and mcp-token command to start together.
func (s *Store) MCPLinkSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockState()
	if err != nil {
		return "", err
	}
	defer unlock()
	path := filepath.Join(s.dir, "mcp-link.secret")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		data = []byte(base64.RawURLEncoding.EncodeToString(raw[:]))
		if err := writeNew(path, data); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	data = []byte(strings.TrimSpace(string(data)))
	decoded, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid MCP link credential")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	return string(data), nil
}

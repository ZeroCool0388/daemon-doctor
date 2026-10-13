package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// MCPLinkRegistration binds enrollment to this Mac's existing signing key.
// The relay derives the endpoint id from PublicKey before checking Signature.
type MCPLinkRegistration struct {
	SecretHash string `json:"secret_hash"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

// MCPIdentityID is a separate remote endpoint id. Legacy phone ids are random
// and cannot prove key ownership to a relay without a prior trusted key record.
func MCPIdentityID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(append([]byte("daemon-doctor/mcp-identity/v1\n"), public...))
	return hex.EncodeToString(sum[:16])
}

func (s *Store) MCPMacID() string { return MCPIdentityID(s.public) }

func MCPRegistrationMessage(macID, publicKey, secretHash string) []byte {
	return []byte("daemon-doctor/mcp-link/v1\nmac_id=" + macID + "\npublic_key=" + publicKey + "\nsecret_hash=" + secretHash)
}

func (s *Store) MCPRegistration(secret string) MCPLinkRegistration {
	sum := sha256.Sum256([]byte(secret))
	proof := MCPLinkRegistration{SecretHash: hex.EncodeToString(sum[:]), PublicKey: encodeKey(s.public)}
	proof.Signature = encodeKey(ed25519.Sign(s.private, MCPRegistrationMessage(s.MCPMacID(), proof.PublicKey, proof.SecretHash)))
	return proof
}

package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// Pairing authenticates a phone key using the QR secret. Only the secret's
// hash and an HMAC are sent through the relay, never the secret itself.
type Pairing struct {
	ID        string
	PublicKey ed25519.PublicKey
	Proof     []byte
}

type pairingWire struct {
	ID        string `json:"pairing_id"`
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`
}

// NewPairing builds the registration the phone sends after scanning the QR.
func NewPairing(macID string, macPublic ed25519.PublicKey, secret string, phone ed25519.PublicKey) (Pairing, error) {
	if !validID(macID) || !validID(secret) || len(macPublic) != ed25519.PublicKeySize || len(phone) != ed25519.PublicKeySize {
		return Pairing{}, fmt.Errorf("pairing fields are not usable")
	}
	key, _ := hex.DecodeString(secret)
	id := sha256.Sum256(key)
	msg := Pairing{ID: hex.EncodeToString(id[:]), PublicKey: phone}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.Join([]string{
		"daemon-doctor/pairing/v2",
		"mac_id=" + macID,
		"mac_public_key=" + encodeKey(macPublic),
		"pairing_id=" + msg.ID,
		"phone_public_key=" + encodeKey(phone),
	}, "\n")))
	msg.Proof = mac.Sum(nil)
	return msg, nil
}

func MarshalPairing(msg Pairing) ([]byte, error) {
	return json.Marshal(pairingWire{ID: msg.ID, PublicKey: encodeKey(msg.PublicKey), Proof: encodeKey(msg.Proof)})
}

// UnmarshalPairing rejects the old secret-bearing format and extra fields.
func UnmarshalPairing(data []byte) (Pairing, error) {
	bad := &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var wire pairingWire
	if err := dec.Decode(&wire); err != nil {
		return Pairing{}, bad
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return Pairing{}, bad
	}
	id, err := hex.DecodeString(wire.ID)
	if err != nil || len(id) != sha256.Size {
		return Pairing{}, bad
	}
	phone, err := decodeKey(wire.PublicKey)
	if err != nil || len(phone) != ed25519.PublicKeySize {
		return Pairing{}, bad
	}
	proof, err := decodeKey(wire.Proof)
	if err != nil || len(proof) != sha256.Size {
		return Pairing{}, bad
	}
	return Pairing{ID: wire.ID, PublicKey: phone, Proof: proof}, nil
}

// AcceptPairing checks the secret-derived proof before storing the phone key.
// Registration and approval state use the same cross-process lock.
func (s *Store) AcceptPairing(now time.Time, msg Pairing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockState()
	if err != nil {
		return err
	}
	defer unlock()
	if s.pending == nil || s.pending.Version != 2 || !now.Before(s.pending.Expires) {
		return &Refusal{Reason: ReasonExpired, Detail: "pairing code is not active"}
	}
	expected, err := NewPairing(s.macID, s.public, s.pending.Code, msg.PublicKey)
	if err != nil {
		return &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	}
	if msg.ID != expected.ID || !hmac.Equal(msg.Proof, expected.Proof) {
		return &Refusal{Reason: ReasonBadSignature, Detail: "pairing proof does not match"}
	}
	encoded := encodeKey(msg.PublicKey)
	if s.pending.Used {
		if s.pending.Phone == encoded {
			if _, ok := s.phones[encoded]; ok {
				return nil
			}
		}
		return &Refusal{Reason: ReasonExpired, Detail: "pairing code is not active"}
	}
	s.pending.Used = true
	s.pending.Phone = encoded
	body, err := json.Marshal(s.pending)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(s.dir, "pending.json"), body); err != nil {
		return err
	}
	s.phones[encoded] = struct{}{}
	return s.savePhones()
}

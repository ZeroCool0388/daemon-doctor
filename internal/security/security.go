// Package security creates the Mac identity, pairs phone keys, and checks
// signed approvals. The relay is not part of this decision.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// ApprovalTTL is the longest an approval may stay valid.
	ApprovalTTL = 10 * time.Minute
	// PairingTTL is how long a pairing code can be accepted.
	PairingTTL = 10 * time.Minute
	// ClockSkew is how far a phone clock may sit ahead of the Mac.
	ClockSkew = time.Minute

	idBytes = 16
)

// Reason explains a refused approval. Callers log it and do not run a fix.
type Reason string

const (
	ReasonMalformed    Reason = "malformed"
	ReasonUnknownKey   Reason = "unknown_key"
	ReasonBadSignature Reason = "bad_signature"
	ReasonExpired      Reason = "expired"
	ReasonWindow       Reason = "window"
	ReasonReplay       Reason = "replay"
	ReasonUnknownAlert Reason = "unknown_alert"
	ReasonWrongFix     Reason = "wrong_fix"
	ReasonMac          Reason = "mac_mismatch"
)

// Refusal is a rejected approval or pairing attempt.
type Refusal struct {
	Reason Reason
	Detail string
}

func (e *Refusal) Error() string {
	if e.Detail == "" {
		return "approval rejected: " + string(e.Reason)
	}
	return "approval rejected: " + e.Detail
}

// IsReplay reports whether err is a reused nonce.
func IsReplay(err error) bool {
	var refusal *Refusal
	return errors.As(err, &refusal) && refusal.Reason == ReasonReplay
}

// Raised is an alert this Mac actually produced.
type Raised struct {
	ID          string    `json:"id"`
	ServiceID   string    `json:"service_id"`
	ServiceName string    `json:"service_name"`
	Kind        string    `json:"kind"`
	Actions     []string  `json:"actions"`
	Process     string    `json:"process"`
	At          time.Time `json:"at"`
}

// Approval is the signed phone message. Extra JSON fields are rejected.
type Approval struct {
	MacID     string
	AlertID   string
	FixID     string
	Nonce     string
	Expires   time.Time
	PublicKey ed25519.PublicKey
	Signature []byte
}

type approvalWire struct {
	MacID       string `json:"mac_id"`
	AlertID     string `json:"alert_id"`
	FixID       string `json:"fix_id"`
	Nonce       string `json:"nonce"`
	ExpiresUnix int64  `json:"expires_unix"`
	PublicKey   string `json:"public_key"`
	Signature   string `json:"signature"`
}

// Store is the local identity, paired phones, nonces, and raised alerts.
type Store struct {
	mu      sync.Mutex
	dir     string
	macID   string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	phones  map[string]struct{}
	nonces  map[string]struct{}
	alerts  map[string]Raised
	pending *pendingCode
}

type identityFile struct {
	MacID      string `json:"mac_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type pendingCode struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

type phoneFile struct {
	PublicKeys []string `json:"public_keys"`
}

// NewID returns 16 random bytes as hex.
func NewID() string {
	var buf [idBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}

// LoadOrCreate reads the Mac identity or generates one. The private key
// stays in dir and is never returned to the relay.
func LoadOrCreate(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	path := filepath.Join(dir, "identity.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createIdentity(dir)
	}
	if err != nil {
		return nil, err
	}
	return openIdentity(dir, data)
}

// Open reads an identity that pair already created.
func Open(dir string) (*Store, error) {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, fmt.Errorf("mac identity: %w", err)
	}
	return openIdentity(dir, data)
}

func createIdentity(dir string) (*Store, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file := identityFile{
		MacID:      NewID(),
		PublicKey:  encodeKey(public),
		PrivateKey: encodeKey(private),
	}
	body, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "identity.json")
	if err := writeNew(path, body); err != nil {
		return nil, err
	}
	st := &Store{
		dir:     dir,
		macID:   file.MacID,
		public:  public,
		private: private,
		phones:  map[string]struct{}{},
		nonces:  map[string]struct{}{},
		alerts:  map[string]Raised{},
	}
	return st, st.load()
}

func openIdentity(dir string, data []byte) (*Store, error) {
	var file identityFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	public, err := decodeKey(file.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity public key")
	}
	private, err := decodeKey(file.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity private key")
	}
	if !ed25519.PublicKey(public).Equal(ed25519.PrivateKey(private).Public()) {
		return nil, fmt.Errorf("identity keys do not match")
	}
	if !validID(file.MacID) {
		return nil, fmt.Errorf("identity mac id")
	}
	st := &Store{
		dir:     dir,
		macID:   file.MacID,
		public:  ed25519.PublicKey(public),
		private: ed25519.PrivateKey(private),
		phones:  map[string]struct{}{},
		nonces:  map[string]struct{}{},
		alerts:  map[string]Raised{},
	}
	if err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) load() error {
	if err := s.loadPhones(); err != nil {
		return err
	}
	if err := s.loadNonces(); err != nil {
		return err
	}
	if err := s.loadAlerts(); err != nil {
		return err
	}
	return s.loadPending()
}

// MacID is the local id included in pairing payloads and approvals.
func (s *Store) MacID() string { return s.macID }

// PublicKey is the Mac public key.
func (s *Store) PublicKey() ed25519.PublicKey { return s.public }

// Fingerprint is a short hash of a public key for the terminal.
func Fingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// BeginPairing saves a one-time code and returns the text a phone scans.
func (s *Store) BeginPairing(now time.Time, relayURL string) (payload string, err error) {
	code := NewID()
	pending := pendingCode{Code: code, Expires: now.Add(PairingTTL).UTC()}
	body, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	if err := writeFile(filepath.Join(s.dir, "pending.json"), body); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pending = &pending
	s.mu.Unlock()
	return Payload(s.macID, s.public, code, relayURL), nil
}

// Payload is the QR text. It carries the Mac public key and a one-time code.
func Payload(macID string, public ed25519.PublicKey, code, relayURL string) string {
	return strings.Join([]string{
		"daemon-doctor:1",
		macID,
		encodeKey(public),
		code,
		relayURL,
	}, ":")
}

// ParsePayload splits a pairing payload. The relay URL may contain colons.
func ParsePayload(payload string) (macID, code, relayURL string, public ed25519.PublicKey, err error) {
	parts := strings.Split(payload, ":")
	if len(parts) < 5 || parts[0] != "daemon-doctor" || parts[1] != "1" {
		return "", "", "", nil, fmt.Errorf("pairing payload")
	}
	macID = parts[2]
	key, err := decodeKey(parts[3])
	if err != nil || len(key) != ed25519.PublicKeySize || !validID(macID) || !validID(parts[4]) {
		return "", "", "", nil, fmt.Errorf("pairing payload")
	}
	relayURL = strings.Join(parts[5:], ":")
	return macID, parts[4], relayURL, ed25519.PublicKey(key), nil
}

// AcceptPairing stores a phone public key when the one-time code matches.
// The code works once. A repeat delivery for that same phone is ignored.
// A different phone using the spent code is refused.
func (s *Store) AcceptPairing(now time.Time, code string, phone ed25519.PublicKey) error {
	if len(phone) != ed25519.PublicKeySize || !validID(code) {
		return &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || !now.Before(s.pending.Expires) {
		return &Refusal{Reason: ReasonExpired, Detail: "pairing code is not active"}
	}
	if subtleMatch(s.pending.Code, code) != 1 {
		return &Refusal{Reason: ReasonMac, Detail: "pairing code does not match"}
	}
	encoded := encodeKey(phone)
	if s.pending.Used {
		if _, ok := s.phones[encoded]; ok {
			return nil
		}
		return &Refusal{Reason: ReasonExpired, Detail: "pairing code is not active"}
	}
	s.pending.Used = true
	body, err := json.Marshal(s.pending)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(s.dir, "pending.json"), body); err != nil {
		return err
	}
	if _, ok := s.phones[encoded]; ok {
		return nil
	}
	s.phones[encoded] = struct{}{}
	return s.savePhones()
}

// Phones returns the paired public keys.
func (s *Store) Phones() []ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ed25519.PublicKey, 0, len(s.phones))
	for encoded := range s.phones {
		key, err := decodeKey(encoded)
		if err == nil {
			out = append(out, key)
		}
	}
	return out
}

// RecordAlert remembers an alert this Mac raised.
func (s *Store) RecordAlert(alert Raised) error {
	if !validID(alert.ID) {
		return fmt.Errorf("alert id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.alerts[alert.ID]; ok {
		return nil
	}
	s.alerts[alert.ID] = alert
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	return appendLine(filepath.Join(s.dir, "alerts.jsonl"), body)
}

// Sign fills the signature with the phone's private key.
func Sign(private ed25519.PrivateKey, approval Approval) (Approval, error) {
	approval.PublicKey = private.Public().(ed25519.PublicKey)
	if err := fieldsOK(approval); err != nil {
		return Approval{}, err
	}
	approval.Signature = ed25519.Sign(private, canonical(approval))
	return approval, nil
}

// Consume checks an approval and records its nonce.
// A second call with the same nonce is a replay.
func (s *Store) Consume(now time.Time, approval Approval) (Raised, error) {
	raised, err := s.check(now, approval, true)
	if err != nil {
		return Raised{}, err
	}
	return raised, nil
}

func (s *Store) check(now time.Time, approval Approval, consume bool) (Raised, error) {
	if err := canonicalOK(approval); err != nil {
		return Raised{}, err
	}
	if approval.MacID != s.macID {
		return Raised{}, &Refusal{Reason: ReasonMac, Detail: "approval is for a different Mac"}
	}
	if !approval.Expires.After(now) {
		return Raised{}, &Refusal{Reason: ReasonExpired, Detail: "approval has expired"}
	}
	if approval.Expires.After(now.Add(ApprovalTTL + ClockSkew)) {
		return Raised{}, &Refusal{Reason: ReasonWindow, Detail: "approval lasts longer than 10 minutes"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, paired := s.phones[encodeKey(approval.PublicKey)]; !paired {
		return Raised{}, &Refusal{Reason: ReasonUnknownKey, Detail: "phone key is not paired"}
	}
	if !ed25519.Verify(approval.PublicKey, canonical(approval), approval.Signature) {
		return Raised{}, &Refusal{Reason: ReasonBadSignature, Detail: "signature does not match"}
	}
	raised, ok := s.alerts[approval.AlertID]
	if !ok {
		return Raised{}, &Refusal{Reason: ReasonUnknownAlert, Detail: "alert was not raised by this Mac"}
	}
	if !offered(raised.Actions, approval.FixID) {
		return Raised{}, &Refusal{Reason: ReasonWrongFix, Detail: "fix is not one this alert offered"}
	}
	if _, used := s.nonces[approval.Nonce]; used {
		return Raised{}, &Refusal{Reason: ReasonReplay, Detail: "approval was already used"}
	}
	if consume {
		if err := appendLine(filepath.Join(s.dir, "nonces.jsonl"), []byte(approval.Nonce)); err != nil {
			return Raised{}, err
		}
		s.nonces[approval.Nonce] = struct{}{}
	}
	raised.Actions = []string{approval.FixID}
	return raised, nil
}

func offered(actions []string, fixID string) bool {
	for _, action := range actions {
		if action == fixID {
			return true
		}
	}
	return false
}

func canonical(a Approval) []byte {
	return []byte(strings.Join([]string{
		"daemon-doctor/approval/v1",
		"mac_id=" + a.MacID,
		"alert_id=" + a.AlertID,
		"fix_id=" + a.FixID,
		"nonce=" + a.Nonce,
		"expires_unix=" + fmt.Sprintf("%d", a.Expires.Unix()),
	}, "\n"))
}

func canonicalOK(a Approval) error {
	if err := fieldsOK(a); err != nil {
		return err
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return &Refusal{Reason: ReasonMalformed, Detail: "approval key or signature is the wrong size"}
	}
	return nil
}

func fieldsOK(a Approval) error {
	if !validID(a.MacID) || !validID(a.AlertID) || !validID(a.Nonce) {
		return &Refusal{Reason: ReasonMalformed, Detail: "approval fields are not usable"}
	}
	if a.FixID == "" || strings.ContainsAny(a.FixID, "\n\r") {
		return &Refusal{Reason: ReasonMalformed, Detail: "fix id is not usable"}
	}
	if len(a.PublicKey) != ed25519.PublicKeySize {
		return &Refusal{Reason: ReasonMalformed, Detail: "approval key or signature is the wrong size"}
	}
	if a.Expires.IsZero() {
		return &Refusal{Reason: ReasonMalformed, Detail: "approval has no expiry"}
	}
	return nil
}

// MarshalApproval encodes an approval for the relay or a file.
func MarshalApproval(a Approval) ([]byte, error) {
	return json.Marshal(approvalWire{
		MacID:       a.MacID,
		AlertID:     a.AlertID,
		FixID:       a.FixID,
		Nonce:       a.Nonce,
		ExpiresUnix: a.Expires.Unix(),
		PublicKey:   encodeKey(a.PublicKey),
		Signature:   encodeKey(a.Signature),
	})
}

// UnmarshalApproval reads an approval. Unknown JSON fields are rejected,
// so a smuggled command cannot ride along.
func UnmarshalApproval(data []byte) (Approval, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var wire approvalWire
	if err := dec.Decode(&wire); err != nil {
		return Approval{}, &Refusal{Reason: ReasonMalformed, Detail: "approval body is not usable"}
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Approval{}, &Refusal{Reason: ReasonMalformed, Detail: "approval body is not usable"}
	}
	pub, err := decodeKey(wire.PublicKey)
	if err != nil {
		return Approval{}, &Refusal{Reason: ReasonMalformed, Detail: "approval body is not usable"}
	}
	sig, err := decodeKey(wire.Signature)
	if err != nil {
		return Approval{}, &Refusal{Reason: ReasonMalformed, Detail: "approval body is not usable"}
	}
	return Approval{
		MacID:     wire.MacID,
		AlertID:   wire.AlertID,
		FixID:     wire.FixID,
		Nonce:     wire.Nonce,
		Expires:   time.Unix(wire.ExpiresUnix, 0).UTC(),
		PublicKey: pub,
		Signature: sig,
	}, nil
}

// UnmarshalPairing reads a phone registration. Unknown JSON fields are rejected.
func UnmarshalPairing(data []byte) (code string, phone ed25519.PublicKey, err error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var wire struct {
		Code      string `json:"code"`
		PublicKey string `json:"public_key"`
	}
	if err := dec.Decode(&wire); err != nil {
		return "", nil, &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", nil, &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	}
	key, err := decodeKey(wire.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || !validID(wire.Code) {
		return "", nil, &Refusal{Reason: ReasonMalformed, Detail: "pairing message is not usable"}
	}
	return wire.Code, ed25519.PublicKey(key), nil
}

func (s *Store) loadPhones() error {
	data, err := os.ReadFile(filepath.Join(s.dir, "phones.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var file phoneFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	for _, key := range file.PublicKeys {
		s.phones[key] = struct{}{}
	}
	return nil
}

func (s *Store) savePhones() error {
	file := phoneFile{}
	for key := range s.phones {
		file.PublicKeys = append(file.PublicKeys, key)
	}
	body, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, "phones.json"), body)
}

func (s *Store) loadNonces() error {
	return readLines(filepath.Join(s.dir, "nonces.jsonl"), func(line []byte) error {
		s.nonces[string(line)] = struct{}{}
		return nil
	})
}

func (s *Store) loadAlerts() error {
	return readLines(filepath.Join(s.dir, "alerts.jsonl"), func(line []byte) error {
		var alert Raised
		if err := json.Unmarshal(line, &alert); err != nil {
			return err
		}
		s.alerts[alert.ID] = alert
		return nil
	})
}

func (s *Store) loadPending() error {
	data, err := os.ReadFile(filepath.Join(s.dir, "pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending pendingCode
	if err := json.Unmarshal(data, &pending); err != nil {
		return err
	}
	s.pending = &pending
	return nil
}

func validID(value string) bool {
	if len(value) != idBytes*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func encodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func decodeKey(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func writeNew(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeFile(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func appendLine(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(body, '\n'))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func readLines(path string, fn func([]byte) error) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := fn([]byte(line)); err != nil {
			return err
		}
	}
	return nil
}

func subtleMatch(left, right string) int {
	if len(left) != len(right) {
		return 0
	}
	var diff byte
	for i := 0; i < len(left); i++ {
		diff |= left[i] ^ right[i]
	}
	if diff == 0 {
		return 1
	}
	return 0
}

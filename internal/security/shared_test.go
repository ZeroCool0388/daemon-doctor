package security

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTwoOpenStoresConsumeOnce(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "sequential"
		if concurrent {
			name = "concurrent"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			first, phone := paired(t, dir)
			second, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0).UTC()
			id := NewID()
			// Both stores were open before the alert and nonce existed.
			if err := first.RecordAlert(Raised{ID: id, Actions: []string{"restart"}}); err != nil {
				t.Fatal(err)
			}
			a := approvalAt(t, phone, first.MacID(), id, "restart", now.Add(time.Minute))
			errs := make([]error, 2)
			if concurrent {
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i, store := range []*Store{first, second} {
					wg.Add(1)
					go func() { defer wg.Done(); <-start; _, errs[i] = store.Consume(now, a) }()
				}
				close(start)
				wg.Wait()
			} else {
				_, errs[0] = first.Consume(now, a)
				_, errs[1] = second.Consume(now, a)
			}
			accepted, replayed := 0, 0
			for _, err := range errs {
				if err == nil {
					accepted++
				} else if IsReplay(err) {
					replayed++
				} else {
					t.Fatal(err)
				}
			}
			if accepted != 1 || replayed != 1 {
				t.Fatalf("accepted %d replayed %d", accepted, replayed)
			}
			data, err := os.ReadFile(filepath.Join(dir, "nonces.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(data), a.Nonce) != 1 {
				t.Fatal("nonce was written more than once")
			}
		})
	}
}

func TestPairingProofRejectsRelaySubstitution(t *testing.T) {
	dir := t.TempDir()
	mac, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload, err := mac.BeginPairing(now, "https://your-relay.example.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _, _, err := ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	phone, _ := keypair(t)
	attacker, _ := keypair(t)
	honest := pairingFor(t, mac, secret, phone)
	raw, err := MarshalPairing(honest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), `"code"`) {
		t.Fatal("registration disclosed the QR secret")
	}
	for _, altered := range []Pairing{
		{ID: honest.ID, PublicKey: attacker, Proof: honest.Proof},
		{ID: honest.ID, PublicKey: attacker, Proof: make([]byte, 32)},
		pairingFor(t, mac, NewID(), attacker),
	} {
		if err := otherStore.AcceptPairing(now, altered); err == nil {
			t.Fatal("relay substituted a phone key")
		}
	}
	if len(otherStore.Phones()) != 0 {
		t.Fatal("failed pairing stored a key")
	}
	if err := otherStore.AcceptPairing(now, honest); err != nil {
		t.Fatal(err)
	}
	if err := mac.AcceptPairing(now, honest); err != nil {
		t.Fatal("valid redelivery across stores was refused", err)
	}
	if err := mac.AcceptPairing(now, pairingFor(t, mac, secret, attacker)); err == nil {
		t.Fatal("spent secret registered a second key")
	}
	// Old registrations which send the code through the relay are refused.
	if _, err := UnmarshalPairing([]byte(`{"code":"` + secret + `","public_key":"` + encodeKey(phone) + `"}`)); err == nil {
		t.Fatal("accepted legacy registration")
	}
	if _, err := UnmarshalPairing(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if _, _, _, _, err := ParsePayload(strings.Replace(payload, "daemon-doctor:2:", "daemon-doctor:1:", 1)); err == nil {
		t.Fatal("accepted legacy QR")
	}
	if err := mac.AcceptPairing(now.Add(PairingTTL), honest); err == nil {
		t.Fatal("accepted expired registration")
	}
}

func TestPairingVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pairing-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		MacID  string `json:"mac_id"`
		MacKey string `json:"mac_public_key"`
		Secret string `json:"secret"`
		Phone  string `json:"phone_public_key"`
		ID     string `json:"pairing_id"`
		Proof  string `json:"proof"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	mac, err := decodeKey(v.MacKey)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := decodeKey(v.Phone)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := NewPairing(v.MacID, ed25519.PublicKey(mac), v.Secret, ed25519.PublicKey(phone))
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != v.ID || encodeKey(msg.Proof) != v.Proof {
		t.Fatal("pairing proof differs from cross-language vector")
	}
}

func TestLegacyPhoneRequiresAuthenticatedPairing(t *testing.T) {
	dir := t.TempDir()
	mac, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, private := keypair(t)
	legacy, err := json.Marshal(phoneFile{PublicKeys: []string{encodeKey(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "phones.json")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	mac, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := NewID()
	if err := mac.RecordAlert(Raised{ID: id, Actions: []string{"restart"}}); err != nil {
		t.Fatal(err)
	}
	a := approvalAt(t, private, mac.MacID(), id, "restart", now.Add(time.Minute))
	if _, err := mac.Consume(now, a); err == nil {
		t.Fatal("legacy key was trusted without authenticated pairing")
	}
	payload, err := mac.BeginPairing(now, "")
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _, _, err := ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.AcceptPairing(now, pairingFor(t, mac, secret, pub)); err != nil {
		t.Fatal(err)
	}
	if _, err := mac.Consume(now, a); err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved) != string(legacy) {
		t.Fatal("legacy file was modified")
	}
}

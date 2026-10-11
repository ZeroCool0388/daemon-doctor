package security

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityAndPairingPayload(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.MacID() != second.MacID() || !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("identity was created twice")
	}
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file identityFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	payload, err := first.BeginPairing(now, "https://relay.example.invalid/mailbox")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, file.PrivateKey) {
		t.Fatal("pairing payload contains the private key")
	}
	macID, code, relayURL, public, err := ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if macID != first.MacID() || !public.Equal(first.PublicKey()) || relayURL != "https://relay.example.invalid/mailbox" {
		t.Fatalf("payload mac %s relay %s", macID, relayURL)
	}
	qr, err := QR(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(qr, "\n") || strings.Contains(qr, file.PrivateKey) {
		t.Fatal("terminal QR is missing or contains the private key")
	}
	phonePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.AcceptPairing(now, code, phonePub); err != nil {
		t.Fatal(err)
	}
	if err := first.AcceptPairing(now, code, phonePub); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.AcceptPairing(now, code, other); err == nil {
		t.Fatal("spent pairing code was accepted for a second phone")
	}
	if err := first.AcceptPairing(now.Add(PairingTTL), "0123456789abcdef0123456789abcdef", phonePub); err == nil {
		t.Fatal("expired pairing code was accepted")
	}
	opened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Phones()) != 1 || !opened.Phones()[0].Equal(phonePub) {
		t.Fatalf("phones %+v", opened.Phones())
	}
}

func TestApprovals(t *testing.T) {
	dir := t.TempDir()
	mac, phone := paired(t, dir)
	now := time.Unix(1_700_000_000, 0).UTC()
	alertID := NewID()
	if err := mac.RecordAlert(Raised{
		ID:        alertID,
		ServiceID: "example-desktop-app",
		Actions:   []string{"restart"},
		At:        now,
	}); err != nil {
		t.Fatal(err)
	}
	otherAlert := NewID()
	if err := mac.RecordAlert(Raised{
		ID:        otherAlert,
		ServiceID: "example-desktop-app",
		Actions:   []string{"force-restart"},
		At:        now,
	}); err != nil {
		t.Fatal(err)
	}

	valid := approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(ApprovalTTL))
	raised, err := mac.Consume(now, valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(raised.Actions) != 1 || raised.Actions[0] != "restart" {
		t.Fatalf("raised %+v", raised)
	}
	if _, err := mac.Consume(now, valid); !IsReplay(err) {
		t.Fatalf("replay err %v", err)
	}
	reloaded, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Consume(now, valid); !IsReplay(err) {
		t.Fatalf("persisted replay err %v", err)
	}

	_, other := keypair(t)
	cases := []struct {
		name   string
		build  func() Approval
		reason Reason
	}{
		{name: "forged", reason: ReasonBadSignature, build: func() Approval {
			a := approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(5*time.Minute))
			a.Signature[0] ^= 0xff
			return a
		}},
		{name: "wrong device", reason: ReasonUnknownKey, build: func() Approval {
			return approvalAt(t, other, mac.MacID(), alertID, "restart", now.Add(5*time.Minute))
		}},
		{name: "expired", reason: ReasonExpired, build: func() Approval {
			return approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(-11*time.Minute))
		}},
		{name: "window", reason: ReasonWindow, build: func() Approval {
			return approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(ApprovalTTL+ClockSkew+time.Second))
		}},
		{name: "wrong fix", reason: ReasonWrongFix, build: func() Approval {
			return approvalAt(t, phone, mac.MacID(), alertID, "force-restart", now.Add(5*time.Minute))
		}},
		{name: "different alert", reason: ReasonUnknownAlert, build: func() Approval {
			return approvalAt(t, phone, mac.MacID(), NewID(), "restart", now.Add(5*time.Minute))
		}},
		{name: "other mac", reason: ReasonMac, build: func() Approval {
			return approvalAt(t, phone, NewID(), alertID, "restart", now.Add(5*time.Minute))
		}},
		{name: "smuggled fix id", reason: ReasonWrongFix, build: func() Approval {
			return approvalAt(t, phone, mac.MacID(), alertID, "restart; touch marker", now.Add(5*time.Minute))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mac.Consume(now, tc.build())
			var refusal *Refusal
			if !errorAs(err, &refusal) || refusal.Reason != tc.reason {
				t.Fatalf("err %v", err)
			}
		})
	}

	edge := approvalAt(t, phone, mac.MacID(), otherAlert, "force-restart", now.Add(ApprovalTTL+ClockSkew))
	if _, err := mac.Consume(now, edge); err != nil {
		t.Fatal(err)
	}

	secondPub, secondPriv := keypair(t)
	payload, err := mac.BeginPairing(now, "")
	if err != nil {
		t.Fatal(err)
	}
	_, code, _, _, err := ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.AcceptPairing(now, code, secondPub); err != nil {
		t.Fatal(err)
	}
	fromSecond := approvalAt(t, secondPriv, mac.MacID(), alertID, "restart", now.Add(5*time.Minute))
	if _, err := mac.Consume(now, fromSecond); err != nil {
		t.Fatal(err)
	}

	swapped := approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(5*time.Minute))
	swapped.PublicKey = secondPub
	if _, err := mac.Consume(now, swapped); err == nil {
		t.Fatal("signature from one paired phone was accepted as another")
	}
}

func TestApprovalJSONRejectsExtraFields(t *testing.T) {
	dir := t.TempDir()
	mac, phone := paired(t, dir)
	now := time.Unix(1_700_000_000, 0).UTC()
	alertID := NewID()
	signed := approvalAt(t, phone, mac.MacID(), alertID, "restart", now.Add(5*time.Minute))
	raw, err := MarshalApproval(signed)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalApproval(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.FixID != "restart" || back.AlertID != alertID {
		t.Fatalf("round trip %+v", back)
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
	if _, err := UnmarshalApproval(smuggled); err == nil {
		t.Fatal("extra json field was accepted")
	}
	if _, err := UnmarshalApproval(append(append([]byte{}, raw...), []byte(`{"command":"touch marker"}`)...)); err == nil {
		t.Fatal("second json value was accepted")
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire["fix_id"] = "force-restart"
	altered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := UnmarshalApproval(altered)
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.RecordAlert(Raised{ID: alertID, ServiceID: "example-desktop-app", Actions: []string{"restart"}, At: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := mac.Consume(now, changed); err == nil {
		t.Fatal("altered fix id kept a valid signature")
	}
}

func paired(t *testing.T, dir string) (*Store, ed25519.PrivateKey) {
	t.Helper()
	mac, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := keypair(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	payload, err := mac.BeginPairing(now, "")
	if err != nil {
		t.Fatal(err)
	}
	_, code, _, _, err := ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.AcceptPairing(now, code, pub); err != nil {
		t.Fatal(err)
	}
	return mac, priv
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func approvalAt(t *testing.T, phone ed25519.PrivateKey, macID, alertID, fixID string, expires time.Time) Approval {
	t.Helper()
	signed, err := Sign(phone, Approval{
		MacID:   macID,
		AlertID: alertID,
		FixID:   fixID,
		Nonce:   NewID(),
		Expires: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func errorAs(err error, target **Refusal) bool {
	if err == nil {
		return false
	}
	refusal, ok := err.(*Refusal)
	if !ok {
		return false
	}
	*target = refusal
	return true
}

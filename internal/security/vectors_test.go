package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	Name         string `json:"name"`
	ProducedBy   string `json:"produced_by"`
	SeedHex      string `json:"seed_hex"`
	PublicKeyB64 string `json:"public_key_b64"`
	MacID        string `json:"mac_id"`
	AlertID      string `json:"alert_id"`
	FixID        string `json:"fix_id"`
	Nonce        string `json:"nonce"`
	ExpiresUnix  int64  `json:"expires_unix"`
	SignatureB64 string `json:"signature_b64"`
}

func TestCrossLanguageVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "approval-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 2 {
		t.Fatalf("vectors %d", len(file.Vectors))
	}
	sawGo := false
	sawOther := false
	for _, item := range file.Vectors {
		t.Run(item.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(item.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			priv := ed25519.NewKeyFromSeed(seed)
			pub := priv.Public().(ed25519.PublicKey)
			if encodeKey(pub) != item.PublicKeyB64 {
				t.Fatalf("public key %s", encodeKey(pub))
			}
			wireSig, err := base64.RawURLEncoding.DecodeString(item.SignatureB64)
			if err != nil {
				t.Fatal(err)
			}
			approval := Approval{
				MacID:     item.MacID,
				AlertID:   item.AlertID,
				FixID:     item.FixID,
				Nonce:     item.Nonce,
				Expires:   time.Unix(item.ExpiresUnix, 0).UTC(),
				PublicKey: pub,
				Signature: wireSig,
			}
			if !ed25519.Verify(pub, canonical(approval), wireSig) {
				t.Fatal("fixture signature did not verify")
			}
			switch item.ProducedBy {
			case "go":
				sawGo = true
				signed, err := Sign(priv, Approval{
					MacID:   item.MacID,
					AlertID: item.AlertID,
					FixID:   item.FixID,
					Nonce:   item.Nonce,
					Expires: approval.Expires,
				})
				if err != nil {
					t.Fatal(err)
				}
				if encodeKey(signed.Signature) != item.SignatureB64 {
					t.Fatalf("go signature %s", encodeKey(signed.Signature))
				}
			default:
				sawOther = true
			}
		})
	}
	if !sawGo || !sawOther {
		t.Fatalf("go fixture %v other fixture %v", sawGo, sawOther)
	}
}

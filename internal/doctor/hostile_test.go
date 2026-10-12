package doctor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type signalCounter struct {
	mu       sync.Mutex
	signals  int
	launches int
}

func (s *signalCounter) Signal(int, syscall.Signal) error {
	s.mu.Lock()
	s.signals++
	s.mu.Unlock()
	return nil
}

func (s *signalCounter) Launch(context.Context, string, []string) error {
	s.mu.Lock()
	s.launches++
	s.mu.Unlock()
	return nil
}

func (s *signalCounter) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signals, s.launches
}

func TestHostileRelay(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	now := time.Now().UTC().Truncate(time.Second)
	type run struct {
		name    string
		fixID   string
		expires time.Time
		alert   string
		sign    func(phone, other ed25519.PrivateKey) ed25519.PrivateKey
		rewrite func([]byte) []byte
		replay  bool
		record  bool
		status  string
		ran     bool
	}
	runs := []run{
		{name: "accepted", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: "accepted", ran: true, record: true},
		{name: "forged", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonBadSignature), record: true, rewrite: forgeSignature},
		{name: "replayed", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonReplay), ran: true, record: true, replay: true},
		{name: "expired", fixID: plugins.FixRestart, expires: now.Add(-11 * time.Minute), status: string(security.ReasonExpired), record: true},
		{name: "altered", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonBadSignature), record: true, rewrite: alterFixID},
		{name: "wrong device", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonUnknownKey), record: true, sign: func(_, other ed25519.PrivateKey) ed25519.PrivateKey { return other }},
		{name: "wrong fix", fixID: plugins.FixForceRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonWrongFix), record: true},
		{name: "different alert", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), alert: "other", status: string(security.ReasonUnknownAlert), record: true},
		{name: "smuggled command", fixID: "restart; touch " + marker, expires: now.Add(5 * time.Minute), status: string(security.ReasonWrongFix), record: true},
		{name: "smuggled field", fixID: plugins.FixRestart, expires: now.Add(5 * time.Minute), status: string(security.ReasonMalformed), record: true, rewrite: addCommand},
	}
	for _, tc := range runs {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mac, phone := pairMac(t, dir, now)
			_, other, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			alertID := security.NewID()
			if err := mac.RecordAlert(security.Raised{
				ID:        alertID,
				ServiceID: "example-desktop-app",
				Actions:   []string{plugins.FixRestart},
				Process:   "example-desktop-app",
				At:        now,
			}); err != nil {
				t.Fatal(err)
			}
			useAlert := alertID
			if tc.alert == "other" {
				useAlert = security.NewID()
			}
			signer := phone
			if tc.sign != nil {
				signer = tc.sign(phone, other)
			}
			signed, err := security.Sign(signer, security.Approval{
				MacID:   mac.MacID(),
				AlertID: useAlert,
				FixID:   tc.fixID,
				Nonce:   security.NewID(),
				Expires: tc.expires,
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := security.MarshalApproval(signed)
			if err != nil {
				t.Fatal(err)
			}
			box := &hostileBox{kind: "approvals", body: raw, rewrite: tc.rewrite, replay: tc.replay}
			srv := httptest.NewServer(box)
			defer srv.Close()
			ctrl := &signalCounter{}
			book := openBook(t, dir)
			d := newLocalDoctor(t, dir, mac, srv.URL, ctrl, book, now)
			if _, err := d.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			signals, launches := ctrl.counts()
			if launches != 0 {
				t.Fatalf("launches %d", launches)
			}
			if tc.ran && signals == 0 {
				t.Fatal("approval did not reach the fix runner")
			}
			if !tc.ran && signals != 0 {
				t.Fatalf("rejected approval signalled %d times", signals)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("a smuggled command created a file")
			}
			if !sawStatus(t, book.Path(), tc.status) {
				t.Fatalf("log missing %s: %s", tc.status, mustRead(t, book.Path()))
			}
			if tc.replay && !sawStatus(t, book.Path(), "accepted") {
				t.Fatal("replayed approval was not accepted once")
			}
		})
	}
}

func TestRunPollsApprovalsBetweenChecks(t *testing.T) {
	testRunPollsApprovalsBetweenChecks(t, false)
}

func TestRunPollsApprovalsBetweenChecksInProcess(t *testing.T) {
	testRunPollsApprovalsBetweenChecks(t, true)
}

func testRunPollsApprovalsBetweenChecks(t *testing.T, inProcess bool) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	mac, phone := pairMac(t, dir, now)
	alertID := security.NewID()
	if err := mac.RecordAlert(security.Raised{ID: alertID, ServiceID: "example-desktop-app", Actions: []string{plugins.FixRestart}, At: now}); err != nil {
		t.Fatal(err)
	}
	signed, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: alertID, FixID: plugins.FixRestart, Nonce: security.NewID(), Expires: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := security.MarshalApproval(signed)
	if err != nil {
		t.Fatal(err)
	}
	var polls int
	results := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			if strings.HasSuffix(r.URL.Path, "/results") {
				results <- struct{}{}
			}
			_, _ = w.Write([]byte(`{"stored":true}`))
			return
		}
		events := []relay.Event{}
		if strings.HasSuffix(r.URL.Path, "/approvals") {
			polls++
			if polls > 1 {
				events = append(events, relay.Event{ID: 1, Kind: "approvals", Body: raw})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	})
	var client *relay.Client
	if inProcess {
		client, err = relay.New("https://your-relay.example.workers.dev")
		if err != nil {
			t.Fatal(err)
		}
		client.HTTP.Transport = handlerTransport{handler: handler}
	} else {
		srv := httptest.NewServer(handler)
		defer srv.Close()
		client, err = relay.New(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctrl := &signalCounter{}
	d := newLocalDoctor(t, dir, mac, client.BaseURL, ctrl, openBook(t, dir), now)
	d.UseRelay(mac, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, time.Hour, nil, func(err error) { t.Errorf("cycle: %v", err) }) }()
	select {
	case <-results:
	case <-time.After(8 * time.Second):
		t.Fatal("approval was not polled between checks")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("run did not stop")
	}
	signals, launches := ctrl.counts()
	if signals != 2 || launches != 0 {
		t.Fatalf("signals %d launches %d", signals, launches)
	}
}

func TestRelayFailureStaysLocal(t *testing.T) {
	dir := t.TempDir()
	mac, err := security.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	book := openBook(t, dir)
	src := &sysprobe.MemSource{}
	d, err := New([]plugins.Plugin{loadExample(t)}, src, &signalCounter{}, book, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	bad, err := relay.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	d.UseRelay(mac, bad)
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != rules.KindDown || rows[0].Alerts[0].ID == "" {
		t.Fatalf("rows %+v", rows)
	}
	if !sawKind(t, book.Path(), "relay") || len(d.outbox) != 1 {
		t.Fatal("missing relay error or pending alert")
	}
}

func pairMac(t *testing.T, dir string, now time.Time) (*security.Store, ed25519.PrivateKey) {
	t.Helper()
	mac, err := security.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := mac.BeginPairing(now, "")
	if err != nil {
		t.Fatal(err)
	}
	_, code, _, _, err := security.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := mac.AcceptPairing(now, pairingFor(t, mac, code, pub)); err != nil {
		t.Fatal(err)
	}
	return mac, priv
}

func newLocalDoctor(t *testing.T, dir string, mac *security.Store, base string, ctrl *signalCounter, book *logbook.Book, now time.Time) *Doctor {
	t.Helper()
	src := &sysprobe.MemSource{}
	src.Set(running(2))
	d, err := New([]plugins.Plugin{loadExample(t)}, src, ctrl, book, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	client, err := relay.New(base)
	if err != nil {
		t.Fatal(err)
	}
	d.UseRelay(mac, client)
	return d
}

func openBook(t *testing.T, dir string) *logbook.Book {
	t.Helper()
	book, err := logbook.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { book.Close() })
	return book
}

func sawStatus(t *testing.T, path, status string) bool {
	t.Helper()
	for _, event := range readEvents(t, path) {
		if event.Kind == "approval" && event.Status == status {
			return true
		}
	}
	return false
}

func sawKind(t *testing.T, path, kind string) bool {
	t.Helper()
	for _, event := range readEvents(t, path) {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type hostileBox struct {
	kind    string
	body    []byte
	rewrite func([]byte) []byte
	replay  bool
}

func (b *hostileBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/exec" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"stored":true}`))
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/"+b.kind) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"events":[]}`))
		return
	}
	body := append([]byte(nil), b.body...)
	if b.rewrite != nil {
		body = b.rewrite(body)
	}
	events := []relay.Event{{ID: 1, Kind: b.kind, Body: body}}
	if b.replay {
		events = append(events, relay.Event{ID: 2, Kind: b.kind, Body: append([]byte(nil), body...)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
}

func forgeSignature(body []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	obj["signature"] = strings.Repeat("A", 86)
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func alterFixID(body []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	obj["fix_id"] = plugins.FixForceRestart
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func addCommand(body []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	obj["command"] = "touch marker"
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func pairingFor(t testing.TB, mac *security.Store, secret string, phone ed25519.PublicKey) security.Pairing {
	t.Helper()
	msg, err := security.NewPairing(mac.MacID(), mac.PublicKey(), secret, phone)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

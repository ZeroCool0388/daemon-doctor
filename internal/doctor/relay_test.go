package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/fixes"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// fakeRelay implements the routes, global event ids, and envelopes in
// relay/src. It can fail delivery without ever invoking a real controller.
type fakeRelay struct {
	mu          sync.Mutex
	macID       string
	next        int64
	rows        []relay.Event
	failAlerts  bool
	failResults bool
}

func (b *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	prefix := "/v1/macs/" + b.macID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	kind := strings.TrimPrefix(r.URL.Path, prefix)
	switch kind {
	case "alerts", "approvals", "pairing", "results":
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost:
		if (kind == "alerts" && b.failAlerts) || (kind == "results" && b.failResults) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var raw json.RawMessage
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&raw) != nil || len(raw) > 4096 || len(raw) == 0 || raw[0] != '{' {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		b.next++
		b.rows = append(b.rows, relay.Event{ID: b.next, Kind: kind, Body: raw})
		_ = json.NewEncoder(w).Encode(map[string]any{"stored": true, "id": b.next})
	case http.MethodGet:
		after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if err != nil {
			http.Error(w, "bad cursor", http.StatusBadRequest)
			return
		}
		events := []relay.Event{}
		for _, row := range b.rows {
			if row.Kind == kind && row.ID > after {
				events = append(events, row)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (b *fakeRelay) events(kind string) []relay.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var events []relay.Event
	for _, row := range b.rows {
		if row.Kind == kind {
			events = append(events, row)
		}
	}
	return events
}

type recoveringController struct {
	signalCounter
	src     *sysprobe.MemSource
	recover bool
}

func (c *recoveringController) Launch(ctx context.Context, path string, args []string) error {
	if path != "/opt/example-launch" || len(args) != 1 || args[0] != "--example" {
		return context.Canceled
	}
	if c.recover {
		c.src.Set(running(2))
	}
	return c.signalCounter.Launch(ctx, path, args)
}

func TestRelayAlertApprovalRecheckResult(t *testing.T) {
	testRelayAlertApprovalRecheckResult(t, networkRelay)
}

// The same workflow can be verified without sockets in restricted runners.
func TestRelayAlertApprovalRecheckResultInProcess(t *testing.T) {
	testRelayAlertApprovalRecheckResult(t, inProcessRelay)
}

type relayFactory func(*testing.T, *fakeRelay) *relay.Client

func networkRelay(t *testing.T, box *fakeRelay) *relay.Client {
	t.Helper()
	srv := httptest.NewServer(box)
	t.Cleanup(srv.Close)
	client, err := relay.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type handlerTransport struct{ handler http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	res := w.Result()
	res.Request = r
	return res, nil
}

func inProcessRelay(t *testing.T, box *fakeRelay) *relay.Client {
	t.Helper()
	client, err := relay.New("https://your-relay.example.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = handlerTransport{handler: box}
	return client
}

func testRelayAlertApprovalRecheckResult(t *testing.T, newClient relayFactory) {
	for _, recover := range []bool{true, false} {
		t.Run(strconv.FormatBool(recover), func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC().Truncate(time.Second)
			mac, phone := pairMac(t, dir, now)
			box := &fakeRelay{macID: mac.MacID()}
			client := newClient(t, box)
			src := &sysprobe.MemSource{}
			ctrl := &recoveringController{src: src, recover: recover}
			p := loadExample(t)
			p.Fixes[plugins.FixRestart] = plugins.Fix{Kind: plugins.FixRestart, Launcher: "/opt/example-launch", Args: []string{"--example"}}
			d, err := New([]plugins.Plugin{p}, src, ctrl, openBook(t, dir), nil, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			d.UseRelay(mac, client)
			ctx := context.Background()
			for i := 0; i < 2; i++ {
				if _, err := d.Cycle(ctx); err != nil {
					t.Fatal(err)
				}
			}
			alerts := box.events("alerts")
			if len(alerts) != 1 {
				t.Fatalf("alerts %+v", alerts)
			}
			var alert struct {
				ID        string   `json:"alert_id"`
				ServiceID string   `json:"service_id"`
				Message   string   `json:"message"`
				Actions   []string `json:"actions"`
			}
			if err := json.Unmarshal(alerts[0].Body, &alert); err != nil {
				t.Fatal(err)
			}
			if alert.ID == "" || alert.ServiceID != p.ID || alert.Message == "" || len(alert.Actions) != 1 || alert.Actions[0] != plugins.FixRestart {
				t.Fatalf("alert %+v", alert)
			}
			signed, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: alert.ID, FixID: alert.Actions[0], Nonce: security.NewID(), Expires: now.Add(5 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := security.MarshalApproval(signed)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Post(ctx, mac.MacID(), "approvals", json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Cycle(ctx); err != nil {
				t.Fatal(err)
			}
			results := box.events("results")
			if len(results) != 1 {
				t.Fatalf("results %+v", results)
			}
			var result struct {
				AlertID string `json:"alert_id"`
				FixID   string `json:"fix_id"`
				Fixed   bool   `json:"fixed"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(results[0].Body, &result); err != nil {
				t.Fatal(err)
			}
			if result.AlertID != alert.ID || result.FixID != plugins.FixRestart || result.Fixed != recover || result.Message == "" {
				t.Fatalf("result %+v", result)
			}
			if !sawKind(t, d.Log.Path(), "fix") || !sawStatus(t, d.Log.Path(), "accepted") {
				t.Fatal("missing local fix or approval log")
			}
			_, launches := ctrl.counts()
			if launches != 1 {
				t.Fatalf("launches %d", launches)
			}
			// A new relay record with the same approval must not run it again,
			// including after reopening the persisted verifier state.
			mac, err = security.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			d.UseRelay(mac, client)
			if err := client.Post(ctx, mac.MacID(), "approvals", json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Cycle(ctx); err != nil {
				t.Fatal(err)
			}
			_, launches = ctrl.counts()
			if launches != 1 || len(box.events("results")) != 1 || !sawStatus(t, d.Log.Path(), string(security.ReasonReplay)) {
				t.Fatal("replayed approval ran twice")
			}
		})
	}
}

func TestRelayRetriesDeliveryWithoutRepeatingFix(t *testing.T) {
	testRelayRetriesDeliveryWithoutRepeatingFix(t, networkRelay)
}

func TestRelayRetriesDeliveryWithoutRepeatingFixInProcess(t *testing.T) {
	testRelayRetriesDeliveryWithoutRepeatingFix(t, inProcessRelay)
}

func testRelayRetriesDeliveryWithoutRepeatingFix(t *testing.T, newClient relayFactory) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	mac, phone := pairMac(t, dir, now)
	box := &fakeRelay{macID: mac.MacID(), failAlerts: true}
	client := newClient(t, box)
	src := &sysprobe.MemSource{}
	ctrl := &signalCounter{}
	d, err := New([]plugins.Plugin{loadExample(t)}, src, ctrl, openBook(t, dir), nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	d.UseRelay(mac, client)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := d.Cycle(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(box.events("alerts")) != 0 || len(d.outbox) != 1 {
		t.Fatal("failed alert was not queued")
	}
	box.mu.Lock()
	box.failAlerts = false
	box.mu.Unlock()
	if _, err := d.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(box.events("alerts")) != 1 || len(d.outbox) != 0 {
		t.Fatal("alert was not retried")
	}
	var alert struct {
		ID string `json:"alert_id"`
	}
	if err := json.Unmarshal(box.events("alerts")[0].Body, &alert); err != nil {
		t.Fatal(err)
	}
	signed, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: alert.ID, FixID: plugins.FixRestart, Nonce: security.NewID(), Expires: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := security.MarshalApproval(signed)
	if err != nil {
		t.Fatal(err)
	}
	src.Set(running(2))
	box.mu.Lock()
	box.failResults = true
	box.mu.Unlock()
	if err := client.Post(ctx, mac.MacID(), "approvals", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	signals, _ := ctrl.counts()
	if signals != 2 || len(d.outbox) != 1 {
		t.Fatal("missing fix or queued result")
	}
	box.mu.Lock()
	box.failResults = false
	box.mu.Unlock()
	if _, err := d.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	signals, _ = ctrl.counts()
	if signals != 2 || len(box.events("results")) != 1 || len(d.outbox) != 0 {
		t.Fatal("retry repeated a fix or lost its result")
	}
}

func TestDryRunDoesNotReportFixed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	mac, phone := pairMac(t, dir, now)
	box := &fakeRelay{macID: mac.MacID()}
	srv := httptest.NewServer(box)
	defer srv.Close()
	d := newLocalDoctor(t, dir, mac, srv.URL, &signalCounter{}, openBook(t, dir), now)
	id := security.NewID()
	if err := mac.RecordAlert(security.Raised{ID: id, ServiceID: "example-desktop-app", Actions: []string{plugins.FixRestart}}); err != nil {
		t.Fatal(err)
	}
	a, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: id, FixID: plugins.FixRestart, Nonce: security.NewID(), Expires: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := security.MarshalApproval(a)
	var res fixes.Result
	res, err = d.ApplyApproval(context.Background(), raw, true)
	if err != nil || !res.Fixed {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if results := box.events("results"); len(results) != 1 || !strings.Contains(string(results[0].Body), `"fixed":false`) {
		t.Fatalf("results %+v", results)
	}
}

func TestHostileRelayInProcess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	mac, phone := pairMac(t, dir, now)
	id := security.NewID()
	if err := mac.RecordAlert(security.Raised{ID: id, ServiceID: "example-desktop-app", Actions: []string{plugins.FixRestart}}); err != nil {
		t.Fatal(err)
	}
	a, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: id, FixID: plugins.FixRestart, Nonce: security.NewID(), Expires: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := security.MarshalApproval(a)
	if err != nil {
		t.Fatal(err)
	}
	a.AlertID = security.NewID()
	a, err = security.Sign(phone, a)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := security.MarshalApproval(a)
	if err != nil {
		t.Fatal(err)
	}
	box := &fakeRelay{macID: mac.MacID()}
	client := inProcessRelay(t, box)
	ctrl := &signalCounter{}
	src := &sysprobe.MemSource{}
	src.Set(running(2))
	d, err := New([]plugins.Plugin{loadExample(t)}, src, ctrl, openBook(t, dir), nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	d.UseRelay(mac, client)
	for _, body := range [][]byte{forgeSignature(raw), alterFixID(raw), addCommand(raw), unknown} {
		if err := client.Post(context.Background(), mac.MacID(), "approvals", json.RawMessage(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	signals, launches := ctrl.counts()
	if signals != 0 || launches != 0 || len(box.events("results")) != 0 {
		t.Fatal("hostile relay triggered a fix")
	}
	for _, reason := range []security.Reason{security.ReasonBadSignature, security.ReasonMalformed, security.ReasonUnknownAlert} {
		if !sawStatus(t, d.Log.Path(), string(reason)) {
			t.Fatalf("missing refusal %s", reason)
		}
	}
}

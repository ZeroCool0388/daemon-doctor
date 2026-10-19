package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
)

type slowTransport struct {
	posts              atomic.Int32
	approvals          atomic.Int32
	approval           json.RawMessage
	postBeforeApproval atomic.Bool
}

func (s *slowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost {
		s.posts.Add(1)
		if s.approvals.Load() == 0 {
			s.postBeforeApproval.Store(true)
		}
		// Model a slow unavailable relay: wait for the request deadline.
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	return handlerTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events := []relay.Event{}
		if strings.HasSuffix(r.URL.Path, "/approvals") {
			s.approvals.Add(1)
			if s.approval != nil && r.URL.Query().Get("after") == "0" {
				events = append(events, relay.Event{ID: 1, Kind: "approvals", Body: s.approval})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	})}.RoundTrip(r)
}

func TestRelayPollAndPostBudgets(t *testing.T) {
	if relayPollInterval != 60*time.Second {
		t.Fatalf("poll interval %s", relayPollInterval)
	}
	if relayPostBudget != 5*time.Second {
		t.Fatalf("post budget %s", relayPostBudget)
	}
}

func TestMonitoringContinuesWithSlowRetriesInProcess(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	mac, _ := pairMac(t, dir, now)
	transport := &slowTransport{}
	client, err := relay.New("https://your-relay.example.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = transport
	d := newLocalDoctor(t, dir, mac, client.BaseURL, &signalCounter{}, openBook(t, dir), now)
	d.UseRelay(mac, client)
	for i := 0; i < 1000; i++ {
		d.outbox = append(d.outbox, outgoing{kind: "alerts", body: map[string]string{"message": "example"}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*relayPostBudget+2*time.Second)
	defer cancel()
	cycles := 0
	if err := d.Run(ctx, 20*time.Millisecond, func([]ServiceStatus) { cycles++ }, func(err error) { t.Error(err) }); err != nil {
		t.Fatal(err)
	}
	if cycles < 3 || transport.approvals.Load() < 3 {
		t.Fatalf("monitoring stalled: %d checks and %d approval polls", cycles, transport.approvals.Load())
	}
	if len(d.outbox) != 1000 {
		t.Fatal("slow retry lost queued deliveries")
	}
}

func TestSlowRetryIsBoundedAndPollsFirstInProcess(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	mac, phone := pairMac(t, dir, now)
	id := security.NewID()
	if err := mac.RecordAlert(security.Raised{ID: id, ServiceID: "example-desktop-app", Actions: []string{"restart"}}); err != nil {
		t.Fatal(err)
	}
	a, err := security.Sign(phone, security.Approval{MacID: mac.MacID(), AlertID: id, FixID: "restart", Nonce: security.NewID(), Expires: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := security.MarshalApproval(a)
	if err != nil {
		t.Fatal(err)
	}
	transport := &slowTransport{approval: raw}
	client, err := relay.New("https://your-relay.example.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = transport
	ctrl := &signalCounter{}
	d := newLocalDoctor(t, dir, mac, client.BaseURL, ctrl, openBook(t, dir), now)
	d.UseRelay(mac, client)
	for i := 0; i < 1000; i++ {
		d.outbox = append(d.outbox, outgoing{kind: "alerts", body: map[string]string{"message": "example"}})
	}
	start := time.Now()
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// One result delivery and only one queued retry may each consume the post budget.
	if elapsed := time.Since(start); elapsed > 2*relayPostBudget+time.Second {
		t.Fatalf("retry backlog monopolised a cycle: %s", elapsed)
	}
	if transport.posts.Load() != 2 || transport.approvals.Load() != 1 || transport.postBeforeApproval.Load() {
		t.Fatalf("posts %d approval polls %d", transport.posts.Load(), transport.approvals.Load())
	}
	signals, _ := ctrl.counts()
	if signals != 2 {
		t.Fatal("slow retries prevented the signed approval")
	}
	before := transport.posts.Load()
	start = time.Now()
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > relayPostBudget+time.Second || transport.posts.Load()-before != 1 {
		t.Fatal("retried more than one queued delivery")
	}
	if len(d.outbox) != 1001 {
		t.Fatalf("lost pending deliveries: %d", len(d.outbox))
	}
}

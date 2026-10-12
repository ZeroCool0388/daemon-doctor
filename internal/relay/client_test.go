package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestPostAndPoll(t *testing.T) {
	box := newBox()
	srv := httptest.NewServer(box)
	defer srv.Close()
	client, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	macID := "0123456789abcdef0123456789abcdef"
	body := map[string]any{"alert_id": macID, "fix_id": "restart"}
	if err := client.Post(ctx, macID, "approvals", body); err != nil {
		t.Fatal(err)
	}
	events, err := client.Poll(ctx, macID, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "approvals" {
		t.Fatalf("events %+v", events)
	}
	var got map[string]string
	if err := json.Unmarshal(events[0].Body, &got); err != nil {
		t.Fatal(err)
	}
	if got["fix_id"] != "restart" {
		t.Fatalf("body %s", events[0].Body)
	}
	again, err := client.Poll(ctx, macID, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("cursor returned %+v", again)
	}
}

func TestWatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frame := []byte(`{"id":7,"kind":"approvals","body":{"fix_id":"restart"}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		writeCtx, stop := context.WithTimeout(r.Context(), 2*time.Second)
		defer stop()
		if err := conn.Write(writeCtx, websocket.MessageText, frame); err != nil {
			return
		}
		<-ctx.Done()
	}))
	defer srv.Close()
	client, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan Event, 1)
	done := make(chan error, 1)
	go func() {
		done <- client.Watch(ctx, "0123456789abcdef0123456789abcdef", func(event Event) {
			got <- event
			cancel()
		})
	}()
	select {
	case event := <-got:
		if event.ID != 7 || event.Kind != "approvals" {
			t.Fatalf("event %+v", event)
		}
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not receive a frame")
	}
}

func TestRejectsBadRelayURL(t *testing.T) {
	for _, raw := range []string{
		"https://user:secret@relay.example.invalid",
		"file:///tmp/relay",
		"relay.example.invalid",
	} {
		if _, err := New(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestPlaceholderWrangler(t *testing.T) {
	path := filepath.Join("..", "..", "relay", "wrangler.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, forbidden := range []string{"account_id", "api_token", "api_key", "begin private key", "route", "zone_id", "https://"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("wrangler.toml contains %s", forbidden)
		}
	}
	push, err := os.ReadFile(filepath.Join("..", "..", "relay", "src", "push.ts"))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(push))
	if strings.Contains(lower, "fcm.googleapis.com") || strings.Contains(lower, "api_key") || strings.Contains(lower, "private_key") {
		t.Fatal("push stub contains a credential or a live push URL")
	}
}

type box struct {
	mu   sync.Mutex
	rows []Event
	next int64
}

func newBox() *box {
	return &box{next: 1}
}

func (b *box) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	switch r.Method {
	case http.MethodPost:
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		id := b.next
		b.next++
		b.rows = append(b.rows, Event{ID: id, Kind: kind, Body: body})
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stored":true}`))
	case http.MethodGet:
		var after int64
		_, _ = fmtSscanf(r.URL.Query().Get("after"), &after)
		b.mu.Lock()
		var events []Event
		for _, row := range b.rows {
			if row.Kind == kind && row.ID > after {
				events = append(events, row)
			}
		}
		b.mu.Unlock()
		if events == nil {
			events = []Event{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page{Events: events})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func fmtSscanf(raw string, after *int64) (int, error) {
	if raw == "" {
		return 0, nil
	}
	var n int
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, nil
		}
		n++
		*after = *after*10 + int64(ch-'0')
	}
	return n, nil
}

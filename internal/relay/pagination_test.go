package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type pageTransport struct{ handler http.Handler }

func (p pageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	p.handler.ServeHTTP(w, r)
	res := w.Result()
	res.Request = r
	return res, nil
}

func TestBacklogPaginationAndRestartInProcess(t *testing.T) {
	const count = 350
	id := "0123456789abcdef0123456789abcdef"
	body, _ := json.Marshal(map[string]string{"pad": strings.Repeat("x", 4000)})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/macs/"+id+"/approvals" || r.URL.Query().Get("limit") != "100" {
			t.Error("unexpected mailbox request")
		}
		after, err := strconv.Atoi(r.URL.Query().Get("after"))
		if err != nil {
			t.Error(err)
		}
		events := []Event{}
		for i := after + 1; i <= count && len(events) < 100; i++ {
			events = append(events, Event{ID: int64(i), Kind: "approvals", Body: body})
		}
		raw, err := json.Marshal(map[string]any{"events": events})
		if err != nil {
			t.Error(err)
		}
		if len(raw) > maxResponse {
			t.Error("page exceeds the response budget")
		}
		_, _ = w.Write(raw)
	})
	if count*len(body) <= maxResponse {
		t.Fatal("backlog is too small to reproduce the failure")
	}
	for restart := 0; restart < 2; restart++ {
		client, err := New("https://your-relay.example.workers.dev")
		if err != nil {
			t.Fatal(err)
		}
		client.HTTP.Transport = pageTransport{handler: handler}
		total := 0
		for {
			events, err := client.Poll(context.Background(), id, "approvals")
			if err != nil {
				t.Fatal(err)
			}
			if len(events) == 0 {
				break
			}
			if len(events) > 100 {
				t.Fatal("unbounded page")
			}
			for _, event := range events {
				total++
				if event.ID != int64(total) {
					t.Fatal("skipped or repeated a backlog event")
				}
			}
		}
		if total != count {
			t.Fatalf("restart %d read %d events", restart, total)
		}
	}
}

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay/relaytest"
)

const mac = "0123456789abcdef0123456789abcdef"

func newClient(t *testing.T, base string) *relay.Client {
	t.Helper()
	c, err := relay.New(base)
	if err != nil {
		t.Fatal(err)
	}
	c.RetryMin = 10 * time.Millisecond
	c.RetryMax = 40 * time.Millisecond
	return c
}

func ids(events []relay.Event) []int64 {
	out := make([]int64, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.ID)
	}
	return out
}

func TestWatchAndPollDeliverEachEventOnce(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var watched []relay.Event
	go c.Listen(ctx, mac, func(ev relay.Event) {
		mu.Lock()
		watched = append(watched, ev)
		mu.Unlock()
	}, nil)
	waitFor(t, func() bool { return fake.Listeners(mac) == 1 })

	first := fake.Store(mac, "approvals", []byte(`{"n":1}`))
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(watched) == 1
	})
	polled, err := c.Poll(ctx, mac, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if len(polled) != 0 {
		t.Fatalf("poll repeated watched events %v", ids(polled))
	}

	cancel()
	waitFor(t, func() bool { return fake.Listeners(mac) == 0 })
	second := fake.Store(mac, "approvals", []byte(`{"n":2}`))
	polled, err = c.Poll(context.Background(), mac, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(polled); len(got) != 1 || got[0] != second || got[0] <= first {
		t.Fatalf("poll %v first %d second %d", got, first, second)
	}
}

func TestCursorFileSurvivesRestart(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	path := filepath.Join(t.TempDir(), "relay-cursor.json")
	c := newClient(t, fake.URL)
	if err := c.UseCursorFile(path); err != nil {
		t.Fatal(err)
	}
	fake.Store(mac, "approvals", []byte(`{"n":1}`))
	fake.Store(mac, "pairing", []byte(`{"n":2}`))
	for _, kind := range []string{"approvals", "pairing"} {
		if got, err := c.Poll(context.Background(), mac, kind); err != nil || len(got) != 1 {
			t.Fatalf("%s: %v %v", kind, ids(got), err)
		}
	}

	restarted := newClient(t, fake.URL)
	if err := restarted.UseCursorFile(path); err != nil {
		t.Fatal(err)
	}
	third := fake.Store(mac, "approvals", []byte(`{"n":3}`))
	got, err := restarted.Poll(context.Background(), mac, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != third {
		t.Fatalf("restart read %v", ids(got))
	}
	if got, _ := restarted.Poll(context.Background(), mac, "pairing"); len(got) != 0 {
		t.Fatalf("restart re-read pairing %v", ids(got))
	}

	other := relaytest.New()
	defer other.Close()
	moved := newClient(t, other.URL)
	if err := moved.UseCursorFile(path); err != nil {
		t.Fatal(err)
	}
	other.Store(mac, "approvals", []byte(`{"n":1}`))
	if got, _ := moved.Poll(context.Background(), mac, "approvals"); len(got) != 1 {
		t.Fatalf("a cursor from another relay URL was applied: %v", ids(got))
	}
}

func TestCursorResetsWhenMailboxIsEmptied(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	for i := 0; i < 3; i++ {
		fake.Store(mac, "approvals", []byte(`{"n":1}`))
	}
	if got, _ := c.Poll(context.Background(), mac, "approvals"); len(got) != 3 {
		t.Fatalf("poll %v", ids(got))
	}
	fake.Reset()
	if err := c.Send(context.Background(), mac, "alerts", map[string]string{"alert_id": mac}); err != nil {
		t.Fatal(err)
	}
	fresh := fake.Store(mac, "approvals", []byte(`{"n":2}`))
	got, err := c.Poll(context.Background(), mac, "approvals")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != fresh {
		t.Fatalf("after reset %v", ids(got))
	}
}

func TestSendKeepsPostsUntilRelayRecovers(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	ctx := context.Background()
	fake.Fail(http.MethodPost, "", http.StatusServiceUnavailable, 2, "relay busy")
	if err := c.Send(ctx, mac, "alerts", map[string]int{"n": 1}); err == nil {
		t.Fatal("expected an error")
	}
	if err := c.Send(ctx, mac, "results", map[string]int{"n": 2}); err == nil {
		t.Fatal("expected an error")
	}
	if c.Pending() != 2 {
		t.Fatalf("pending %d", c.Pending())
	}
	if err := c.Send(ctx, mac, "alerts", map[string]int{"n": 3}); err != nil {
		t.Fatal(err)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending %d", c.Pending())
	}
	var order []int
	for _, kind := range []string{"alerts", "results"} {
		for _, ev := range fake.Events(mac, kind) {
			var body struct{ N int }
			if err := json.Unmarshal(ev.Body, &body); err != nil {
				t.Fatal(err)
			}
			order = append(order, int(ev.ID)*10+body.N)
		}
	}
	if len(order) != 3 || order[0] != 11 || order[1] != 33 || order[2] != 22 {
		t.Fatalf("stored id*10+n %v", order)
	}
}

func TestSendDoesNotKeepPermanentRefusal(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	err := c.Send(context.Background(), mac, "alerts", map[string]string{"pad": strings.Repeat("a", relaytest.MaxBody)})
	var status *relay.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("err %v", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending %d", c.Pending())
	}
	err = c.Send(context.Background(), "not-a-mac", "alerts", map[string]string{"n": "1"})
	if !errors.As(err, &status) || status.Code != http.StatusBadRequest || c.Pending() != 0 {
		t.Fatalf("err %v pending %d", err, c.Pending())
	}
}

func TestOutboxIsBounded(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	fake.Fail(http.MethodPost, "", http.StatusBadGateway, relay.MaxOutbox*3, "down")
	for i := 0; i < relay.MaxOutbox+10; i++ {
		_ = c.Send(context.Background(), mac, "alerts", map[string]int{"n": i})
	}
	if c.Pending() != relay.MaxOutbox {
		t.Fatalf("pending %d", c.Pending())
	}
}

func TestPollReportsRelayErrors(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	fake.Fail(http.MethodGet, "approvals", http.StatusInternalServerError, 1, "internal error")
	_, err := c.Poll(context.Background(), mac, "approvals")
	var status *relay.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusInternalServerError || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("err %v", err)
	}
	fake.Fail(http.MethodGet, "approvals", http.StatusOK, 1, "<html>not a mailbox</html>")
	if _, err := c.Poll(context.Background(), mac, "approvals"); err == nil || !strings.Contains(err.Error(), "relay response") {
		t.Fatalf("err %v", err)
	}
	stored := fake.Store(mac, "approvals", []byte(`{"n":1}`))
	got, err := c.Poll(context.Background(), mac, "approvals")
	if err != nil || len(got) != 1 || got[0].ID != stored {
		t.Fatalf("after errors %v %v", ids(got), err)
	}
}

func TestListenReconnectsAfterDrop(t *testing.T) {
	fake := relaytest.New()
	defer fake.Close()
	c := newClient(t, fake.URL)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan relay.Event, 4)
	var errs sync.WaitGroup
	errs.Add(1)
	var once sync.Once
	done := make(chan struct{})
	go func() {
		c.Listen(ctx, mac, func(ev relay.Event) { got <- ev }, func(error) { once.Do(errs.Done) })
		close(done)
	}()
	waitFor(t, func() bool { return fake.Listeners(mac) == 1 })
	fake.DropSockets()
	errs.Wait()
	waitFor(t, func() bool { return fake.Dials() >= 2 && fake.Listeners(mac) == 1 })
	id := fake.Store(mac, "approvals", []byte(`{"n":1}`))
	select {
	case ev := <-got:
		if ev.ID != id || ev.Kind != "approvals" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event after reconnect")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return after cancel")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 5s")
}

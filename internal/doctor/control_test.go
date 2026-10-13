package doctor

import (
	"context"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func offerDoctor(t *testing.T) (*Doctor, *sysprobe.MemSource, *time.Time, *signalCounter) {
	t.Helper()
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	src := &sysprobe.MemSource{}
	src.Set(running(0))
	ctrl := &signalCounter{}
	book, err := logbook.Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { book.Close() })
	d, err := New([]plugins.Plugin{loadExample(t)}, src, ctrl, book, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store, err := offers.Open(filepath.Join(t.TempDir(), "control"))
	if err != nil {
		t.Fatal(err)
	}
	d.UseOffers(store)
	for range 3 {
		if _, err = d.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return d, src, &now, ctrl
}

func TestApplyOfferOnceAndSource(t *testing.T) {
	d, _, _, ctrl := offerDoctor(t)
	items, err := d.OfferedFixes()
	if err != nil || len(items) != 1 {
		t.Fatalf("offers %v %v", items, err)
	}
	if _, err = d.ApplyOffer(context.Background(), items[0].ID, "wrong", false); err == nil {
		t.Fatal("service mismatch accepted")
	}
	if ctrl.signals != 0 {
		t.Fatal("mismatch signalled")
	}
	res, err := d.ApplyOffer(context.Background(), items[0].ID, items[0].ServiceID, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixed || !strings.HasPrefix(res.Message, "Didn't work.") {
		t.Fatalf("fake failure: %+v", res)
	}
	before := ctrl.signals
	if before == 0 {
		t.Fatal("no fix attempted")
	}
	if _, err = d.ApplyOffer(context.Background(), items[0].ID, "", false); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay %v", err)
	}
	if ctrl.signals != before {
		t.Fatal("replay signalled")
	}
	events, err := d.RecentEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Kind == "fix" {
			found = true
			if event.Source != "mcp" {
				t.Fatalf("source %+v", event)
			}
		}
	}
	if !found {
		t.Fatal("fix not logged")
	}
}

func TestOfferRefusesExpiredRecoveredAndChangedAllowlist(t *testing.T) {
	for _, scenario := range []string{"expired", "recovered", "allowlist"} {
		t.Run(scenario, func(t *testing.T) {
			d, src, now, ctrl := offerDoctor(t)
			items, _ := d.OfferedFixes()
			switch scenario {
			case "expired":
				*now = now.Add(10 * time.Minute)
			case "recovered":
				src.Set(running(2))
			case "allowlist":
				delete(d.Plugins[0].Fixes, plugins.FixForceRestart)
			}
			if _, err := d.ApplyOffer(context.Background(), items[0].ID, "", false); err == nil {
				t.Fatal("unsafe offer accepted")
			}
			if ctrl.signals != 0 {
				t.Fatal("refused fix signalled")
			}
			list, err := d.OfferedFixes()
			if err != nil || len(list) != 0 {
				t.Fatalf("inactive offers: %v %v", list, err)
			}
		})
	}
}

func TestRepeatedFailuresYieldNoOffers(t *testing.T) {
	d, src, _, ctrl := offerDoctor(t)
	first, _ := d.OfferedFixes()
	for range 2 {
		src.Set(running(2))
		_, _ = d.Cycle(context.Background())
		src.Set(running(0))
		for range 3 {
			_, _ = d.Cycle(context.Background())
		}
	}
	items, err := d.OfferedFixes()
	if err != nil || len(items) != 0 {
		t.Fatalf("keeps happening offers %v %v", items, err)
	}
	if _, err = d.ApplyOffer(context.Background(), first[0].ID, "", false); err == nil {
		t.Fatal("old offer accepted")
	}
	if ctrl.signals != 0 {
		t.Fatal("suppressed fix signalled")
	}
}

func TestReadsDoNotAdvanceRulesAndAreCopies(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	before := d.sampledAt
	for range 5 {
		rows, _, err := d.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		rows[0].Outcomes[0].Detail = "mutated"
	}
	rows, at, err := d.Snapshot()
	if err != nil || !at.Equal(before) || rows[0].Outcomes[0].Detail == "mutated" {
		t.Fatal("snapshot mutates state")
	}
	items, _ := d.OfferedFixes()
	if len(items) != 1 {
		t.Fatal("reads changed offers")
	}
}

type cancelSample struct {
	sysprobe.Source
	cancel context.CancelFunc
}

func (s cancelSample) Take(ctx context.Context) (sysprobe.Snapshot, error) {
	snap, err := s.Source.Take(ctx)
	s.cancel()
	return snap, err
}

func TestCancelDuringRefreshDoesNotConsumeOrSignal(t *testing.T) {
	d, _, _, ctrl := offerDoctor(t)
	items, _ := d.OfferedFixes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := d.Source
	d.Source = cancelSample{Source: original, cancel: cancel}
	if _, err := d.ApplyOffer(ctx, items[0].ID, "", false); err == nil {
		t.Fatal("cancelled call accepted")
	}
	if ctrl.signals != 0 {
		t.Fatal("cancelled call signalled")
	}
	d.Source = original
	remaining, err := d.OfferedFixes()
	if err != nil || len(remaining) != 1 {
		t.Fatalf("cancelled pre-accept call burned offer: %v %v", remaining, err)
	}
}

func TestPreviousDaemonOffersAreInactive(t *testing.T) {
	d, src, now, ctrl := offerDoctor(t)
	old, _ := d.OfferedFixes()
	store := d.offers
	restarted, err := New(d.Plugins, src, ctrl, d.Log, nil, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	restarted.UseOffers(store)
	for range 3 {
		if _, err = restarted.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	current, err := restarted.OfferedFixes()
	if err != nil || len(current) != 1 || current[0].ID == old[0].ID {
		t.Fatalf("restart offers %v %v", current, err)
	}
	if _, err = restarted.ApplyOffer(context.Background(), old[0].ID, "", false); err == nil {
		t.Fatal("previous instance offer accepted")
	}
	if ctrl.signals != 0 {
		t.Fatal("previous instance offer signalled")
	}
}

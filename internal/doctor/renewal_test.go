package doctor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
)

func TestExpiredOfferRenewsWithoutRepeatingLiveOfferOrCountingIncident(t *testing.T) {
	d, _, now, ctrl := offerDoctor(t)
	first, _ := d.OfferedFixes()
	previous := first[0]
	for round := 0; round < 5; round++ {
		*now = previous.ExpiresAt.Add(-time.Nanosecond)
		rows, err := d.Cycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(rows[0].Alerts) != 0 {
			t.Fatalf("live offer repeated incident alert: %+v", rows)
		}
		live, _ := d.OfferedFixes()
		if len(live) != 1 || live[0].ID != previous.ID {
			t.Fatalf("live offer duplicated: %+v", live)
		}
		*now = previous.ExpiresAt
		rows, err = d.Cycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		live, _ = d.OfferedFixes()
		if len(live) != 1 || live[0].ID == previous.ID || live[0].AlertID == previous.AlertID || !live[0].ExpiresAt.Equal(now.Add(security.ApprovalTTL)) {
			t.Fatalf("renewal: %+v", live)
		}
		if len(rows[0].Alerts) != 0 {
			t.Fatalf("renewal repeated incident alert: %+v", rows)
		}
		snapshot, _, err := d.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot[0].Alerts) != 1 || !snapshot[0].Alerts[0].OfferFix || snapshot[0].Alerts[0].ID != live[0].AlertID || !snapshot[0].Alerts[0].At.Equal(*now) {
			t.Fatalf("renewal missing from active snapshot: %+v", snapshot)
		}
		if _, err := d.ApplyOffer(context.Background(), previous.ID, "", false); err == nil {
			t.Fatal("expired offer executed")
		}
		previous = live[0]
	}
	events, err := d.RecentEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	alertCount := 0
	for _, event := range events {
		if event.Kind == "alert" {
			alertCount++
		}
	}
	if alertCount != 1 {
		t.Fatalf("renewal logged duplicate incident alerts: %d", alertCount)
	}
	if ctrl.signals != 0 {
		t.Fatal("renewal executed a fix")
	}
	if _, err := d.ApplyOffer(context.Background(), previous.ID, "", false); err != nil {
		t.Fatal(err)
	}
	before := ctrl.signals
	if _, err := d.ApplyOffer(context.Background(), previous.ID, "", false); err == nil {
		t.Fatal("renewed offer replay accepted")
	}
	*now = now.Add(11 * time.Minute)
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if live, _ := d.OfferedFixes(); len(live) != 0 || ctrl.signals != before {
		t.Fatalf("consumed incident renewed: %+v", live)
	}
}

func TestRenewalRetainsRecoveryAllowlistAndLockoutSafeguards(t *testing.T) {
	for _, scenario := range []string{"recovery", "allowlist", "lockout"} {
		t.Run(scenario, func(t *testing.T) {
			d, src, now, _ := offerDoctor(t)
			switch scenario {
			case "recovery":
				src.Set(running(2))
			case "allowlist":
				delete(d.Plugins[0].Fixes, plugins.FixForceRestart)
			case "lockout":
				for range 2 {
					src.Set(running(2))
					_, _ = d.Cycle(context.Background())
					src.Set(running(0))
					for range 3 {
						_, _ = d.Cycle(context.Background())
					}
				}
			}
			*now = now.Add(11 * time.Minute)
			if _, err := d.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if live, _ := d.OfferedFixes(); len(live) != 0 {
				t.Fatalf("unsafe renewal: %+v", live)
			}
		})
	}
}

func TestFixResultSurvivesDoctorRestart(t *testing.T) {
	d, src, _, _ := relaunchDoctor(t)
	items, _ := d.OfferedFixes()
	id := items[0].ID
	res, err := d.ApplyOffer(context.Background(), id, "", false)
	if err != nil || !res.Fixed {
		t.Fatalf("fix: %+v %v", res, err)
	}
	// A new doctor instance after reconnect/restart reads the same durable store.
	store := d.offers
	restarted, err := New(d.Plugins, src, d.Fixes.Control, nil, nil, d.now)
	if err != nil {
		t.Fatal(err)
	}
	restarted.UseOffers(store)
	result, err := restarted.FixResultContext(context.Background(), id)
	if err != nil || result == nil || result.Status != "completed" || result.Fixed == nil || !*result.Fixed {
		t.Fatalf("recorded success: %+v %v", result, err)
	}
	unknown, err := restarted.FixResultContext(context.Background(), "unknown")
	if err != nil || unknown != nil {
		t.Fatalf("unknown result: %+v %v", unknown, err)
	}
}

func TestCancelledFixStillRecordsInterruptedResult(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	items, _ := d.OfferedFixes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Fixes.Source = cancelSample{Source: d.Source, cancel: cancel}
	_, err := d.ApplyOffer(ctx, items[0].ID, "", false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fix cancellation: %v", err)
	}
	result, err := d.FixResultContext(context.Background(), items[0].ID)
	if err != nil || result == nil || result.Status != "interrupted" || result.Fixed != nil {
		t.Fatalf("interrupted result: %+v %v", result, err)
	}
}

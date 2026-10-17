package doctor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestMemoryOfferReturnsAfterTemporaryIneligibility(t *testing.T) {
	for _, interruption := range []string{"pressure dip", "another largest process"} {
		for _, watched := range []bool{false, true} {
			name := interruption + "/" + map[bool]string{false: "unwatched", true: "watched"}[watched]
			t.Run(name, func(t *testing.T) {
				host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				service := loadExample(t)
				service.Fixes[plugins.FixStop] = plugins.Fix{Kind: plugins.FixStop}
				src := &sysprobe.MemSource{}
				now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
				ctrl := &signalCounter{}
				d, err := New([]plugins.Plugin{host, service}, src, ctrl, nil, nil, func() time.Time { return now })
				if err != nil {
					t.Fatal(err)
				}
				store, err := offers.Open(filepath.Join(t.TempDir(), "offers"))
				if err != nil {
					t.Fatal(err)
				}
				d.UseOffers(store)
				snap := running(2)
				snap.Host = sysprobe.Host{MemoryPressureKnown: true, MemoryPressure: "warn"}
				index := 0
				if !watched {
					snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, Name: "ExampleTool"})
					index = len(snap.Processes) - 1
				}
				snap.Processes[index].MemoryKnown = true
				snap.Processes[index].MemoryBytes = 80
				cycle := func(minute int) []ServiceStatus {
					t.Helper()
					now = time.Date(2026, 1, 2, 3, minute, 0, 0, time.UTC)
					src.Set(snap)
					rows, err := d.Cycle(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					return rows
				}
				cycle(0)
				rows := cycle(5)
				if len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != rules.KindMemoryHog {
					t.Fatalf("expected one memory alert: %+v", rows)
				}
				alert := rows[0].Alerts[0]
				original, err := d.OfferedFixes()
				wantOffers := 1
				if watched {
					wantOffers = 2 // The watched process allows both stop and restart.
				}
				if err != nil || len(original) != wantOffers {
					t.Fatalf("initial memory offers: %+v, %v", original, err)
				}
				if interruption == "pressure dip" {
					snap.Host.MemoryPressure = "normal"
				} else {
					snap.Processes = append(snap.Processes, sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90})
				}
				cycle(6)
				if _, retained := d.active[alert.ID]; !retained || !d.Rules.AlertActive(alert) {
					t.Fatal("temporary fix ineligibility removed the active memory incident")
				}
				if interruption == "pressure dip" {
					current, err := d.OfferedFixes()
					if err != nil || len(current) != len(original) {
						t.Fatalf("one-sample pressure dip dropped the memory offer: %+v, %v", current, err)
					}
					for i, offer := range original {
						if err := d.offerValid(offer); err != nil || current[i].ID != offer.ID || current[i].AlertID != alert.ID {
							t.Fatalf("one-sample pressure dip did not keep the original offer: %+v, %v", current, err)
						}
					}
				} else {
					if current, err := d.OfferedFixes(); err != nil || len(current) != 0 {
						t.Fatalf("ineligible memory fixes remained available: %+v, %v", current, err)
					}
					for _, offer := range original {
						if _, err := d.ApplyOffer(context.Background(), offer.ID, "", true); err == nil {
							t.Fatal("temporarily ineligible memory offer could be executed")
						}
					}
				}
				snap.Host.MemoryPressure = "warn"
				if interruption == "another largest process" {
					snap.Processes = snap.Processes[:len(snap.Processes)-1]
				}
				rows = cycle(7)
				if len(rows[0].Alerts) != 0 {
					t.Fatal("returning fix eligibility repeated the memory alert")
				}
				if _, retained := d.active[alert.ID]; !retained {
					t.Fatal("original memory alert did not survive the interruption")
				}
				current, err := d.OfferedFixes()
				if err != nil || len(current) != len(original) {
					t.Fatalf("original process did not regain its offers: %+v, %v", current, err)
				}
				for i, offer := range original {
					if current[i].ID != offer.ID || current[i].AlertID != alert.ID || d.offerValid(offer) != nil {
						t.Fatalf("original offer did not become valid again: %+v", current)
					}
				}
				snap.Host.MemoryPressure = "normal"
				cycle(8)
				cycle(11)
				if _, retained := d.active[alert.ID]; retained || d.Rules.AlertActive(alert) {
					t.Fatal("recovered memory incident remained active beyond the grace period")
				}
				if current, err := d.OfferedFixes(); err != nil || len(current) != 0 {
					t.Fatalf("recovered memory incident retained offers: %+v, %v", current, err)
				}
				if ctrl.signals != 0 {
					t.Fatal("offer validation signalled a process")
				}
			})
		}
	}
}

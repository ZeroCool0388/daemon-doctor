package doctor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestMemoryPhoneApprovalRejectsIneligibleFixWithoutConsuming(t *testing.T) {
	for _, interruption := range []string{"pressure dip", "another largest process"} {
		for _, watched := range []bool{false, true} {
			name := interruption + "/" + map[bool]string{false: "unwatched", true: "watched"}[watched]
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				start := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
				now := start
				mac, phone := pairMac(t, dir, now)
				host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				service := loadExample(t)
				service.Fixes[plugins.FixStop] = plugins.Fix{Kind: plugins.FixStop}
				src := &sysprobe.MemSource{}
				ctrl := &signalCounter{}
				d, err := New([]plugins.Plugin{host, service}, src, ctrl, openBook(t, dir), nil, func() time.Time { return now })
				if err != nil {
					t.Fatal(err)
				}
				d.UseRelay(mac, nil)
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
					now = start.Add(time.Duration(minute) * time.Minute)
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
				approval, err := security.Sign(phone, security.Approval{
					MacID: mac.MacID(), AlertID: alert.ID, FixID: plugins.FixStop,
					Nonce: security.NewID(), Expires: now.Add(5 * time.Minute),
				})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := security.MarshalApproval(approval)
				if err != nil {
					t.Fatal(err)
				}
				if interruption == "pressure dip" {
					snap.Host.MemoryPressure = "normal"
				} else {
					snap.Processes = append(snap.Processes, sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90})
				}
				cycle(6)
				if d.Rules.FixEligible(alert) {
					t.Fatal("test did not make the memory fix ineligible")
				}
				if _, err := d.ApplyApproval(context.Background(), raw, false); err == nil {
					t.Fatal("signed approval executed an ineligible memory fix")
				}
				if signals, launches := ctrl.counts(); signals != 0 || launches != 0 {
					t.Fatal("rejected memory approval signalled or launched a process")
				}
				if !d.Rules.AlertActive(alert) {
					t.Fatal("rejected approval withdrew the active memory incident")
				}
				// Reload the verifier to prove rejection did not persist the nonce.
				mac, err = security.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				d.UseRelay(mac, nil)
				snap.Host.MemoryPressure = "warn"
				if interruption == "another largest process" {
					snap.Processes = snap.Processes[:len(snap.Processes)-1]
				}
				rows = cycle(7)
				if len(rows[0].Alerts) != 0 || !d.Rules.FixEligible(alert) {
					t.Fatal("original process did not regain eligibility without a new alert")
				}
				if _, err := d.ApplyApproval(context.Background(), raw, false); err != nil {
					t.Fatalf("rejection consumed the approval or prevented retry: %v", err)
				}
				before, launches := ctrl.counts()
				if before == 0 || launches != 0 {
					t.Fatal("eligible phone stop did not execute")
				}
				if _, err := d.ApplyApproval(context.Background(), raw, false); !security.IsReplay(err) {
					t.Fatalf("successful approval was not protected against replay: %v", err)
				}
				if signals, _ := ctrl.counts(); signals != before {
					t.Fatal("replayed phone approval signalled again")
				}
			})
		}
	}
}

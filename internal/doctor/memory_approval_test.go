package doctor

import (
	"context"
	"encoding/json"
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
				// The live machine changes between cycles while the cached state
				// still considers the original process eligible.
				now = start.Add(6 * time.Minute)
				src.Set(snap)
				if !d.Rules.FixEligible(alert) {
					t.Fatal("test did not retain stale eligible machine state")
				}
				if watched {
					if _, err := d.ApplyApproval(context.Background(), raw, false); err == nil {
						t.Fatal("signed approval executed an ineligible memory fix")
					}
				} else {
					// Exercise the five-second relay poll path between check cycles.
					box := &fakeRelay{macID: mac.MacID()}
					client := inProcessRelay(t, box)
					d.UseRelay(mac, client)
					if err := client.Post(context.Background(), mac.MacID(), "approvals", json.RawMessage(raw)); err != nil {
						t.Fatal(err)
					}
					d.intake(context.Background())
				}
				if d.Rules.FixEligible(alert) {
					t.Fatal("phone approval did not refresh stale memory eligibility")
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

func TestMemoryPhoneApprovalOnFreshDoctor(t *testing.T) {
	for _, watched := range []bool{false, true} {
		for _, condition := range []string{"eligible", "below level", "below critical level", "another largest process", "unknown pressure", "missing process", "asleep"} {
			name := map[bool]string{false: "unwatched", true: "watched"}[watched] + "/" + condition
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				now := time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC)
				mac, phone := pairMac(t, dir, now)
				host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				service := loadExample(t)
				service.Fixes[plugins.FixStop] = plugins.Fix{Kind: plugins.FixStop}
				snap := running(2)
				snap.Host = sysprobe.Host{MemoryPressureKnown: true, MemoryPressure: "warn"}
				index, serviceID := 0, service.ID
				if !watched {
					snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, Name: "ExampleTool"})
					index, serviceID = len(snap.Processes)-1, rules.UnwatchedID
				}
				snap.Processes[index].MemoryKnown = true
				snap.Processes[index].MemoryBytes = 80
				id := security.NewID()
				if err := mac.RecordAlert(security.Raised{
					ID: id, ServiceID: serviceID, ServiceName: service.Name,
					Kind: rules.KindMemoryHog, Process: snap.Processes[index].Name,
					Actions: []string{plugins.FixStop}, At: now.Add(-time.Minute),
				}); err != nil {
					t.Fatal(err)
				}
				approval, err := security.Sign(phone, security.Approval{
					MacID: mac.MacID(), AlertID: id, FixID: plugins.FixStop,
					Nonce: security.NewID(), Expires: now.Add(5 * time.Minute),
				})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := security.MarshalApproval(approval)
				if err != nil {
					t.Fatal(err)
				}
				eligible := snap
				if condition == "below critical level" {
					for i := range host.Checks {
						if host.Checks[i].Type == plugins.CheckMemory {
							host.Checks[i].Level = "critical"
						}
					}
					eligible.Host.MemoryPressure = "critical"
				}
				snap.Processes = append([]sysprobe.Process(nil), snap.Processes...)
				switch condition {
				case "below level":
					snap.Host.MemoryPressure = "normal"
				case "another largest process":
					snap.Processes = append(snap.Processes, sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90})
				case "unknown pressure":
					snap.Host.MemoryPressureKnown = false
				case "missing process":
					snap.Processes[index].MemoryKnown = false
				case "asleep":
					snap.Host.SleepKnown, snap.Host.Asleep = true, true
				}
				src := &sysprobe.MemSource{}
				src.Set(snap)
				ctrl := &signalCounter{}
				newDoctor := func() *Doctor {
					t.Helper()
					d, err := New([]plugins.Plugin{host, service}, src, ctrl, nil, nil, func() time.Time { return now })
					if err != nil {
						t.Fatal(err)
					}
					d.UseRelay(mac, nil)
					return d
				}
				d := newDoctor()
				_, err = d.ApplyApproval(context.Background(), raw, false)
				if condition == "eligible" {
					if err != nil {
						t.Fatalf("fresh Doctor rejected a currently eligible saved memory approval: %v", err)
					}
				} else {
					if err == nil {
						t.Fatal("fresh Doctor executed an ineligible saved memory approval")
					}
					if signals, launches := ctrl.counts(); signals != 0 || launches != 0 {
						t.Fatal("ineligible standalone approval signalled or launched a process")
					}
					// A new standalone invocation can retry the same unconsumed approval.
					src.Set(eligible)
					mac, err = security.Open(dir)
					if err != nil {
						t.Fatal(err)
					}
					d = newDoctor()
					if _, err := d.ApplyApproval(context.Background(), raw, false); err != nil {
						t.Fatalf("fresh Doctor could not retry the unconsumed approval after eligibility returned: %v", err)
					}
				}
				if signals, launches := ctrl.counts(); signals == 0 || launches != 0 {
					t.Fatal("eligible standalone approval did not execute its stop")
				}
				if _, err := d.ApplyApproval(context.Background(), raw, false); !security.IsReplay(err) {
					t.Fatalf("standalone approval was not protected against replay: %v", err)
				}
			})
		}
	}
}

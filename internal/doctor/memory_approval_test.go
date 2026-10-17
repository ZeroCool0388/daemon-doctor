package doctor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestMemoryPhoneApprovalRejectsIneligibleFixWithoutConsuming(t *testing.T) {
	for _, interruption := range []string{"another largest process"} {
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
				book := openBook(t, dir)
				d, err := New([]plugins.Plugin{host, service}, src, ctrl, book, nil, func() time.Time { return now })
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
				if interruption == "another largest process" {
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
					_, err := d.ApplyApproval(context.Background(), raw, false)
					if err == nil || !strings.Contains(err.Error(), "a different process is now the largest memory user") {
						t.Fatalf("signed approval executed an ineligible memory fix: %v", err)
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
					if !strings.Contains(latestApprovalRefusal(t, book.Path()), "a different process is now the largest memory user") {
						t.Fatalf("between-cycles refusal reason %q", latestApprovalRefusal(t, book.Path()))
					}
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

// A between-cycles approval has to read the machine again. The cached rules
// can still say the fix is ineligible while the fresh sample is eligible.
func TestMemoryPhoneApprovalBetweenCyclesAppliesFreshSample(t *testing.T) {
	for _, watched := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwatched", true: "watched"}[watched], func(t *testing.T) {
			f := newMemoryFixFixture(t, watched, false)
			f.snap.Processes = append(f.snap.Processes, sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90})
			f.cycle(6)
			if f.d.Rules.FixEligible(f.alert) || !f.d.Rules.AlertActive(f.alert) {
				t.Fatal("changing the largest process did not pause the cached offer")
			}
			f.snap.Processes = f.snap.Processes[:len(f.snap.Processes)-1]
			*f.now = f.start.Add(7 * time.Minute)
			f.src.Set(f.snap)
			if f.d.Rules.FixEligible(f.alert) {
				t.Fatal("restoring the sample updated rules without an approval")
			}
			raw := f.sign()
			before := f.src.Takes
			f.deliver(raw)
			if f.src.Takes <= before {
				t.Fatal("between-cycles approval did not take a fresh sample")
			}
			if signals, launches := f.ctrl.counts(); signals == 0 || launches != 0 {
				t.Fatalf("fresh eligible sample did not apply the stop: signals %d launches %d", signals, launches)
			}
			if _, err := f.d.ApplyApproval(context.Background(), raw, false); !security.IsReplay(err) {
				t.Fatalf("applied approval was not consumed: %v", err)
			}
		})
	}
}

// One reading below the alert level is the approval's fresh sample. The offer
// stays, and the stop still runs.
func TestMemoryPhoneApprovalAppliesThroughOneSampleDip(t *testing.T) {
	for _, watched := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwatched", true: "watched"}[watched], func(t *testing.T) {
			f := newMemoryFixFixture(t, watched, true)
			original, err := f.d.OfferedFixes()
			if err != nil || len(original) == 0 {
				t.Fatalf("offers before the dip: %+v, %v", original, err)
			}
			f.snap.Host.MemoryPressure = "normal"
			*f.now = f.start.Add(6 * time.Minute)
			f.src.Set(f.snap)
			if !f.d.Rules.FixEligible(f.alert) {
				t.Fatal("rules moved before the approval sample")
			}
			raw := f.sign()
			before := f.src.Takes
			f.deliver(raw)
			if f.src.Takes <= before {
				t.Fatal("dip approval did not take a fresh sample")
			}
			if signals, launches := f.ctrl.counts(); signals == 0 || launches != 0 {
				t.Fatalf("one-sample dip refused the phone approval: signals %d launches %d", signals, launches)
			}
			if _, err := f.d.ApplyApproval(context.Background(), raw, false); !security.IsReplay(err) {
				t.Fatalf("dip approval was not consumed: %v", err)
			}
		})
	}
}

// Pressure that stays below the level for the whole recovery grace clears the
// offer. The approval that observes that sample is refused and can be retried.
func TestMemoryPhoneApprovalRefusesSustainedNormalWithoutConsuming(t *testing.T) {
	for _, watched := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwatched", true: "watched"}[watched], func(t *testing.T) {
			f := newMemoryFixFixture(t, watched, true)
			f.snap.Host.MemoryPressure = "normal"
			for _, minute := range []int{6, 7, 8} {
				rows := f.cycle(minute)
				if len(rows[0].Alerts) != 0 || !f.d.Rules.AlertActive(f.alert) || !f.d.Rules.FixEligible(f.alert) {
					t.Fatalf("minute %d dropped the offer or repeated the alert: %+v", minute, rows)
				}
				if current, err := f.d.OfferedFixes(); err != nil || len(current) == 0 {
					t.Fatalf("minute %d offer: %+v, %v", minute, current, err)
				}
			}
			*f.now = f.start.Add(9 * time.Minute)
			f.src.Set(f.snap)
			if !f.d.Rules.FixEligible(f.alert) {
				t.Fatal("grace ended before the approval sample")
			}
			raw := f.sign()
			before := f.src.Takes
			f.deliver(raw)
			if f.src.Takes <= before {
				t.Fatal("recovery approval did not take a fresh sample")
			}
			if signals, launches := f.ctrl.counts(); signals != 0 || launches != 0 {
				t.Fatal("sustained recovery ran the fix")
			}
			if f.d.Rules.AlertActive(f.alert) || f.d.Rules.FixEligible(f.alert) {
				t.Fatal("sustained recovery left the memory offer active")
			}
			if !strings.Contains(latestApprovalRefusal(t, f.book), "memory pressure has returned to normal") {
				t.Fatalf("refusal reason %q", latestApprovalRefusal(t, f.book))
			}
			if _, err := f.d.ApplyApproval(context.Background(), raw, false); err == nil || security.IsReplay(err) {
				t.Fatalf("sustained recovery consumed the approval: %v", err)
			}
		})
	}
}

func TestMemoryPhoneApprovalRechecksReloadedOffers(t *testing.T) {
	for _, eligible := range []bool{true, false} {
		for _, watched := range []bool{false, true} {
			name := map[bool]string{false: "unwatched", true: "watched"}[watched] + "/" + map[bool]string{false: "ineligible", true: "eligible"}[eligible]
			t.Run(name, func(t *testing.T) {
				f := newMemoryFixFixture(t, watched, true)
				original, err := f.d.OfferedFixes()
				if err != nil || len(original) == 0 {
					t.Fatalf("offers before restart: %+v, %v", original, err)
				}
				*f.now = f.start.Add(6 * time.Minute)
				if !eligible {
					f.snap.Processes = append(f.snap.Processes, sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90})
				}
				f.src.Set(f.snap)
				raw := f.sign()
				restarted, err := New(f.d.Plugins, f.src, f.ctrl, f.d.Log, nil, f.d.now)
				if err != nil {
					t.Fatal(err)
				}
				restarted.UseOffers(f.d.offers)
				restarted.UseRelay(f.mac, nil)
				_, err = restarted.ApplyApproval(context.Background(), raw, false)
				if eligible {
					if err != nil {
						t.Fatalf("fresh doctor rejected a reloaded eligible memory approval: %v", err)
					}
					if signals, launches := f.ctrl.counts(); signals == 0 || launches != 0 {
						t.Fatalf("reloaded approval did not stop the process: signals %d launches %d", signals, launches)
					}
					if _, err := restarted.ApplyApproval(context.Background(), raw, false); !security.IsReplay(err) {
						t.Fatalf("reloaded approval was not consumed: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "a different process is now the largest memory user") {
					t.Fatalf("reloaded ineligible approval ran: %v", err)
				}
				if signals, launches := f.ctrl.counts(); signals != 0 || launches != 0 {
					t.Fatal("reloaded ineligible approval signalled or launched a process")
				}
				left, err := f.d.offers.List(*f.now)
				if err != nil || len(left) != len(original) {
					t.Fatalf("refusal consumed reloaded offers: %+v, %v", left, err)
				}
				for _, offer := range left {
					if offer.Consumed {
						t.Fatal("refusal marked a reloaded offer consumed")
					}
				}
				if _, err := restarted.ApplyApproval(context.Background(), raw, false); err == nil || security.IsReplay(err) {
					t.Fatalf("refusal consumed the approval: %v", err)
				}
			})
		}
	}
}

type memoryFixFixture struct {
	t      *testing.T
	d      *Doctor
	src    *sysprobe.MemSource
	ctrl   *signalCounter
	mac    *security.Store
	phone  ed25519.PrivateKey
	now    *time.Time
	start  time.Time
	snap   sysprobe.Snapshot
	alert  rules.Alert
	book   string
	offers *offers.Store
}

func newMemoryFixFixture(t *testing.T, watched, withOffers bool) *memoryFixFixture {
	t.Helper()
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
	book := openBook(t, dir)
	d, err := New([]plugins.Plugin{host, service}, src, ctrl, book, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	d.UseRelay(mac, nil)
	var store *offers.Store
	if withOffers {
		store, err = offers.Open(filepath.Join(dir, "offers"))
		if err != nil {
			t.Fatal(err)
		}
		d.UseOffers(store)
	}
	snap := running(2)
	snap.Host = sysprobe.Host{MemoryPressureKnown: true, MemoryPressure: "warn"}
	index := 0
	if !watched {
		snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, Name: "ExampleTool"})
		index = len(snap.Processes) - 1
	}
	snap.Processes[index].MemoryKnown = true
	snap.Processes[index].MemoryBytes = 80
	f := &memoryFixFixture{
		t: t, d: d, src: src, ctrl: ctrl, mac: mac, phone: phone, now: &now, start: start,
		snap: snap, book: book.Path(), offers: store,
	}
	f.cycle(0)
	rows := f.cycle(5)
	if len(rows) == 0 || len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != rules.KindMemoryHog {
		t.Fatalf("expected one memory alert: %+v", rows)
	}
	f.alert = rows[0].Alerts[0]
	return f
}

func (f *memoryFixFixture) cycle(minute int) []ServiceStatus {
	f.t.Helper()
	*f.now = f.start.Add(time.Duration(minute) * time.Minute)
	f.src.Set(f.snap)
	rows, err := f.d.Cycle(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return rows
}

func (f *memoryFixFixture) sign() []byte {
	f.t.Helper()
	approval, err := security.Sign(f.phone, security.Approval{
		MacID: f.mac.MacID(), AlertID: f.alert.ID, FixID: plugins.FixStop,
		Nonce: security.NewID(), Expires: f.now.Add(5 * time.Minute),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := security.MarshalApproval(approval)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *memoryFixFixture) deliver(raw []byte) {
	f.t.Helper()
	box := &fakeRelay{macID: f.mac.MacID()}
	client := inProcessRelay(f.t, box)
	f.d.UseRelay(f.mac, client)
	if err := client.Post(context.Background(), f.mac.MacID(), "approvals", json.RawMessage(raw)); err != nil {
		f.t.Fatal(err)
	}
	f.d.intake(context.Background())
}

func latestApprovalRefusal(t *testing.T, path string) string {
	t.Helper()
	var msg string
	for _, event := range readEvents(t, path) {
		if event.Kind == "approval" && event.Status != "accepted" {
			msg = event.Message
		}
	}
	return msg
}

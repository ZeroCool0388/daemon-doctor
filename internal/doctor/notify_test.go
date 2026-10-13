package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/notify"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type notifyFunc func(context.Context, notify.Event) error

func (f notifyFunc) Send(ctx context.Context, event notify.Event) error { return f(ctx, event) }
func queuedStates(d *Doctor) []string {
	var states []string
	for {
		select {
		case event := <-d.notifications:
			states = append(states, event.State)
		default:
			return states
		}
	}
}

func captureNotifications(t *testing.T, d *Doctor) func() []notify.Event {
	t.Helper()
	sent := make(chan notify.Event, notificationQueueSize+1)
	d.UseNotifier(notifyFunc(func(_ context.Context, event notify.Event) error {
		sent <- event
		return nil
	}))
	stop := d.startNotifications(context.Background())
	t.Cleanup(stop)
	return func() []notify.Event {
		t.Helper()
		// A marker waits for the worker to finish all notifications from the cycle.
		d.notifications <- notify.Event{State: "test barrier"}
		var events []notify.Event
		for {
			select {
			case event := <-sent:
				if event.State == "test barrier" {
					return events
				}
				events = append(events, event)
			case <-time.After(time.Second):
				t.Fatal("notification worker did not finish the cycle")
			}
		}
	}
}

func TestNtfyMemoryHogAlertsOnceAndRecovers(t *testing.T) {
	host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := &sysprobe.MemSource{}
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	d, err := New([]plugins.Plugin{host, loadExample(t)}, src, nil, nil, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	sent := captureNotifications(t, d)
	snap := running(2)
	snap.Host = sysprobe.Host{MemoryPressureKnown: true, MemoryPressure: "warn"}
	snap.Processes[0].MemoryKnown = true
	snap.Processes[0].MemoryBytes = 1 << 30
	src.Set(snap)
	cycle := func() []ServiceStatus {
		t.Helper()
		rows, err := d.Cycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("memory pressure notified before the sustained threshold")
	}
	now = now.Add(6 * time.Minute)
	rows := cycle()
	if rows[0].Status != rules.StatusWatch || len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != rules.KindMemoryHog {
		t.Fatalf("expected a memory_hog alert while host is watch: %+v", rows[0])
	}
	if events := sent(); len(events) != 1 || events[0].Message != rows[0].Alerts[0].Message {
		t.Fatalf("memory_hog should send exactly one notification, got %d", len(events))
	}
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("persistent memory_hog repeated its notification")
	}
	// Neither missing pressure readings nor a hold confirms recovery.
	snap.Host.MemoryPressureKnown = false
	src.Set(snap)
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("unknown memory pressure caused a false all-clear")
	}
	snap.Host.MemoryPressureKnown = true
	snap.Host.SleepKnown, snap.Host.Asleep = true, true
	snap.Host.MemoryPressure = "normal"
	src.Set(snap)
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("held resource checks caused a false all-clear")
	}
	snap.Host.Asleep = false
	snap.Host.MemoryPressure = "warn"
	// A new largest process is still the same continuous pressure incident.
	snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 2 << 30})
	src.Set(snap)
	cycle()
	now = now.Add(6 * time.Minute)
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("changing the largest process repeated the pressure notification")
	}
	snap.Host.MemoryPressure = "normal"
	src.Set(snap)
	cycle()
	if events := sent(); len(events) != 1 || events[0].State != rules.StatusOK || events[0].Message != "Memory pressure is back to normal." {
		t.Fatalf("expected one memory all-clear, got %+v", events)
	}
	cycle()
	if events := sent(); len(events) != 0 {
		t.Fatal("memory all-clear repeated")
	}
}

func TestNtfyMachineConditionsHaveIndependentLifecycles(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		watched    bool
	}{
		{"watched CPU without fixes", rules.KindCPUHog, true},
		{"unwatched CPU", rules.KindCPUHog, false},
		{"unwatched memory", rules.KindMemoryHog, false},
		{"low disk", rules.KindDiskLow, false},
		{"network down", rules.KindNetworkDown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			service := loadExample(t)
			service.Fixes = nil
			src := &sysprobe.MemSource{}
			now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
			d, err := New([]plugins.Plugin{host, service}, src, nil, nil, nil, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			sent := captureNotifications(t, d)
			snap := running(2)
			snap.Host = sysprobe.Host{NetworkKnown: true, NetworkUp: true, DiskKnown: true, DiskFreePercent: 40, MemoryPressureKnown: true, MemoryPressure: "normal"}
			index := 0
			if !tc.watched {
				snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, Name: "OtherTool"})
				index = len(snap.Processes) - 1
			}
			cycle := func() []ServiceStatus {
				t.Helper()
				src.Set(snap)
				rows, err := d.Cycle(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				return rows
			}
			cycle()
			if events := sent(); len(events) != 0 {
				t.Fatal("initial health sent a notification")
			}
			for range 2 { // A second incident can alert again after recovery.
				switch tc.kind {
				case rules.KindCPUHog:
					snap.Processes[index].CPUKnown = true
					snap.Processes[index].CPUPercent = 95
				case rules.KindMemoryHog:
					snap.Host.MemoryPressure = "critical"
					snap.Processes[index].MemoryKnown = true
					snap.Processes[index].MemoryBytes = 1 << 30
				case rules.KindDiskLow:
					snap.Host.DiskFreePercent = 9
				case rules.KindNetworkDown:
					snap.Host.NetworkUp = false
				}
				rows := cycle()
				if tc.kind == rules.KindCPUHog || tc.kind == rules.KindMemoryHog {
					if events := sent(); len(events) != 0 {
						t.Fatal("resource incident notified before its threshold")
					}
					now = now.Add(6 * time.Minute)
					rows = cycle()
				}
				if len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != tc.kind {
					t.Fatalf("expected machine alert: %+v", rows[0])
				}
				if events := sent(); len(events) != 1 || events[0].Message != rows[0].Alerts[0].Message {
					t.Fatalf("expected one human alert message, got %+v", events)
				}
				cycle()
				if events := sent(); len(events) != 0 {
					t.Fatal("persistent machine incident repeated")
				}
				known := snap
				unknown := snap
				unknown.Host = sysprobe.Host{}
				unknown.Processes = append([]sysprobe.Process(nil), snap.Processes...)
				unknown.Processes[index].CPUKnown = false
				snap = unknown
				cycle()
				if events := sent(); len(events) != 0 {
					t.Fatal("unknown reading caused a false recovery")
				}
				snap = known
				snap.Processes[index].CPUPercent = 0
				snap.Host.MemoryPressure = "normal"
				snap.Host.DiskFreePercent = 40
				snap.Host.NetworkUp = true
				cycle()
				if events := sent(); len(events) != 1 || events[0].State != rules.StatusOK || !strings.Contains(events[0].Message, "back to normal") {
					t.Fatalf("expected one machine all-clear, got %+v", events)
				}
				cycle()
				if events := sent(); len(events) != 0 {
					t.Fatal("machine all-clear repeated")
				}
			}
		})
	}
}

func TestNtfySimultaneousMachineConditionsClearSeparately(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	sent := captureNotifications(t, d)
	d.queueMachineNotifications(rules.MachineVerdict{Alerts: []rules.Alert{
		{Kind: rules.KindMemoryHog + "_unwatched", Message: "Memory warning."},
		{Kind: rules.KindCPUHog + "_unwatched", Message: "CPU warning."},
	}})
	if events := sent(); len(events) != 2 {
		t.Fatalf("expected independent CPU and memory alerts, got %+v", events)
	}
	d.queueMachineNotifications(rules.MachineVerdict{Normal: []string{rules.KindCPUHog}})
	if events := sent(); len(events) != 1 || events[0].Message != "CPU usage is back to normal." {
		t.Fatalf("expected only CPU recovery, got %+v", events)
	}
	d.queueMachineNotifications(rules.MachineVerdict{Normal: []string{rules.KindCPUHog, rules.KindMemoryHog}})
	if events := sent(); len(events) != 1 || events[0].Message != "Memory pressure is back to normal." {
		t.Fatalf("expected only memory recovery, got %+v", events)
	}
	d.UseNotifier(nil)
	d.queueMachineNotifications(rules.MachineVerdict{Alerts: []rules.Alert{{Kind: rules.KindDiskLow, Message: "Disk warning."}}})
	if len(queuedStates(d)) != 0 {
		t.Fatal("disabled notifier queued a machine alert")
	}
}

func TestNtfyDebouncesFailuresAndRecovery(t *testing.T) {
	d, src, _, _ := offerDoctor(t)
	d.UseNotifier(notifyFunc(func(context.Context, notify.Event) error { return nil }))
	cycle := func() {
		t.Helper()
		if _, err := d.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	cycle() // Already stuck when monitoring starts: one notice.
	for range 5 {
		cycle()
	}
	states := queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusStuck {
		t.Fatal("unchanged stuck state repeated")
	}
	src.Set(running(2))
	cycle()
	cycle()
	states = queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusOK {
		t.Fatal("recovery missing or repeated")
	}
	src.Set(sysprobe.Snapshot{})
	cycle()
	if len(queuedStates(d)) != 0 {
		t.Fatal("pending sample notified before Down was confirmed")
	}
	cycle()
	cycle()
	cycle()
	states = queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusDown {
		t.Fatal("Down notice missing or repeated")
	}
	src.Set(running(0))
	cycle()
	cycle()
	cycle()
	states = queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusStuck {
		t.Fatal("changed failure state did not notify")
	}
	src.Set(running(2))
	cycle()
	cycle()
	states = queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusOK {
		t.Fatal("second recovery missing or repeated")
	}
}

func TestNtfyPausedStatesAreNotRecovery(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	d.UseNotifier(notifyFunc(func(context.Context, notify.Event) error { return nil }))
	row := ServiceStatus{ID: "example", Name: "Example", Status: rules.StatusDown}
	d.queueNotification(row)
	for _, state := range []string{rules.StatusHeld, rules.StatusPending, rules.StatusWatch, rules.StatusDown} {
		row.Status = state
		d.queueNotification(row)
	}
	row.Status = rules.StatusOK
	d.queueNotification(row)
	d.queueNotification(row)
	states := queuedStates(d)
	if len(states) != 2 || states[0] != rules.StatusDown || states[1] != rules.StatusOK {
		t.Fatal("paused state caused a false recovery or repeated failure")
	}
}

func TestNtfyWorkerDoesNotBlockChecksAndStopsWithDaemon(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	started := make(chan struct{})
	d.UseNotifier(notifyFunc(func(ctx context.Context, _ notify.Event) error { close(started); <-ctx.Done(); return ctx.Err() }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	cycles := make(chan struct{}, 16)
	go func() {
		done <- d.Run(ctx, time.Millisecond, func([]ServiceStatus) {
			select {
			case cycles <- struct{}{}:
			default:
			}
		}, nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("notification worker did not start")
	}
	for range 3 {
		select {
		case <-cycles:
		case <-time.After(time.Second):
			t.Fatal("phone delivery blocked monitoring")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Fatal("notification worker blocked daemon shutdown")
	}
}

func TestNtfyDeliveryErrorCannotLogTopic(t *testing.T) {
	d, _, _, _ := offerDoctor(t)
	topic, err := notify.GenerateTopic()
	if err != nil {
		t.Fatal(err)
	}
	d.UseNotifier(notifyFunc(func(context.Context, notify.Event) error { return errors.New(topic) }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, time.Millisecond, nil, nil) }()
	found := false
	for range 100 {
		data, err := os.ReadFile(d.Log.Path())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), topic) {
			cancel()
			<-done
			t.Fatal("notification error disclosed topic")
		}
		if strings.Contains(string(data), "ntfy delivery failed") {
			found = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if !found {
		t.Fatal("delivery failure was not recorded")
	}
}

func TestNtfyDisabledAndInitialHealthyDoNotSend(t *testing.T) {
	d, src, _, _ := offerDoctor(t)
	src.Set(running(2))
	d.UseNotifier(notifyFunc(func(context.Context, notify.Event) error { return nil }))
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(queuedStates(d)) != 0 {
		t.Fatal("initial health produced a recovery")
	}
	d.UseNotifier(nil)
	src.Set(running(0))
	for range 3 {
		if _, err := d.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(queuedStates(d)) != 0 {
		t.Fatal("disabled notifier queued a message")
	}
	// Fix rechecks use the same transition path without duplicate recovery pushes.
	d.UseNotifier(notifyFunc(func(context.Context, notify.Event) error { return nil }))
	d.notifyStates[d.Plugins[0].ID] = rules.StatusStuck
	src.Set(running(2))
	if _, err := d.ApplyFix(context.Background(), d.Plugins[0].ID, plugins.FixForceRestart, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	states := queuedStates(d)
	if len(states) != 1 || states[0] != rules.StatusOK {
		t.Fatal("fix recheck recovery missing or repeated")
	}
}

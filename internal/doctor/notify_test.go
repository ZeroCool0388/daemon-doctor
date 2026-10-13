package doctor

import (
	"context"
	"errors"
	"os"
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

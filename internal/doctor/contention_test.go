package doctor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type busyMonitorSource struct {
	sysprobe.Source
	started chan struct{}
}

func (s busyMonitorSource) Take(ctx context.Context) (sysprobe.Snapshot, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return sysprobe.Snapshot{}, ctx.Err()
	case <-timer.C:
	}
	return s.Source.Take(ctx)
}

func TestBusyMonitorDoesNotStarveOfferReads(t *testing.T) {
	d, src, _, _ := offerDoctor(t)
	started := make(chan struct{}, 1)
	d.Source = busyMonitorSource{Source: src, started: started}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, time.Nanosecond, nil, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("monitor did not stop after cancellation")
		}
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("monitor did not start")
	}
	// Every cycle takes longer than the interval, so the ticker stays ready.
	// Offer reads must queue for the state lock rather than miss its brief release.
	queryCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	items, err := d.OfferedFixesContext(queryCtx)
	if err != nil || len(items) != 1 {
		t.Fatalf("busy monitor starved offer read: %v %v", items, err)
	}
}

func TestCancelledCycleDoesNotWaitForStateLock(t *testing.T) {
	d, src, _, _ := offerDoctor(t)
	before := src.Takes
	d.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.Cycle(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error(err)
		}
	case <-time.After(time.Second):
		d.mu.Unlock()
		t.Fatal("cancelled check cycle waited for the state lock")
	}
	d.mu.Unlock()
	if src.Takes != before {
		t.Fatal("cancelled queued cycle ran a sample")
	}
}

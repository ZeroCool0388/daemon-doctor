package doctor

import (
	"context"

	"github.com/ZeroCool0388/daemon-doctor/internal/notify"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
)

const notificationQueueSize = 64

// UseNotifier attaches phone alerts independently of relay and phone pairing.
func (d *Doctor) UseNotifier(sender notify.Sender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifier = sender
	d.notifyStates = map[string]string{}
	d.notifications = make(chan notify.Event, notificationQueueSize)
}

// queueNotification runs under the doctor lock, after a confirmed observation.
// Transitional and held states preserve the incident until a healthy sample.
func (d *Doctor) queueNotification(row ServiceStatus) {
	if d.notifier == nil {
		return
	}
	previous := d.notifyStates[row.ID]
	switch row.Status {
	case rules.StatusDown, rules.StatusStuck:
		if previous == row.Status {
			return
		}
	case rules.StatusOK:
		if previous != rules.StatusDown && previous != rules.StatusStuck {
			return
		}
	default:
		return
	}
	d.notifyStates[row.ID] = row.Status
	select {
	case d.notifications <- notify.Event{ServiceName: row.Name, State: row.Status}:
	default:
		_ = d.logNote("phone notification queue full")
	}
}

// Sending never holds the doctor lock or delays check cycles. One bounded
// attempt is made per transition; unsuccessful sends do not repeat every cycle.
func (d *Doctor) startNotifications(parent context.Context) func() {
	if d.lockContext(parent) != nil {
		return func() {}
	}
	sender, queue := d.notifier, d.notifications
	d.mu.Unlock()
	if sender == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-queue:
				if ctx.Err() != nil {
					return
				}
				if err := sender.Send(ctx, event); err != nil && ctx.Err() == nil {
					if d.lockContext(ctx) == nil {
						_ = d.logNote("ntfy delivery failed")
						d.mu.Unlock()
					}
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

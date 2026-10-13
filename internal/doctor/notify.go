package doctor

import (
	"context"
	"strings"

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
	d.notifyMachine = map[string]rules.Alert{}
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
	d.enqueueNotification(notify.Event{ServiceName: row.Name, State: row.Status})
}

// Machine incidents are independent of service health and fix eligibility.
// Track the condition until a normal reading, even if its top process changes.
func (d *Doctor) queueMachineNotifications(verdict rules.MachineVerdict) {
	if d.notifier == nil {
		return
	}
	clear := func(kind, message string) {
		alert, ok := d.notifyMachine[kind]
		if !ok {
			return
		}
		delete(d.notifyMachine, kind)
		if message == "" {
			switch kind {
			case rules.KindMemoryHog:
				message = "Memory pressure is back to normal."
			case rules.KindCPUHog:
				message = "CPU usage is back to normal."
			case rules.KindDiskLow:
				message = "Free disk space is back to normal."
			}
		}
		d.enqueueNotification(notify.Event{ServiceName: alert.ServiceName, State: rules.StatusOK, Message: message})
	}
	for _, alert := range verdict.Alerts {
		kind := strings.TrimSuffix(alert.Kind, "_unwatched")
		switch kind {
		case rules.KindNetworkBack:
			outage, active := d.notifyMachine[rules.KindNetworkDown]
			if !active {
				continue
			}
			message := "Network connection was lost and is now back. "
			if !outage.At.IsZero() {
				message = "Network connection was lost at " + outage.At.UTC().Format("15:04 UTC on 2 Jan 2006") + " and is now back. "
			}
			clear(rules.KindNetworkDown, message+alert.Message)
		case rules.KindNetworkDown:
			// No default route means delivery will fail. Remember the outage
			// and report both the loss and recovery when the network is back.
			if _, active := d.notifyMachine[kind]; !active {
				d.notifyMachine[kind] = alert
			}
		case rules.KindCPUHog, rules.KindMemoryHog, rules.KindDiskLow:
			if _, active := d.notifyMachine[kind]; active {
				continue
			}
			d.notifyMachine[kind] = alert
			d.enqueueNotification(notify.Event{ServiceName: alert.ServiceName, State: "alert", Message: alert.Message})
		}
	}
	for _, kind := range verdict.Normal {
		clear(kind, "")
	}
}

func (d *Doctor) enqueueNotification(event notify.Event) {
	select {
	case d.notifications <- event:
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

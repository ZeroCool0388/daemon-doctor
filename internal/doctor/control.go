package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ZeroCool0388/daemon-doctor/internal/fixes"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"time"
)

func (d *Doctor) UseOffers(store *offers.Store) { d.mu.Lock(); defer d.mu.Unlock(); d.offers = store }

func (d *Doctor) pruneAlerts() {
	for id, a := range d.active {
		// Informational alerts remain visible for the approval window only.
		if d.held || !d.now().Before(a.At.Add(security.ApprovalTTL)) || (a.OfferFix && !d.Rules.AlertActive(a)) {
			delete(d.active, id)
		}
	}
}

// Snapshot returns the last completed monitor cycle. Reads never drive rules.
func (d *Doctor) Snapshot() ([]ServiceStatus, time.Time, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sampledAt.IsZero() {
		return nil, time.Time{}, fmt.Errorf("daemon has not completed its first check")
	}
	rows := append([]ServiceStatus(nil), d.latest...)
	for i := range rows {
		rows[i].Alerts = nil
		for _, a := range d.active {
			if a.ServiceID == rows[i].ID {
				rows[i].Alerts = append(rows[i].Alerts, a)
			}
		}
	}
	// Deep-copy so transports cannot mutate the daemon's state.
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, time.Time{}, err
	}
	var copied []ServiceStatus
	err = json.Unmarshal(data, &copied)
	return copied, d.sampledAt, err
}

func (d *Doctor) RecentEvents(limit int) ([]logbook.Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	out := []logbook.Event{}
	if d.Log == nil {
		return out, nil
	}
	// Read under the doctor lock to avoid concurrent rotation or partial appends.
	for _, path := range []string{d.Log.Path(), d.Log.Path() + ".1"} {
		events, err := logbook.Read(path)
		if err != nil {
			return nil, err
		}
		for i := len(events) - 1; i >= 0 && len(out) < limit; i-- {
			out = append(out, events[i])
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (d *Doctor) offerValid(o offers.Offer) error {
	a, ok := d.active[o.AlertID]
	if !ok || d.held || !d.Rules.AlertActive(a) {
		return fmt.Errorf("fix offer is no longer active or fixes are paused")
	}
	if a.ServiceID != o.ServiceID {
		return fmt.Errorf("offer service mismatch")
	}
	allowed := false
	for _, action := range offeredActions(a) {
		if action == o.FixID {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("fix is no longer offered for this alert")
	}
	if a.ServiceID == rules.UnwatchedID {
		if o.FixID != plugins.FixStop || !d.Rules.StopAllowed(a.Process) {
			return fmt.Errorf("stop is no longer allowed")
		}
	} else {
		p, ok := d.find(o.ServiceID)
		if !ok || !plugins.Approved(p, o.FixID) {
			return fmt.Errorf("fix is not allowlisted")
		}
	}
	return nil
}

func (d *Doctor) OfferedFixes() ([]offers.Offer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []offers.Offer{}
	if d.offers == nil {
		return out, nil
	}
	all, err := d.offers.List(d.now())
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if d.offerValid(o) == nil {
			out = append(out, o)
		}
	}
	return out, nil
}

// ApplyOffer is a local capability path, independent of signed phone approval.
// The optional service match is checked before any token is consumed.
func (d *Doctor) ApplyOffer(ctx context.Context, id, service string, dryRun bool) (fixes.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	previous := d.fixSource
	d.fixSource = "mcp"
	defer func() { d.fixSource = previous }()
	refuse := func(err error) (fixes.Result, error) { _ = d.logRefusal(id, err); return fixes.Result{}, err }
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if d.offers == nil {
		return refuse(fmt.Errorf("local fix offers are disabled"))
	}
	// Refresh observations before accepting a possibly stale offer. This is a
	// mutating operation; ordinary MCP reads use the cached cycle instead.
	if _, err := d.cycle(ctx); err != nil {
		return refuse(err)
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	o, err := d.offers.Consume(d.now(), id, func(o offers.Offer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if service != "" && o.ServiceID != service {
			return fmt.Errorf("offer does not match requested service")
		}
		return d.offerValid(o)
	})
	if err != nil {
		return refuse(err)
	}
	a := d.active[o.AlertID]
	if err = d.logAccepted(o.AlertID, o.ServiceID, o.FixID); err != nil {
		return fixes.Result{}, err
	}
	// Retire every alternative for this service, including other incident kinds.
	for key, alert := range d.active {
		if alert.ServiceID == o.ServiceID {
			delete(d.active, key)
		}
	}
	var res fixes.Result
	if o.ServiceID == rules.UnwatchedID {
		res, err = d.applyStop(ctx, a.Process, dryRun, true)
	} else {
		res, err = d.applyFix(ctx, o.ServiceID, o.FixID, dryRun)
	}
	// Publish the post-fix state in the same daemon instance.
	_, checkErr := d.cycle(ctx)
	if err == nil {
		err = checkErr
	}
	return res, err
}

func (d *Doctor) RecordMCPRefusal(id, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	previous := d.fixSource
	d.fixSource = "mcp"
	defer func() { d.fixSource = previous }()
	_ = d.logRefusal(id, fmt.Errorf("%s", message))
}

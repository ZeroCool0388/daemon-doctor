package doctor

import (
	"context"
	"encoding/json"
	"errors"
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
	return d.SnapshotContext(context.Background())
}
func (d *Doctor) SnapshotContext(ctx context.Context) ([]ServiceStatus, time.Time, error) {
	if err := d.lockContext(ctx); err != nil {
		return nil, time.Time{}, err
	}
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
	return d.RecentEventsContext(context.Background(), limit)
}
func (d *Doctor) RecentEventsContext(ctx context.Context, limit int) ([]logbook.Event, error) {
	if err := d.lockContext(ctx); err != nil {
		return nil, err
	}
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
	return d.OfferedFixesContext(context.Background())
}
func (d *Doctor) OfferedFixesContext(ctx context.Context) ([]offers.Offer, error) {
	if err := d.lockContext(ctx); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	out := []offers.Offer{}
	if d.offers == nil {
		return out, nil
	}
	all, err := d.offers.ListContext(ctx, d.now())
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
func (d *Doctor) ApplyOffer(ctx context.Context, id, service string, dryRun bool) (res fixes.Result, err error) {
	if err := d.lockContext(ctx); err != nil {
		return fixes.Result{}, err
	}
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
	o, err := d.offers.ConsumeContext(ctx, d.now(), id, func(o offers.Offer) error {
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
	// Finalization writes data only; it never extends execution past ctx.
	defer func() {
		result := offers.FixResult{Status: "completed", Message: logbook.Blank(res.Message), Detail: logbook.Blank(res.Detail)}
		if dryRun && err == nil {
			result.Status = "dry_run"
			result.Message = "Dry run completed; no fix was applied."
		} else if !dryRun && (err == nil || res.Fixed) {
			fixed := res.Fixed
			result.Fixed = &fixed
		} else {
			result.Status = "failed"
			result.Error = logbook.Blank(err.Error())
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Status = "interrupted"
				result.Message = "Fix was interrupted before its recheck completed. Check the service state."
			}
		}
		if result.Message == "" {
			result.Message = "Fix could not complete."
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if saveErr := d.offers.FinishResult(cleanup, d.now(), id, result); saveErr != nil && err == nil {
			err = saveErr
		}
	}()
	// Retire every alternative for this service, including other incident kinds.
	for key, alert := range d.active {
		if alert.ServiceID == o.ServiceID {
			delete(d.active, key)
		}
	}
	if err = d.logAccepted(o.AlertID, o.ServiceID, o.FixID); err != nil {
		return fixes.Result{}, err
	}
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

func (d *Doctor) FixResultContext(ctx context.Context, id string) (*offers.FixResult, error) {
	if err := d.lockContext(ctx); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	if d.offers == nil {
		return nil, fmt.Errorf("local fix offers are disabled")
	}
	return d.offers.ResultContext(ctx, d.now(), id)
}

// Renew only expired capabilities for an active incident, without advancing
// failure counts or reviving consumed, held or withdrawn incidents.
func (d *Doctor) renewExpiredOffers(ctx context.Context) ([]rules.Alert, error) {
	var expired []rules.Alert
	for _, alert := range d.active {
		if !d.held && alert.OfferFix && d.Rules.AlertActive(alert) && !d.now().Before(alert.At.Add(security.ApprovalTTL)) {
			expired = append(expired, alert)
		}
	}
	var renewed []rules.Alert
	for _, old := range expired {
		next := old
		next.ID, next.At = security.NewID(), d.now()
		if old.ServiceID != rules.UnwatchedID {
			p, ok := d.find(old.ServiceID)
			if !ok {
				continue
			}
			next.Actions = nil
			for _, action := range offeredActions(old) {
				if plugins.Approved(p, action) {
					next.Actions = append(next.Actions, action)
				}
			}
			if len(next.Actions) == 0 {
				continue
			}
			next.Action = next.Actions[0]
		}
		if err := d.noteAlert(ctx, next); err != nil {
			return nil, err
		}
		delete(d.active, old.ID)
		if err := d.logAlert(next); err != nil {
			return nil, err
		}
		renewed = append(renewed, next)
	}
	return renewed, nil
}

func (d *Doctor) RecordMCPRefusal(id, message string) {
	d.RecordMCPRefusalContext(context.Background(), id, message)
}
func (d *Doctor) RecordMCPRefusalContext(ctx context.Context, id, message string) {
	if d.lockContext(ctx) != nil {
		return
	}
	defer d.mu.Unlock()
	previous := d.fixSource
	d.fixSource = "mcp"
	defer func() { d.fixSource = previous }()
	_ = d.logRefusal(id, fmt.Errorf("%s", message))
}

// No detached waiter goroutine: cancellation stops a queued backend call before
// it can acquire the monitor lock and start reading or applying an offer.
func (d *Doctor) lockContext(ctx context.Context) error {
	return d.mu.LockContext(ctx)
}

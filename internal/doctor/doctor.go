// Package doctor runs one check cycle: sample, checks, alert rules, and the log.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/fixes"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// ServiceStatus is the outcome of one plug-in for one sample.
type ServiceStatus struct {
	ID       string
	Name     string
	Status   string
	Outcomes []checks.Outcome
	Alerts   []rules.Alert
}

// Doctor ties checks, rules, fixes, and the local log together.
type Doctor struct {
	Plugins []plugins.Plugin
	Source  sysprobe.Source
	Checks  *checks.Runner
	Rules   *rules.Engine
	Fixes   *fixes.Runner
	Log     *logbook.Book

	mu          sync.Mutex
	now         func() time.Time
	sec         *security.Store
	relay       *relay.Client
	outbox      []outgoing
	lastStatus  map[string]string
	lastSummary time.Time
}

type outgoing struct {
	kind string
	body any
}

const relayPollInterval = 5 * time.Second

// New validates plug-ins and returns a doctor.
// reg may be nil to use the built-in checks. now may be nil to use time.Now.
// book may be nil to skip logging.
func New(ps []plugins.Plugin, src sysprobe.Source, ctrl fixes.Controller, book *logbook.Book, reg *checks.Registry, now func() time.Time) (*Doctor, error) {
	if src == nil {
		return nil, fmt.Errorf("a system source is required")
	}
	if now == nil {
		now = time.Now
	}
	if reg == nil {
		reg = checks.NewRegistry()
	}
	list := append([]plugins.Plugin(nil), ps...)
	if err := plugins.ValidateAll(list, reg.Costs()); err != nil {
		return nil, err
	}
	runner := checks.NewRunner(reg)
	runner.Now = now
	return &Doctor{
		Plugins:    list,
		Source:     src,
		Checks:     runner,
		lastStatus: map[string]string{},
		Rules:      rules.NewEngine(now),
		Fixes: &fixes.Runner{
			Source:  src,
			Control: ctrl,
			Checks:  runner,
		},
		Log: book,
		now: now,
	}, nil
}

// UseRelay attaches local approval state and the outbound mailbox client.
// A nil client keeps alerts on this machine.
func (d *Doctor) UseRelay(sec *security.Store, client *relay.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sec = sec
	d.relay = client
}

// Cycle takes one sample, runs every plug-in, and logs checks and alerts.
// While the network is down or the Mac is asleep, service checks are skipped
// so their streaks stay where they were, and no service alert is raised.
func (d *Doctor) Cycle(ctx context.Context) ([]ServiceStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cycle(ctx)
}

func (d *Doctor) cycle(ctx context.Context) ([]ServiceStatus, error) {
	if hinted, ok := d.Source.(sysprobe.Hinted); ok {
		hinted.SetHints(hintsFor(d.Plugins))
	}
	snap, err := d.Source.Take(ctx)
	if err != nil {
		return nil, err
	}
	host, hasHost := findHost(d.Plugins)
	hold := hasHost && rules.HostHold(host, snap.Host)

	type pending struct {
		plugin   plugins.Plugin
		outcomes []checks.Outcome
	}
	rows := make([]pending, 0, len(d.Plugins))
	for _, p := range d.Plugins {
		if hold && !p.Host {
			rows = append(rows, pending{
				plugin: p,
				outcomes: []checks.Outcome{{
					Type:    "paused",
					Skipped: true,
					Detail:  "paused while the network is down or the Mac is asleep",
				}},
			})
			continue
		}
		outcomes, err := d.Checks.Run(p, snap)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.ID, err)
		}
		rows = append(rows, pending{plugin: p, outcomes: outcomes})
	}

	samples := make([]rules.Sample, 0, len(rows))
	for _, row := range rows {
		samples = append(samples, rules.Sample{Plugin: row.plugin, Outcomes: row.outcomes})
	}
	machine := d.Rules.DecideMachine(d.now(), snap, samples)

	out := make([]ServiceStatus, 0, len(rows))
	for _, row := range rows {
		st := ServiceStatus{ID: row.plugin.ID, Name: row.plugin.Name, Outcomes: row.outcomes}
		switch {
		case machine.Hold && row.plugin.Host:
			st.Status = rules.StatusHeld
			st.Alerts = machine.Alerts
		case machine.Hold:
			st.Status = rules.StatusHeld
		default:
			verdict := d.Rules.Decide(row.plugin, row.outcomes)
			if row.plugin.Host {
				verdict.Alerts = append(verdict.Alerts, machine.Alerts...)
			}
			st.Status = verdict.Status
			st.Alerts = verdict.Alerts
		}
		verdict := rules.Verdict{Status: st.Status, Alerts: st.Alerts}
		if err := d.logCheck(row.plugin, row.outcomes, verdict); err != nil {
			return nil, err
		}
		for i := range st.Alerts {
			if st.Alerts[i].ID == "" {
				st.Alerts[i].ID = security.NewID()
			}
			if err := d.noteAlert(ctx, st.Alerts[i]); err != nil {
				return nil, err
			}
			if err := d.logAlert(st.Alerts[i]); err != nil {
				return nil, err
			}
		}
		out = append(out, st)
	}
	if err := d.logSummary(out); err != nil {
		return nil, err
	}
	d.intake(ctx)
	return out, nil
}

func hintsFor(list []plugins.Plugin) sysprobe.ProbeHints {
	var hints sysprobe.ProbeHints
	for _, p := range list {
		for _, check := range p.Checks {
			switch check.Type {
			case plugins.CheckLaunchdJob:
				if check.Label != "" {
					hints.Labels = append(hints.Labels, check.Label)
				}
			case plugins.CheckFileRecent:
				if check.Path != "" {
					hints.Files = append(hints.Files, check.Path)
				}
			}
		}
	}
	return hints
}

// Run calls Cycle immediately and then on each interval until ctx is cancelled.
// onCycle and onError may be nil.
func (d *Doctor) Run(ctx context.Context, interval time.Duration, onCycle func([]ServiceStatus), onError func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	tick := func() {
		if ctx.Err() != nil {
			return
		}
		rows, err := d.Cycle(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if onError != nil {
				onError(err)
			}
			return
		}
		if onCycle != nil {
			onCycle(rows)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var relayTick <-chan time.Time
	d.mu.Lock()
	connected := d.relay != nil && d.sec != nil
	d.mu.Unlock()
	if connected {
		poller := time.NewTicker(relayPollInterval)
		defer poller.Stop()
		relayTick = poller.C
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			tick()
		case <-relayTick:
			d.mu.Lock()
			d.intake(ctx)
			d.mu.Unlock()
		}
	}
}

// ApplyFix runs an allowlisted action, logs it, rechecks, and updates alert state.
func (d *Doctor) ApplyFix(ctx context.Context, serviceID, action string, dryRun bool) (fixes.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applyFix(ctx, serviceID, action, dryRun)
}

func (d *Doctor) applyFix(ctx context.Context, serviceID, action string, dryRun bool) (fixes.Result, error) {
	p, ok := d.find(serviceID)
	if !ok {
		err := fmt.Errorf("no plug-in with id %q", serviceID)
		if logErr := d.logFix(plugins.Plugin{ID: serviceID}, action, dryRun, fixes.Result{}, err); logErr != nil {
			return fixes.Result{}, logErr
		}
		return fixes.Result{}, err
	}
	res, err := d.Fixes.Apply(ctx, p, action, dryRun)
	if logErr := d.logFix(p, action, dryRun, res, err); logErr != nil && err == nil {
		err = logErr
	}
	if err != nil {
		return res, err
	}
	verdict := d.Rules.Decide(p, res.Outcomes)
	if logErr := d.logCheck(p, res.Outcomes, verdict); logErr != nil {
		return res, logErr
	}
	for _, alert := range verdict.Alerts {
		if logErr := d.logAlert(alert); logErr != nil {
			return res, logErr
		}
	}
	return res, nil
}

// ApplyStop signals one unwatched process that a hog rule named.
// It never launches a program.
func (d *Doctor) ApplyStop(ctx context.Context, processName string, dryRun bool) (fixes.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applyStop(ctx, processName, dryRun, false)
}

func (d *Doctor) applyStop(ctx context.Context, processName string, dryRun, preapproved bool) (fixes.Result, error) {
	processName = strings.TrimSpace(processName)
	p := plugins.Plugin{ID: rules.UnwatchedID, Name: processName}
	if err := fixes.ValidProcessName(processName); err != nil {
		if logErr := d.logFix(p, plugins.FixStop, dryRun, fixes.Result{}, err); logErr != nil {
			return fixes.Result{}, logErr
		}
		return fixes.Result{}, err
	}
	if !preapproved && !d.stopPermitted(processName) {
		err := fmt.Errorf("stop is not approved for process %q", processName)
		if logErr := d.logFix(p, plugins.FixStop, dryRun, fixes.Result{}, err); logErr != nil {
			return fixes.Result{}, logErr
		}
		return fixes.Result{}, err
	}
	res, err := d.Fixes.ApplyStop(ctx, processName, dryRun)
	if logErr := d.logFix(p, plugins.FixStop, dryRun, res, err); logErr != nil && err == nil {
		err = logErr
	}
	return res, err
}

func (d *Doctor) stopPermitted(name string) bool {
	if d.Rules.StopAllowed(name) {
		return true
	}
	if d.Log == nil {
		return false
	}
	events, err := logbook.Read(d.Log.Path())
	if err != nil {
		return false
	}
	var cpuName, memName string
	var cpuOffer, memOffer bool
	for _, event := range events {
		if event.Kind != "alert" || event.ServiceID != rules.UnwatchedID {
			continue
		}
		offered := event.OfferFix != nil && *event.OfferFix
		switch event.AlertKind {
		case rules.KindCPUHog:
			cpuName = event.Process
			cpuOffer = offered
		case rules.KindMemoryHog:
			memName = event.Process
			memOffer = offered
		}
	}
	return (cpuOffer && cpuName == name) || (memOffer && memName == name)
}

func (d *Doctor) find(id string) (plugins.Plugin, bool) {
	for _, p := range d.Plugins {
		if p.ID == id {
			return p, true
		}
	}
	return plugins.Plugin{}, false
}

func findHost(list []plugins.Plugin) (plugins.Plugin, bool) {
	for _, p := range list {
		if p.Host {
			return p, true
		}
	}
	return plugins.Plugin{}, false
}

func (d *Doctor) logCheck(p plugins.Plugin, outcomes []checks.Outcome, verdict rules.Verdict) error {
	if d.Log == nil {
		return nil
	}
	if d.lastStatus == nil {
		d.lastStatus = map[string]string{}
	}
	if d.lastStatus[p.ID] == verdict.Status {
		return nil
	}
	d.lastStatus[p.ID] = verdict.Status
	ok := checks.AllHealthy(outcomes)
	return d.Log.Append(logbook.Event{
		Time:        d.now(),
		Kind:        "check",
		ServiceID:   p.ID,
		ServiceName: p.Name,
		Status:      verdict.Status,
		OK:          &ok,
		Detail:      checks.Detail(outcomes),
	})
}

func (d *Doctor) logSummary(rows []ServiceStatus) error {
	if d.Log == nil {
		return nil
	}
	now := d.now().UTC()
	if d.lastSummary.IsZero() {
		d.lastSummary = now
		return nil
	}
	if now.Sub(d.lastSummary) < time.Hour {
		return nil
	}
	d.lastSummary = now
	sorted := append([]ServiceStatus(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	parts := make([]string, 0, len(sorted))
	for _, row := range sorted {
		name := row.Name
		if name == "" {
			name = row.ID
		}
		parts = append(parts, name+": "+summaryStatus(row.Status))
	}
	return d.Log.Append(logbook.Event{
		Time:    now,
		Kind:    "summary",
		Message: "Hourly summary. " + strings.Join(parts, ". ") + ".",
	})
}

func summaryStatus(status string) string {
	switch status {
	case rules.KindMissingFlags:
		return "started without its required settings"
	case rules.KindLaunchd:
		return "not recently successful"
	case "":
		return "unknown"
	default:
		return status
	}
}

func (d *Doctor) logAlert(a rules.Alert) error {
	if d.Log == nil {
		return nil
	}
	offer := a.OfferFix
	action := a.Action
	if len(a.Actions) > 1 {
		action = strings.Join(a.Actions, " or ")
	}
	return d.Log.Append(logbook.Event{
		Time:        a.At,
		Kind:        "alert",
		ServiceID:   a.ServiceID,
		ServiceName: a.ServiceName,
		Status:      a.Kind,
		AlertKind:   a.Kind,
		AlertID:     a.ID,
		Message:     a.Message,
		OfferFix:    &offer,
		Action:      action,
		Process:     a.Process,
	})
}

func (d *Doctor) logFix(p plugins.Plugin, requested string, dry bool, res fixes.Result, applyErr error) error {
	if d.Log == nil {
		return nil
	}
	action := res.Action
	if action == "" {
		action = requested
	}
	fixed := res.Fixed
	dryRun := dry
	msg := res.Message
	if applyErr != nil {
		msg = applyErr.Error()
		fixed = false
	}
	return d.Log.Append(logbook.Event{
		Time:        d.now(),
		Kind:        "fix",
		ServiceID:   p.ID,
		ServiceName: p.Name,
		Action:      action,
		DryRun:      &dryRun,
		Fixed:       &fixed,
		Message:     msg,
		Detail:      res.Detail,
		DurationMS:  res.Duration.Milliseconds(),
	})
}

// ApplyApproval checks a signed phone approval and, when it matches an alert
// this Mac raised, runs that alert's allowlisted fix.
func (d *Doctor) ApplyApproval(ctx context.Context, raw []byte, dryRun bool) (fixes.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applyApproval(ctx, raw, dryRun)
}

func (d *Doctor) applyApproval(ctx context.Context, raw []byte, dryRun bool) (fixes.Result, error) {
	approval, err := security.UnmarshalApproval(raw)
	if err != nil {
		_ = d.logRefusal("", err)
		return fixes.Result{}, err
	}
	if d.sec == nil {
		err = fmt.Errorf("pair first")
		_ = d.logRefusal(approval.AlertID, err)
		return fixes.Result{}, err
	}
	raised, err := d.sec.Consume(d.now(), approval)
	if err != nil {
		_ = d.logRefusal(approval.AlertID, err)
		return fixes.Result{}, err
	}
	fixID := ""
	if len(raised.Actions) == 1 {
		fixID = raised.Actions[0]
	}
	_ = d.logAccepted(raised.ID, raised.ServiceID, fixID)
	var res fixes.Result
	if raised.ServiceID == rules.UnwatchedID {
		res, err = d.applyStop(ctx, raised.Process, dryRun, true)
	} else {
		res, err = d.applyFix(ctx, raised.ServiceID, fixID, dryRun)
	}
	d.publishResult(ctx, raised.ID, fixID, res, err)
	return res, err
}

func (d *Doctor) noteAlert(ctx context.Context, a rules.Alert) error {
	actions := offeredActions(a)
	if d.sec != nil {
		if err := d.sec.RecordAlert(security.Raised{
			ID:          a.ID,
			ServiceID:   a.ServiceID,
			ServiceName: a.ServiceName,
			Kind:        a.Kind,
			Actions:     actions,
			Process:     a.Process,
			At:          a.At,
		}); err != nil {
			return err
		}
	}
	if d.relay != nil && d.sec != nil {
		body := map[string]any{
			"alert_id":     a.ID,
			"service_id":   a.ServiceID,
			"service_name": a.ServiceName,
			"kind":         a.Kind,
			"message":      a.Message,
			"actions":      actions,
			"process":      a.Process,
		}
		d.send(ctx, "alerts", body)
	}
	return nil
}

func offeredActions(a rules.Alert) []string {
	if !a.OfferFix {
		return nil
	}
	if len(a.Actions) > 0 {
		return append([]string(nil), a.Actions...)
	}
	if a.Action != "" {
		return []string{a.Action}
	}
	return nil
}

func (d *Doctor) intake(ctx context.Context) {
	if d.relay == nil || d.sec == nil {
		return
	}
	d.flush(ctx)
	for _, kind := range []string{"pairing", "approvals"} {
		if ctx.Err() != nil {
			return
		}
		events, err := d.relay.Poll(ctx, d.sec.MacID(), kind)
		if err != nil {
			_ = d.logNote(err.Error())
			continue
		}
		for _, event := range events {
			d.handle(ctx, event)
		}
	}
}

func (d *Doctor) handle(ctx context.Context, event relay.Event) {
	switch event.Kind {
	case "pairing":
		if d.sec == nil {
			return
		}
		code, key, err := security.UnmarshalPairing(event.Body)
		if err != nil {
			_ = d.logRefusal("", err)
			return
		}
		if err := d.sec.AcceptPairing(d.now(), code, key); err != nil {
			_ = d.logRefusal("", err)
			return
		}
		_ = d.logAccepted("", "", security.Fingerprint(key))
	case "approvals":
		_, _ = d.applyApproval(ctx, event.Body, false)
	}
}

func (d *Doctor) publishResult(ctx context.Context, alertID, fixID string, res fixes.Result, applyErr error) {
	if d.relay == nil || d.sec == nil {
		return
	}
	msg := res.Message
	if applyErr != nil {
		msg = applyErr.Error()
	}
	body := map[string]any{
		"alert_id": alertID,
		"fix_id":   fixID,
		"fixed":    applyErr == nil && !res.DryRun && res.Fixed,
		"message":  msg,
	}
	d.send(ctx, "results", body)
}

// Failed deliveries stay in memory for the next poll. Only delivery is
// retried; an approval's persisted nonce prevents running its fix twice.
func (d *Doctor) send(ctx context.Context, kind string, body any) {
	if err := d.relay.Post(ctx, d.sec.MacID(), kind, body); err != nil {
		_ = d.logNote(err.Error())
		d.outbox = append(d.outbox, outgoing{kind: kind, body: body})
	}
}

func (d *Doctor) flush(ctx context.Context) {
	pending := d.outbox
	d.outbox = nil
	for _, item := range pending {
		d.send(ctx, item.kind, item.body)
	}
}

func (d *Doctor) logRefusal(alertID string, err error) error {
	if d.Log == nil || err == nil {
		return nil
	}
	ev := logbook.Event{
		Time:    d.now(),
		Kind:    "approval",
		AlertID: alertID,
		Message: err.Error(),
	}
	var refusal *security.Refusal
	if errors.As(err, &refusal) {
		ev.Status = string(refusal.Reason)
	}
	return d.Log.Append(ev)
}

func (d *Doctor) logAccepted(alertID, serviceID, action string) error {
	if d.Log == nil {
		return nil
	}
	return d.Log.Append(logbook.Event{
		Time:      d.now(),
		Kind:      "approval",
		AlertID:   alertID,
		ServiceID: serviceID,
		Action:    action,
		Status:    "accepted",
	})
}

func (d *Doctor) logNote(message string) error {
	if d.Log == nil {
		return nil
	}
	return d.Log.Append(logbook.Event{
		Time:    d.now(),
		Kind:    "relay",
		Message: message,
	})
}

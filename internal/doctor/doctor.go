// Package doctor runs one check cycle: sample, checks, alert rules, and the log.
package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/fixes"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
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
	now     func() time.Time
}

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
	return &Doctor{
		Plugins: list,
		Source:  src,
		Checks:  runner,
		Rules:   rules.NewEngine(now),
		Fixes: &fixes.Runner{
			Source:  src,
			Control: ctrl,
			Checks:  runner,
		},
		Log: book,
		now: now,
	}, nil
}

// Cycle takes one sample, runs every plug-in, and logs checks and alerts.
// While the network is down or the Mac is asleep, service checks are skipped
// so their streaks stay where they were, and no service alert is raised.
func (d *Doctor) Cycle(ctx context.Context) ([]ServiceStatus, error) {
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
		for _, alert := range st.Alerts {
			if err := d.logAlert(alert); err != nil {
				return nil, err
			}
		}
		out = append(out, st)
	}
	return out, nil
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
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			tick()
		}
	}
}

// ApplyFix runs an allowlisted action, logs it, rechecks, and updates alert state.
func (d *Doctor) ApplyFix(ctx context.Context, serviceID, action string, dryRun bool) (fixes.Result, error) {
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
	processName = strings.TrimSpace(processName)
	p := plugins.Plugin{ID: rules.UnwatchedID, Name: processName}
	if err := fixes.ValidProcessName(processName); err != nil {
		if logErr := d.logFix(p, plugins.FixStop, dryRun, fixes.Result{}, err); logErr != nil {
			return fixes.Result{}, logErr
		}
		return fixes.Result{}, err
	}
	if !d.stopPermitted(processName) {
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

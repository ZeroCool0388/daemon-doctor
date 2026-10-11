// Package rules decides when a service is down or stuck, suppresses repeat
// alerts, and stops offering fixes after three failures in one hour.
package rules

import (
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

const (
	KindDown           = "down"
	KindStuck          = "stuck"
	KindKeepsHappening = "keeps_happening"
	KindSleep          = "sleep"
	KindWake           = "wake"
	KindNetworkDown    = "network_down"
	KindNetworkBack    = "network_back"
	KindDiskLow        = "disk_low"
	KindCPUHog         = "cpu_hog"
	KindMemoryHog      = "memory_hog"

	StatusOK      = "ok"
	StatusWatch   = "watch"
	StatusPending = "pending"
	StatusDown    = "down"
	StatusStuck   = "stuck"
	StatusHeld    = "held"

	// UnwatchedID is the service id used when a resource hog is not a watched plug-in.
	UnwatchedID = "unwatched"

	downStreakNeeded = 2
	keepsLimit       = 3
	keepsWindow      = time.Hour
)

// Alert is one plain-English notice. OfferFix is false when no allowlisted
// fix should be offered, including after the keeps-happening rule.
type Alert struct {
	ServiceID   string
	ServiceName string
	Kind        string
	Message     string
	OfferFix    bool
	Action      string
	Actions     []string
	Process     string
	At          time.Time
}

// Verdict is the decision for one sample.
type Verdict struct {
	Status string
	Alerts []Alert
}

// Engine stores per-service streaks, recent failures, and host-rule state.
type Engine struct {
	now func() time.Time
	svc map[string]*state
	mac *machineState
}

type state struct {
	downStreak    int
	active        string
	incidents     []time.Time
	keepsNotified bool
}

// NewEngine returns an engine that uses now for the failure window.
// A nil clock uses time.Now.
func NewEngine(now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{now: now, svc: map[string]*state{}}
}

// Decide applies the down, stuck, repeat, and keeps-happening rules.
func (e *Engine) Decide(p plugins.Plugin, outcomes []checks.Outcome) Verdict {
	s := e.service(p.ID)
	notRunning, stuck, healthy := summarize(outcomes)
	if notRunning {
		s.downStreak++
	} else {
		s.downStreak = 0
	}

	kind := ""
	switch {
	case s.downStreak >= downStreakNeeded:
		kind = KindDown
	case stuck:
		kind = KindStuck
	default:
		// This sample is not an alert-level failure, so the previous
		// condition is no longer active.
		s.active = ""
		switch {
		case notRunning:
			return Verdict{Status: StatusPending}
		case !healthy:
			return Verdict{Status: StatusWatch}
		default:
			return Verdict{Status: StatusOK}
		}
	}

	status := kind
	if s.active == kind {
		return Verdict{Status: status}
	}
	s.active = kind

	now := e.now().UTC()
	s.incidents = append(s.incidents, now)
	s.incidents = prune(s.incidents, now.Add(-keepsWindow))
	if len(s.incidents) < keepsLimit {
		s.keepsNotified = false
	}
	suppress := len(s.incidents) >= keepsLimit

	if suppress && !s.keepsNotified {
		s.keepsNotified = true
		return Verdict{
			Status: status,
			Alerts: []Alert{{
				ServiceID:   p.ID,
				ServiceName: p.Name,
				Kind:        KindKeepsHappening,
				Message:     message(p, KindKeepsHappening),
				At:          now,
			}},
		}
	}

	action := ""
	offer := false
	if !suppress {
		switch kind {
		case KindDown:
			if plugins.Approved(p, plugins.FixRestart) {
				offer = true
				action = plugins.FixRestart
			}
		case KindStuck:
			if plugins.Approved(p, plugins.FixForceRestart) {
				offer = true
				action = plugins.FixForceRestart
			}
		}
	}
	alert := Alert{
		ServiceID:   p.ID,
		ServiceName: p.Name,
		Kind:        kind,
		Message:     message(p, kind),
		OfferFix:    offer,
		Action:      action,
		At:          now,
	}
	if offer && action != "" {
		alert.Actions = []string{action}
	}
	return Verdict{Status: status, Alerts: []Alert{alert}}
}

func (e *Engine) service(id string) *state {
	s, ok := e.svc[id]
	if !ok {
		s = &state{}
		e.svc[id] = s
	}
	return s
}

func summarize(outcomes []checks.Outcome) (notRunning, stuck, healthy bool) {
	healthy = len(outcomes) > 0
	saw := false
	for _, o := range outcomes {
		if o.Skipped {
			healthy = false
			continue
		}
		saw = true
		if !o.Healthy {
			healthy = false
		}
		if o.NotRunning {
			notRunning = true
		}
		if o.Stuck {
			stuck = true
		}
	}
	if !saw {
		healthy = false
	}
	return notRunning, stuck, healthy
}

func prune(times []time.Time, cutoff time.Time) []time.Time {
	out := times[:0]
	for _, ts := range times {
		if !ts.Before(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}

func message(p plugins.Plugin, kind string) string {
	return fill(templateFor(p.Messages, kind), map[string]string{"name": p.Name})
}

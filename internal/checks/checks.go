// Package checks runs a plug-in's health checks in order.
// Check types are registered, so a test can supply its own health signal.
package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// Outcome is the result of one check.
type Outcome struct {
	Type       string
	Healthy    bool
	Failed     bool
	Skipped    bool
	NotRunning bool
	Stuck      bool
	Detail     string
}

// Input is the data a check type sees for one sample.
type Input struct {
	Plugin plugins.Plugin
	Spec   plugins.Check
	Index  int
	Snap   sysprobe.Snapshot
	// Streak is the consecutive unhealthy samples for this check.
	// The check updates it. The runner keeps it across samples.
	Streak *int
}

// Type is one pluggable check.
type Type interface {
	Type() string
	Cost() int
	Run(in Input) Outcome
}

// Registry holds check types by name.
type Registry struct {
	byType map[string]Type
}

// NewRegistry returns the built-in process and outbound TCP checks.
func NewRegistry() *Registry {
	r := &Registry{byType: map[string]Type{}}
	r.mustRegister(processCheck{})
	r.mustRegister(outboundCheck{})
	return r
}

func (r *Registry) mustRegister(t Type) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

// Register adds a check type. A second registration of the same name fails.
func (r *Registry) Register(t Type) error {
	if t == nil || t.Type() == "" {
		return fmt.Errorf("check type needs a name")
	}
	if _, ok := r.byType[t.Type()]; ok {
		return fmt.Errorf("check type %q is already registered", t.Type())
	}
	r.byType[t.Type()] = t
	return nil
}

// Costs returns the cost of each registered check type.
func (r *Registry) Costs() map[string]int {
	out := make(map[string]int, len(r.byType))
	for name, t := range r.byType {
		out[name] = t.Cost()
	}
	return out
}

// Runner executes checks and remembers consecutive-sample streaks.
type Runner struct {
	reg    *Registry
	streak map[string]int
}

// NewRunner returns a runner for reg.
func NewRunner(reg *Registry) *Runner {
	if reg == nil {
		reg = NewRegistry()
	}
	return &Runner{reg: reg, streak: map[string]int{}}
}

// Run executes p's checks against snap, stopping after the first failure.
// Later checks are skipped and their streaks are reset.
func (r *Runner) Run(p plugins.Plugin, snap sysprobe.Snapshot) ([]Outcome, error) {
	out := make([]Outcome, 0, len(p.Checks))
	failed := false
	for i, spec := range p.Checks {
		key := p.ID + "#" + strconv.Itoa(i)
		if failed {
			r.streak[key] = 0
			out = append(out, Outcome{
				Type:    spec.Type,
				Skipped: true,
				Detail:  "skipped after an earlier check failed",
			})
			continue
		}
		impl, ok := r.reg.byType[spec.Type]
		if !ok {
			return nil, fmt.Errorf("unknown check type %q", spec.Type)
		}
		streak := r.streak[key]
		oc := impl.Run(Input{
			Plugin: p,
			Spec:   spec,
			Index:  i,
			Snap:   snap,
			Streak: &streak,
		})
		r.streak[key] = streak
		if oc.Type == "" {
			oc.Type = spec.Type
		}
		out = append(out, oc)
		if oc.Failed {
			failed = true
		}
	}
	return out, nil
}

// AllHealthy reports whether every check ran and looked healthy on this sample.
func AllHealthy(outcomes []Outcome) bool {
	if len(outcomes) == 0 {
		return false
	}
	for _, o := range outcomes {
		if o.Skipped || !o.Healthy {
			return false
		}
	}
	return true
}

// Detail joins check details into one line.
func Detail(outcomes []Outcome) string {
	parts := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		if o.Detail != "" {
			parts = append(parts, o.Detail)
		}
	}
	return strings.Join(parts, "; ")
}

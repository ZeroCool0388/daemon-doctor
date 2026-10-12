package checks

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

type runSight struct {
	runs int
	at   time.Time
}

// launchdCheck remembers the runs count from earlier samples so a periodic
// job can be called stale when that count does not increase within the
// job's run interval.
type launchdCheck struct {
	mu   sync.Mutex
	seen map[string]runSight
}

func (*launchdCheck) Type() string { return plugins.CheckLaunchdJob }
func (*launchdCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckLaunchdJob] }

func (c *launchdCheck) Run(in Input) Outcome {
	name := in.Plugin.Name
	maxAge, limited := parseOptionalAge(in.Spec.MaxAge)
	if strings.TrimSpace(in.Spec.MaxAge) != "" && !limited {
		return jobFail(name + " has no age limit set.")
	}
	job, ok := in.Snap.Launchd[in.Spec.Label]
	if !ok {
		return jobFail(name + " has no recorded last run.")
	}
	if job.ExitKnown && job.ExitCode != 0 {
		return jobFail(fmt.Sprintf("%s last exited with status %d.", name, job.ExitCode))
	}
	if !job.ExitKnown {
		return jobFail(name + " has no recorded last exit.")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if job.LastRunKnown && limited {
		if now.Sub(job.LastRun) > maxAge {
			return jobFail(fmt.Sprintf("%s has not had a successful run in the last %s.", name, plainAge(maxAge)))
		}
		return Outcome{
			Type:    plugins.CheckLaunchdJob,
			Healthy: true,
			Detail:  fmt.Sprintf("%s completed a successful run within the last %s.", name, plainAge(maxAge)),
		}
	}
	window := maxAge
	if window <= 0 && job.IntervalKnown {
		window = job.Interval
	}
	if job.StdoutKnown && !job.StdoutMissing && window > 0 {
		if now.Sub(job.StdoutMod) > window {
			return jobFail(fmt.Sprintf("%s has not updated its output in the last %s.", name, plainAge(window)))
		}
		return Outcome{
			Type:    plugins.CheckLaunchdJob,
			Healthy: true,
			Detail:  fmt.Sprintf("%s completed a successful run within the last %s.", name, plainAge(window)),
		}
	}
	if job.RunsKnown && job.IntervalKnown {
		switch c.noteRuns(in.Plugin.ID+"\n"+in.Spec.Label, job.Runs, job.Interval, now) {
		case runIncreased:
			return Outcome{
				Type:    plugins.CheckLaunchdJob,
				Healthy: true,
				Detail:  fmt.Sprintf("%s completed a successful run within the last %s.", name, plainAge(job.Interval)),
			}
		case runOverdue:
			return jobFail(fmt.Sprintf("%s has not run in the last %s.", name, plainAge(job.Interval)))
		}
	}
	return Outcome{
		Type:    plugins.CheckLaunchdJob,
		Healthy: true,
		Detail:  name + " last exited with status 0.",
	}
}

type runChange int

const (
	runSame runChange = iota
	runIncreased
	runOverdue
)

func (c *launchdCheck) noteRuns(key string, runs int, interval time.Duration, now time.Time) runChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]runSight{}
	}
	prev, ok := c.seen[key]
	if !ok || runs < prev.runs {
		c.seen[key] = runSight{runs: runs, at: now}
		return runSame
	}
	if runs > prev.runs {
		c.seen[key] = runSight{runs: runs, at: now}
		return runIncreased
	}
	if interval > 0 && now.Sub(prev.at) > interval {
		return runOverdue
	}
	return runSame
}

func parseOptionalAge(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

func jobFail(detail string) Outcome {
	return Outcome{
		Type:      plugins.CheckLaunchdJob,
		Failed:    true,
		JobFailed: true,
		Detail:    detail,
	}
}

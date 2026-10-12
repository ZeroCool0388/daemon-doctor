package checks

import (
	"fmt"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

type launchdCheck struct{}

func (launchdCheck) Type() string { return plugins.CheckLaunchdJob }
func (launchdCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckLaunchdJob] }

func (launchdCheck) Run(in Input) Outcome {
	maxAge, err := time.ParseDuration(in.Spec.MaxAge)
	if err != nil || maxAge <= 0 {
		return jobFail(in.Plugin.Name + " has no age limit set.")
	}
	job, ok := in.Snap.Launchd[in.Spec.Label]
	if !ok {
		return jobFail(in.Plugin.Name + " has no recorded last run.")
	}
	if job.ExitKnown && job.ExitCode != 0 {
		return jobFail(fmt.Sprintf("%s last exited with status %d.", in.Plugin.Name, job.ExitCode))
	}
	if !job.LastRunKnown {
		return jobFail(in.Plugin.Name + " has no recorded last run.")
	}
	if !job.ExitKnown {
		return jobFail(in.Plugin.Name + " has no recorded last exit.")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Sub(job.LastRun) > maxAge {
		return jobFail(fmt.Sprintf("%s has not had a successful run in the last %s.", in.Plugin.Name, plainAge(maxAge)))
	}
	return Outcome{
		Type:    plugins.CheckLaunchdJob,
		Healthy: true,
		Detail:  fmt.Sprintf("%s completed a successful run within the last %s.", in.Plugin.Name, plainAge(maxAge)),
	}
}

func jobFail(detail string) Outcome {
	return Outcome{
		Type:      plugins.CheckLaunchdJob,
		Failed:    true,
		JobFailed: true,
		Detail:    detail,
	}
}

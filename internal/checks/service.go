package checks

import (
	"fmt"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// launchdServiceCheck watches a system service that may start on demand.
// An idle service does not need a running process or a recorded job exit.
type launchdServiceCheck struct{}

func (launchdServiceCheck) Type() string { return plugins.CheckLaunchdService }
func (launchdServiceCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckLaunchdService] }

func (launchdServiceCheck) Run(in Input) Outcome {
	state := in.Snap.Services[sysprobe.ServiceHint{Label: in.Spec.Label, Port: in.Spec.Port}]
	out := Outcome{Type: plugins.CheckLaunchdService}
	switch {
	case state.Loaded:
		out.Healthy = true
		out.Detail = fmt.Sprintf("%s is enabled (system/%s is loaded; starts on demand).", in.Plugin.Name, in.Spec.Label)
	case state.Listening:
		out.Healthy = true
		out.Detail = fmt.Sprintf("%s is available (TCP port %d is listening).", in.Plugin.Name, in.Spec.Port)
	case !state.Known:
		out.Skipped = true
		out.Detail = in.Plugin.Name + " service availability could not be read."
	default:
		out.Failed = true
		out.NotRunning = true
		out.Detail = fmt.Sprintf("%s is disabled or unreachable (system/%s is not loaded and TCP port %d is not listening).", in.Plugin.Name, in.Spec.Label, in.Spec.Port)
	}
	return out
}

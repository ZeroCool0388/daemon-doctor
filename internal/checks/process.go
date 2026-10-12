package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type processCheck struct{}

func (processCheck) Type() string { return plugins.CheckProcessRunning }
func (processCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckProcessRunning] }

func (processCheck) Run(in Input) Outcome {
	found := sysprobe.MatchingSpec(in.Snap, in.Plugin.Process.Spec())
	name := watchedName(in)
	if len(found) == 0 {
		return Outcome{
			Type:       plugins.CheckProcessRunning,
			NotRunning: true,
			Failed:     true,
			Detail:     fmt.Sprintf("process %s is not running", name),
		}
	}
	pids := make([]string, len(found))
	for i, proc := range found {
		pids[i] = strconv.Itoa(proc.PID)
	}
	return Outcome{
		Type:    plugins.CheckProcessRunning,
		Healthy: true,
		Detail:  fmt.Sprintf("process %s is running (pid %s)", name, strings.Join(pids, ", ")),
	}
}

// watchedName is the process match, or the plug-in display name when the
// plug-in matches only by a command-line substring or expression.
func watchedName(in Input) string {
	if name := strings.TrimSpace(in.Plugin.Process.Match); name != "" {
		return name
	}
	if name := strings.TrimSpace(in.Plugin.Name); name != "" {
		return name
	}
	return "service"
}

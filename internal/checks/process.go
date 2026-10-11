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
	found := sysprobe.Matching(in.Snap, in.Plugin.Process.Match)
	if len(found) == 0 {
		return Outcome{
			Type:       plugins.CheckProcessRunning,
			NotRunning: true,
			Failed:     true,
			Detail:     fmt.Sprintf("process %s is not running", in.Plugin.Process.Match),
		}
	}
	pids := make([]string, len(found))
	for i, proc := range found {
		pids[i] = strconv.Itoa(proc.PID)
	}
	return Outcome{
		Type:    plugins.CheckProcessRunning,
		Healthy: true,
		Detail:  fmt.Sprintf("process %s is running (pid %s)", in.Plugin.Process.Match, strings.Join(pids, ", ")),
	}
}

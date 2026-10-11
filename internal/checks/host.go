package checks

import (
	"fmt"
	"strconv"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type sleepCheck struct{}

func (sleepCheck) Type() string { return plugins.CheckSleep }
func (sleepCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckSleep] }

func (sleepCheck) Run(in Input) Outcome {
	h := in.Snap.Host
	if !h.SleepKnown {
		return Outcome{Type: plugins.CheckSleep, Healthy: true, Detail: "sleep state is not available"}
	}
	if h.Asleep {
		return Outcome{Type: plugins.CheckSleep, Detail: "the Mac is asleep"}
	}
	return Outcome{Type: plugins.CheckSleep, Healthy: true, Detail: "the Mac is awake"}
}

type networkCheck struct{}

func (networkCheck) Type() string { return plugins.CheckNetwork }
func (networkCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckNetwork] }

func (networkCheck) Run(in Input) Outcome {
	h := in.Snap.Host
	if !h.NetworkKnown {
		return Outcome{Type: plugins.CheckNetwork, Healthy: true, Detail: "network state is not available"}
	}
	if !h.NetworkUp {
		return Outcome{Type: plugins.CheckNetwork, Detail: "the network is down"}
	}
	return Outcome{Type: plugins.CheckNetwork, Healthy: true, Detail: "the network is up"}
}

type diskCheck struct{}

func (diskCheck) Type() string { return plugins.CheckDisk }
func (diskCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckDisk] }

func (diskCheck) Run(in Input) Outcome {
	h := in.Snap.Host
	if !h.DiskKnown {
		return Outcome{Type: plugins.CheckDisk, Healthy: true, Detail: "disk space is not available"}
	}
	free := formatPercent(h.DiskFreePercent)
	if h.DiskFreePercent < in.Spec.MinFreePercent {
		return Outcome{
			Type:   plugins.CheckDisk,
			Detail: fmt.Sprintf("free disk space is %s%%, below %s%%", free, formatPercent(in.Spec.MinFreePercent)),
		}
	}
	return Outcome{Type: plugins.CheckDisk, Healthy: true, Detail: fmt.Sprintf("free disk space is %s%%", free)}
}

type memoryCheck struct{}

func (memoryCheck) Type() string { return plugins.CheckMemory }
func (memoryCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckMemory] }

func (memoryCheck) Run(in Input) Outcome {
	h := in.Snap.Host
	if !h.MemoryPressureKnown {
		return Outcome{Type: plugins.CheckMemory, Healthy: true, Detail: "memory pressure is not available"}
	}
	level := h.MemoryPressure
	if pressureRank(level) >= pressureRank(in.Spec.Level) && pressureRank(in.Spec.Level) > 0 {
		return Outcome{Type: plugins.CheckMemory, Detail: "memory pressure is " + pressureWord(level)}
	}
	return Outcome{Type: plugins.CheckMemory, Healthy: true, Detail: "memory pressure is " + pressureWord(level)}
}

type cpuCheck struct{}

func (cpuCheck) Type() string { return plugins.CheckCPU }
func (cpuCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckCPU] }

func (cpuCheck) Run(in Input) Outcome {
	top, ok := sysprobe.TopCPU(in.Snap)
	if !ok {
		return Outcome{Type: plugins.CheckCPU, Healthy: true, Detail: "cpu use is not available"}
	}
	line := in.Spec.CPUPercent
	if line <= 0 {
		line = plugins.DefaultCPUPercent
	}
	name := sysprobe.DisplayName(top)
	if top.CPUPercent >= line {
		return Outcome{
			Type:   plugins.CheckCPU,
			Detail: fmt.Sprintf("cpu %s%% on %s", formatPercent(top.CPUPercent), name),
		}
	}
	return Outcome{
		Type:    plugins.CheckCPU,
		Healthy: true,
		Detail:  fmt.Sprintf("cpu %s%% on %s", formatPercent(top.CPUPercent), name),
	}
}

func pressureRank(level string) int {
	switch level {
	case "warn":
		return 1
	case "critical":
		return 2
	case "normal":
		return 0
	default:
		return -1
	}
}

func pressureWord(level string) string {
	switch level {
	case "warn":
		return "warning"
	case "critical":
		return "critical"
	case "normal":
		return "normal"
	default:
		return level
	}
}

func formatPercent(v float64) string {
	rounded := float64(int(v*10+0.5)) / 10
	if rounded == float64(int(rounded)) {
		return strconv.Itoa(int(rounded))
	}
	return strconv.FormatFloat(rounded, 'f', 1, 64)
}

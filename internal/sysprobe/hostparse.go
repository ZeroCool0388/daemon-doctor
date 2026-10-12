package sysprobe

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DisplayName is the short process name used in alerts.
// It is the kernel name, or the executable base name, and never the full command line.
func DisplayName(p Process) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Exe != "" {
		base := filepath.Base(p.Exe)
		if base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	if p.PID > 0 {
		return fmt.Sprintf("pid %d", p.PID)
	}
	return "unknown"
}

// TopCPU returns the CPUKnown process with the highest share of the machine.
// Equal shares use the lower PID.
func TopCPU(s Snapshot) (Process, bool) {
	var best Process
	found := false
	for _, p := range s.Processes {
		if !p.CPUKnown || p.PID <= 0 {
			continue
		}
		if !found || p.CPUPercent > best.CPUPercent || (p.CPUPercent == best.CPUPercent && p.PID < best.PID) {
			best = p
			found = true
		}
	}
	return best, found
}

// TopMemory returns the MemoryKnown process using the most bytes.
// Equal sizes use the lower PID.
func TopMemory(s Snapshot) (Process, bool) {
	var best Process
	found := false
	for _, p := range s.Processes {
		if !p.MemoryKnown || p.PID <= 0 {
			continue
		}
		if !found || p.MemoryBytes > best.MemoryBytes || (p.MemoryBytes == best.MemoryBytes && p.PID < best.PID) {
			best = p
			found = true
		}
	}
	return best, found
}

// TickSample is one CPU reading. Total is the machine's tick count.
// Proc maps a PID to that process's user plus system ticks.
type TickSample struct {
	Total uint64
	Proc  map[int]uint64
}

// CPUShare converts a process tick delta and a machine tick delta into a
// percentage of the whole machine, capped at 100. A zero machine delta is unknown.
func CPUShare(deltaProc, deltaTotal uint64) (float64, bool) {
	if deltaTotal == 0 {
		return 0, false
	}
	pct := float64(deltaProc) / float64(deltaTotal) * 100
	if pct < 0 {
		return 0, false
	}
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

// ApplyCPU sets CPUKnown from the difference of two samples.
// The first sample has no previous reading, so every process stays unknown.
func ApplyCPU(prev, cur TickSample, procs []Process) []Process {
	out := append([]Process(nil), procs...)
	if prev.Total == 0 || cur.Total <= prev.Total {
		return out
	}
	deltaTotal := cur.Total - prev.Total
	for i := range out {
		prevTicks, okPrev := prev.Proc[out[i].PID]
		curTicks, okCur := cur.Proc[out[i].PID]
		if !okPrev || !okCur || curTicks < prevTicks {
			continue
		}
		pct, known := CPUShare(curTicks-prevTicks, deltaTotal)
		out[i].CPUKnown = known
		out[i].CPUPercent = pct
	}
	return out
}

// ScaleMachineCPU turns a per-CPU percentage into a share of the whole machine.
func ScaleMachineCPU(raw float64, ncpu int) float64 {
	if ncpu < 1 {
		ncpu = 1
	}
	pct := raw / float64(ncpu)
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

// ParseProcStatTotal reads the aggregate "cpu" line from /proc/stat.
func ParseProcStatTotal(text string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "cpu" {
			continue
		}
		var total uint64
		for _, field := range fields[1:] {
			n, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, false
			}
			total += n
		}
		return total, true
	}
	return 0, false
}

// ParsePIDStatTicks reads utime+stime from /proc/pid/stat.
// Those are the 14th and 15th fields, which sit just after the comm field.
func ParsePIDStatTicks(text string) (uint64, bool) {
	text = strings.TrimSpace(text)
	close := strings.LastIndex(text, ")")
	if close < 0 || close == len(text)-1 {
		return 0, false
	}
	rest := strings.Fields(text[close+1:])
	// state ppid ... utime stime, so utime is index 11 and stime is index 12.
	if len(rest) < 13 {
		return 0, false
	}
	utime, err1 := strconv.ParseUint(rest[11], 10, 64)
	stime, err2 := strconv.ParseUint(rest[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return utime + stime, true
}

func parseStatmResident(text string) (int64, bool) {
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ParseProcNetRoute reports whether /proc/net/route lists an IPv4 default route.
// The gateway address is not returned.
func ParseProcNetRoute(text string) (up, known bool) {
	saw := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "Iface" || fields[1] == "Destination" {
			saw = true
			continue
		}
		saw = true
		if fields[1] == "00000000" {
			return true, true
		}
	}
	if !saw {
		return false, false
	}
	return false, true
}

// ParseMeminfo maps MemAvailable/MemTotal onto normal, warn, or critical.
// This is a Linux stand-in for memory pressure: at least 20% available is
// normal, at least 10% is warn, and below that is critical.
func ParseMeminfo(text string) (level string, known bool) {
	var total, avail int64
	var sawTotal, sawAvail bool
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			if n > 0 {
				total = n
				sawTotal = true
			}
		case "MemAvailable:":
			if n >= 0 {
				avail = n
				sawAvail = true
			}
		}
	}
	if !sawTotal || !sawAvail || total <= 0 {
		return "", false
	}
	return PressureFromFreeRatio(float64(avail) / float64(total)), true
}

// PressureFromFreeRatio maps a free-memory ratio to normal, warn, or critical.
func PressureFromFreeRatio(ratio float64) string {
	switch {
	case ratio >= 0.20:
		return "normal"
	case ratio >= 0.10:
		return "warn"
	default:
		return "critical"
	}
}

// ParseDF reads POSIX df -P output and returns available space as a percent
// of the 1024-block size. The first data line is used.
func ParseDF(text string) (percent float64, known bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Filesystem") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, false
		}
		blocks, err1 := strconv.ParseFloat(fields[len(fields)-5], 64)
		avail, err2 := strconv.ParseFloat(fields[len(fields)-3], 64)
		if err1 != nil || err2 != nil || blocks <= 0 || avail < 0 {
			return 0, false
		}
		return avail / blocks * 100, true
	}
	return 0, false
}

// ParsePMSetLog reads pmset -g log text. Sleep means asleep.
// Wake and DarkWake mean awake. The last event wins.
func ParsePMSetLog(text string) (asleep, known bool) {
	for _, line := range strings.Split(text, "\n") {
		kind, ok := pmsetEvent(line)
		if !ok {
			continue
		}
		asleep = kind == "sleep"
		known = true
	}
	return asleep, known
}

func pmsetEvent(line string) (string, bool) {
	for _, field := range strings.Fields(line) {
		switch field {
		case "DarkWake", "Wake":
			return "wake", true
		case "Sleep":
			return "sleep", true
		}
	}
	return "", false
}

// ParseRouteGet reads `route -n get default` output.
// A gateway or interface line means a default route exists. The address is discarded.
func ParseRouteGet(text string) (up, known bool) {
	if strings.TrimSpace(text) == "" {
		return false, false
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		var prefix string
		switch {
		case strings.HasPrefix(lower, "gateway:"):
			prefix = "gateway:"
		case strings.HasPrefix(lower, "interface:"):
			prefix = "interface:"
		default:
			continue
		}
		val := strings.TrimSpace(line[len(prefix):])
		if val != "" {
			return true, true
		}
	}
	return false, true
}

// ParseVMPressure reads a memory-pressure level.
// 1 is normal, 2 is warn, and 4 is critical.
func ParseVMPressure(text string) (level string, known bool) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "1", "normal":
		return "normal", true
	case "2", "warn", "warning":
		return "warn", true
	case "4", "critical":
		return "critical", true
	default:
		return "", false
	}
}

// ParseMemoryPressureText reads a "memory free percentage" line.
func ParseMemoryPressureText(text string) (level string, known bool) {
	const marker = "memory free percentage:"
	lower := strings.ToLower(text)
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return "", false
	}
	rest := strings.TrimSpace(text[idx+len(marker):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "%"), 64)
	if err != nil {
		return "", false
	}
	return PressureFromFreeRatio(pct / 100), true
}

// ParsePSResource reads "pid ppid %cpu rss command" lines.
// %cpu is the raw ps value. rss is kilobytes. Callers scale %cpu to a machine share.
// The command line is stored whole. The executable path is not taken from it,
// because an application path can contain spaces.
func ParsePSResource(text string) ([]Process, error) {
	var procs []Process
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, rest, ok := leadingInt(line)
		if !ok {
			return nil, fmt.Errorf("ps line has no pid: %q", line)
		}
		ppid, rest, ok := leadingInt(rest)
		if !ok {
			return nil, fmt.Errorf("ps line has no parent pid: %q", line)
		}
		cpu, rest, ok := leadingFloat(rest)
		if !ok {
			return nil, fmt.Errorf("ps line has no cpu: %q", line)
		}
		rss, rest, ok := leadingInt(rest)
		if !ok {
			return nil, fmt.Errorf("ps line has no rss: %q", line)
		}
		cmd := strings.TrimSpace(rest)
		procs = append(procs, Process{
			PID:         pid,
			PPID:        ppid,
			Cmd:         cmd,
			CPUKnown:    true,
			CPUPercent:  cpu,
			MemoryKnown: true,
			MemoryBytes: int64(rss) * 1024,
		})
	}
	return procs, nil
}

// ParsePSPaths reads "pid path" lines from `ps -o pid= -o comm=`.
// The path is the rest of the line, so it may contain spaces.
func ParsePSPaths(text string) (map[int]string, error) {
	out := map[int]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, rest, ok := leadingInt(line)
		if !ok {
			return nil, fmt.Errorf("ps path line has no pid: %q", line)
		}
		path := strings.TrimSpace(rest)
		if path == "" || pid <= 0 {
			continue
		}
		out[pid] = path
	}
	return out, nil
}

// ApplyExePaths sets Exe and Name from a pid-to-path map.
// Name is the base name of that path. Paths that are missing are left unset.
func ApplyExePaths(procs []Process, paths map[int]string) []Process {
	out := append([]Process(nil), procs...)
	for i := range out {
		path := strings.TrimSpace(paths[out[i].PID])
		if path == "" {
			continue
		}
		out[i].Exe = path
		out[i].Name = filepathBase(path)
	}
	return out
}

// ParseLaunchctlPrint reads `launchctl print` text for one job.
// It reads the last exit code, the runs count, the run interval, and the
// stdout path. A last exit time is kept when a print includes one.
// A job that has never exited, and that has none of those fields, is unknown.
func ParseLaunchctlPrint(text string) (LaunchdJob, bool) {
	var job LaunchdJob
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := splitEq(line)
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "last exit code":
			if code, known := parseExitCode(val); known {
				job.ExitCode = code
				job.ExitKnown = true
			}
		case "last exit time":
			if ts, known := parseLaunchdTime(val); known {
				job.LastRun = ts
				job.LastRunKnown = true
			}
		case "runs":
			if n, known := parseRuns(val); known {
				job.Runs = n
				job.RunsKnown = true
			}
		case "run interval":
			if d, known := parseRunInterval(val); known {
				job.Interval = d
				job.IntervalKnown = true
			}
		case "stdout path":
			path := strings.TrimSpace(val)
			if path != "" && path != "-" {
				job.StdoutPath = path
			}
		}
	}
	found := job.ExitKnown || job.LastRunKnown || job.RunsKnown || job.IntervalKnown || job.StdoutPath != ""
	return job, found
}

func splitEq(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	return line[:idx], strings.TrimSpace(line[idx+1:]), true
}

func parseExitCode(val string) (int, bool) {
	val = strings.TrimSpace(val)
	if val == "" || strings.Contains(strings.ToLower(val), "never") {
		return 0, false
	}
	val = strings.Trim(val, "()")
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return 0, false
	}
	token := strings.TrimRight(fields[0], ":")
	n, err := strconv.Atoi(token)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseRuns(val string) (int, bool) {
	fields := strings.Fields(strings.TrimSpace(val))
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseRunInterval(val string) (time.Duration, bool) {
	fields := strings.Fields(strings.TrimSpace(val))
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	unit := "seconds"
	if len(fields) > 1 {
		unit = strings.ToLower(strings.TrimRight(fields[1], ".,"))
	}
	var d time.Duration
	switch unit {
	case "second", "seconds", "sec", "secs", "s":
		d = time.Duration(n) * time.Second
	case "minute", "minutes", "min", "mins", "m":
		d = time.Duration(n) * time.Minute
	case "hour", "hours", "h":
		d = time.Duration(n) * time.Hour
	default:
		return 0, false
	}
	return d, true
}

func parseLaunchdTime(val string) (time.Time, bool) {
	val = strings.TrimSpace(val)
	if val == "" || val == "-" || strings.EqualFold(val, "never") {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0).UTC(), true
	}
	layouts := []string{
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, val); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func leadingFloat(s string) (float64, string, bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, s, false
	}
	return n, strings.TrimSpace(s[i:]), true
}

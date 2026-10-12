package sysprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const hostReadTimeout = 2 * time.Second

// liveSource reads the machine this process is running on.
// It keeps the previous CPU sample so a percentage can be a delta.
type liveSource struct {
	mu    sync.Mutex
	prev  TickSample
	hints ProbeHints
}

// SetHints records the launchd labels and file paths the next sample should read.
func (s *liveSource) SetHints(h ProbeHints) {
	s.mu.Lock()
	s.hints = h
	s.mu.Unlock()
}

// Live returns a Source backed by the local operating system.
func Live() Source { return &liveSource{} }

func (s *liveSource) Take(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	switch runtime.GOOS {
	case "linux":
		var err error
		snap, err = ReadProc("/proc")
		if err != nil {
			return Snapshot{}, err
		}
		s.annotateLinux(ctx, &snap)
	case "darwin":
		var err error
		snap, err = takeDarwin(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		s.annotateDarwin(ctx, &snap)
	default:
		return Snapshot{}, fmt.Errorf("unsupported operating system %s", runtime.GOOS)
	}
	s.fillHints(ctx, &snap)
	return snap, nil
}

func (s *liveSource) annotateLinux(ctx context.Context, snap *Snapshot) {
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		up, known := ParseProcNetRoute(string(data))
		snap.Host.NetworkKnown = known
		snap.Host.NetworkUp = up
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		level, known := ParseMeminfo(string(data))
		snap.Host.MemoryPressureKnown = known
		snap.Host.MemoryPressure = level
	}
	if out, ok := commandOutput(ctx, hostReadTimeout, "df", "-P", "/"); ok {
		pct, known := ParseDF(out)
		snap.Host.DiskKnown = known
		snap.Host.DiskFreePercent = pct
	}
	cur, err := readLinuxTicks("/proc", snap.Processes)
	if err != nil {
		return
	}
	s.mu.Lock()
	prev := s.prev
	s.prev = cur
	s.mu.Unlock()
	snap.Processes = ApplyCPU(prev, cur, snap.Processes)
}

func (s *liveSource) annotateDarwin(ctx context.Context, snap *Snapshot) {
	ncpu := runtime.NumCPU()
	for i := range snap.Processes {
		if snap.Processes[i].CPUKnown {
			snap.Processes[i].CPUPercent = ScaleMachineCPU(snap.Processes[i].CPUPercent, ncpu)
		}
	}
	if out, ok := commandOutput(ctx, hostReadTimeout, "route", "-n", "get", "default"); ok {
		if out == "" {
			snap.Host.NetworkKnown = true
			snap.Host.NetworkUp = false
		} else {
			up, known := ParseRouteGet(out)
			snap.Host.NetworkKnown = known
			snap.Host.NetworkUp = up
		}
	}
	if out, ok := commandOutput(ctx, hostReadTimeout, "df", "-P", "/"); ok {
		pct, known := ParseDF(out)
		snap.Host.DiskKnown = known
		snap.Host.DiskFreePercent = pct
	}
	if out, ok := commandOutput(ctx, hostReadTimeout, "sysctl", "-n", "kern.memorystatus_vm_pressure_level"); ok {
		if level, known := ParseVMPressure(out); known {
			snap.Host.MemoryPressureKnown = true
			snap.Host.MemoryPressure = level
		}
	}
	if !snap.Host.MemoryPressureKnown {
		if out, ok := commandOutput(ctx, hostReadTimeout, "memory_pressure"); ok {
			if level, known := ParseMemoryPressureText(out); known {
				snap.Host.MemoryPressureKnown = true
				snap.Host.MemoryPressure = level
			}
		}
	}
	if out, ok := commandOutput(ctx, hostReadTimeout, "pmset", "-g", "log"); ok {
		asleep, known := ParsePMSetLog(out)
		snap.Host.SleepKnown = known
		snap.Host.Asleep = asleep
	}
}

func readLinuxTicks(root string, procs []Process) (TickSample, error) {
	data, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return TickSample{}, err
	}
	total, ok := ParseProcStatTotal(string(data))
	if !ok {
		return TickSample{}, fmt.Errorf("unrecognized %s", filepath.Join(root, "stat"))
	}
	sample := TickSample{Total: total, Proc: map[int]uint64{}}
	for _, proc := range procs {
		raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(proc.PID), "stat"))
		if err != nil {
			continue
		}
		ticks, ok := ParsePIDStatTicks(string(raw))
		if !ok {
			continue
		}
		sample.Proc[proc.PID] = ticks
	}
	return sample, nil
}

// commandOutput runs a short read-only command. ran is false when the program
// cannot be started. A non-zero exit still returns whatever the program wrote.
func commandOutput(ctx context.Context, timeout time.Duration, name string, args ...string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), true
		}
		return "", false
	}
	return string(out), true
}

func takeDarwin(ctx context.Context) (Snapshot, error) {
	psOut, err := exec.CommandContext(ctx, "ps", "-ax", "-o", "pid=", "-o", "ppid=", "-o", "%cpu=", "-o", "rss=", "-o", "command=").Output()
	if err != nil {
		return Snapshot{}, fmt.Errorf("ps: %w", err)
	}
	procs, err := ParsePSResource(string(psOut))
	if err != nil {
		return Snapshot{}, err
	}
	procs = attachExePaths(ctx, procs)
	lsofCmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn")
	lsofOut, err := lsofCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			lsofOut = nil
		} else {
			return Snapshot{}, fmt.Errorf("lsof: %w", err)
		}
	}
	return Snapshot{Processes: procs, OutboundPorts: ParseLsofF(string(lsofOut))}, nil
}

// attachExePaths fills Exe from `ps -o comm=`. The path is its own column,
// so an application path that contains spaces is not split out of the arguments.
func attachExePaths(ctx context.Context, procs []Process) []Process {
	out, err := exec.CommandContext(ctx, "ps", "-ax", "-o", "pid=", "-o", "comm=").Output()
	if err != nil {
		return procs
	}
	paths, err := ParsePSPaths(string(out))
	if err != nil {
		return procs
	}
	return ApplyExePaths(procs, paths)
}

func (s *liveSource) fillHints(ctx context.Context, snap *Snapshot) {
	s.mu.Lock()
	hints := s.hints
	s.mu.Unlock()
	if len(hints.Files) > 0 {
		snap.Files = statFiles(hints.Files)
	}
	if runtime.GOOS == "darwin" && len(hints.Labels) > 0 {
		snap.Launchd = readLaunchdJobs(ctx, hints.Labels)
	}
}

func statFiles(paths []string) map[string]FileStamp {
	out := make(map[string]FileStamp, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				out[path] = FileStamp{Known: true, Missing: true}
			}
			continue
		}
		out[path] = FileStamp{Known: true, ModTime: info.ModTime()}
	}
	return out
}

// GUIServiceTarget is the launchctl service name for label in this user's
// gui domain. The uid is read at runtime. label is one argument and may
// contain spaces; the caller does not pass it through a shell.
func GUIServiceTarget(label string) string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), label)
}

func readLaunchdJobs(ctx context.Context, labels []string) map[string]LaunchdJob {
	out := make(map[string]LaunchdJob, len(labels))
	for _, label := range labels {
		text, ok := commandOutput(ctx, hostReadTimeout, "launchctl", "print", GUIServiceTarget(label))
		if !ok {
			continue
		}
		job, found := ParseLaunchctlPrint(text)
		if !found {
			continue
		}
		out[label] = stampStdout(job)
	}
	return out
}

func stampStdout(job LaunchdJob) LaunchdJob {
	if job.StdoutPath == "" {
		return job
	}
	info, err := os.Stat(job.StdoutPath)
	if err != nil {
		if os.IsNotExist(err) {
			job.StdoutKnown = true
			job.StdoutMissing = true
		}
		return job
	}
	job.StdoutKnown = true
	job.StdoutMod = info.ModTime()
	return job
}

package sysprobe

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestTopCPUAndMemoryBreakTiesByPID(t *testing.T) {
	snap := Snapshot{Processes: []Process{
		{PID: 5, Name: "later", CPUKnown: true, CPUPercent: 90, MemoryKnown: true, MemoryBytes: 100},
		{PID: 3, Name: "earlier", CPUKnown: true, CPUPercent: 90, MemoryKnown: true, MemoryBytes: 100},
		{PID: 4, Name: "unknown"},
		{PID: 2, Name: "lower", CPUKnown: true, CPUPercent: 10, MemoryKnown: true, MemoryBytes: 50},
	}}
	cpu, ok := TopCPU(snap)
	if !ok || cpu.PID != 3 {
		t.Fatalf("cpu %+v ok %v", cpu, ok)
	}
	mem, ok := TopMemory(snap)
	if !ok || mem.PID != 3 {
		t.Fatalf("memory %+v ok %v", mem, ok)
	}
	if _, ok := TopCPU(Snapshot{}); ok {
		t.Fatal("expected no cpu culprit")
	}
}

func TestCPUShareAndApplyCPU(t *testing.T) {
	if _, ok := CPUShare(10, 0); ok {
		t.Fatal("zero total should be unknown")
	}
	pct, ok := CPUShare(250, 1000)
	if !ok || pct != 25 {
		t.Fatalf("share %v %v", pct, ok)
	}
	capped, ok := CPUShare(5000, 1000)
	if !ok || capped != 100 {
		t.Fatalf("capped %v", capped)
	}
	procs := []Process{{PID: 7, Name: "example-tool"}, {PID: 8, Name: "other"}}
	first := ApplyCPU(TickSample{}, TickSample{Total: 1000, Proc: map[int]uint64{7: 10, 8: 10}}, procs)
	for _, proc := range first {
		if proc.CPUKnown {
			t.Fatalf("first sample should have no percentage: %+v", proc)
		}
	}
	second := ApplyCPU(
		TickSample{Total: 1000, Proc: map[int]uint64{7: 10, 8: 10}},
		TickSample{Total: 2000, Proc: map[int]uint64{7: 910, 8: 20}},
		procs,
	)
	if !second[0].CPUKnown || second[0].CPUPercent != 90 {
		t.Fatalf("pid 7: %+v", second[0])
	}
	if !second[1].CPUKnown || second[1].CPUPercent != 1 {
		t.Fatalf("pid 8: %+v", second[1])
	}
	if got := ScaleMachineCPU(170, 2); got != 85 {
		t.Fatalf("scaled %v", got)
	}
	if got := ScaleMachineCPU(400, 2); got != 100 {
		t.Fatalf("scaled cap %v", got)
	}
}

func TestParseProcStatAndPIDTicks(t *testing.T) {
	total, ok := ParseProcStatTotal("cpu  100 0 0 900 0 0 0 0\ncpu0 50 0 0 450 0 0 0 0\n")
	if !ok || total != 1000 {
		t.Fatalf("total %d ok %v", total, ok)
	}
	ticks, ok := ParsePIDStatTicks("7 (example tool) S 1 0 0 0 0 0 0 0 0 0 10 5 0 0\n")
	if !ok || ticks != 15 {
		t.Fatalf("ticks %d ok %v", ticks, ok)
	}
	pages, ok := parseStatmResident("6 3 1 2 0 0\n")
	if !ok || pages != 3 {
		t.Fatalf("pages %d", pages)
	}
}

func TestParseProcNetRouteIgnoresGateway(t *testing.T) {
	text := "" +
		"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0101A8C0 0003 0 0 0 00000000 0 0 0\n" +
		"eth0 0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
	up, known := ParseProcNetRoute(text)
	if !up || !known {
		t.Fatalf("up %v known %v", up, known)
	}
	up, known = ParseProcNetRoute("Iface Destination Gateway Flags\neth0 0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n")
	if up || !known {
		t.Fatalf("no default: up %v known %v", up, known)
	}
	_, known = ParseProcNetRoute("")
	if known {
		t.Fatal("empty route text should be unknown")
	}
}

func TestParseMeminfoBands(t *testing.T) {
	level, known := ParseMeminfo("MemTotal: 1000 kB\nMemAvailable: 200 kB\n")
	if !known || level != "normal" {
		t.Fatalf("20%%: %s %v", level, known)
	}
	level, known = ParseMeminfo("MemTotal: 1000 kB\nMemAvailable: 100 kB\n")
	if !known || level != "warn" {
		t.Fatalf("10%%: %s %v", level, known)
	}
	level, known = ParseMeminfo("MemTotal: 1000 kB\nMemAvailable: 99 kB\n")
	if !known || level != "critical" {
		t.Fatalf("9.9%%: %s %v", level, known)
	}
	if _, known := ParseMeminfo("MemTotal: 1000 kB\n"); known {
		t.Fatal("missing available should be unknown")
	}
}

func TestParseDF(t *testing.T) {
	text := "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk1 1000 800 200 80% /\n"
	pct, known := ParseDF(text)
	if !known || pct != 20 {
		t.Fatalf("pct %v known %v", pct, known)
	}
	pct, known = ParseDF("Filesystem 1024-blocks Used Available Capacity Mounted on\nmy disk 1000 800 50 95% /\n")
	if !known || pct != 5 {
		t.Fatalf("spaced name pct %v", pct)
	}
	if _, known := ParseDF("Filesystem 1024-blocks\n"); known {
		t.Fatal("header only should be unknown")
	}
}

func TestParsePMSetLogLastEventWins(t *testing.T) {
	log := "" +
		"2026-01-02 03:04:05 +0000 Sleep Entering Sleep state\n" +
		"2026-01-02 03:10:00 +0000 Wake Wake from Sleep\n" +
		"2026-01-02 03:11:00 +0000 DarkWake DarkWake from idle\n"
	asleep, known := ParsePMSetLog(log)
	if !known || asleep {
		t.Fatalf("last darkwake: asleep %v known %v", asleep, known)
	}
	asleep, known = ParsePMSetLog("2026-01-02 03:04:05 +0000 Wake from Sleep\n")
	if !known || asleep {
		t.Fatal("Wake from Sleep is awake")
	}
	asleep, known = ParsePMSetLog("2026-01-02 03:04:05 +0000 Sleep Entering Sleep state\n")
	if !known || !asleep {
		t.Fatal("expected asleep")
	}
	if _, known := ParsePMSetLog("no power events\n"); known {
		t.Fatal("expected unknown")
	}
}

func TestParseRouteAndPressure(t *testing.T) {
	up, known := ParseRouteGet("   route to: default\ninterface: en0\ngateway: gateway\n")
	if !up || !known {
		t.Fatalf("route up %v known %v", up, known)
	}
	up, known = ParseRouteGet("route: not found\n")
	if up || !known {
		t.Fatalf("route down %v known %v", up, known)
	}
	if _, known := ParseRouteGet("  \n"); known {
		t.Fatal("blank route should be unknown")
	}
	level, known := ParseVMPressure("4\n")
	if !known || level != "critical" {
		t.Fatalf("vm %s", level)
	}
	level, known = ParseMemoryPressureText("System-wide memory free percentage: 15%\n")
	if !known || level != "warn" {
		t.Fatalf("free text %s %v", level, known)
	}
}

func TestParsePSResource(t *testing.T) {
	procs, err := ParsePSResource(" 4  1  170.0  2048 example-tool --flag\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 1 || procs[0].Cmd != "example-tool --flag" || procs[0].Exe != "" || procs[0].CPUPercent != 170 || procs[0].MemoryBytes != 2048*1024 {
		t.Fatalf("%+v", procs)
	}
}

func TestAppPathWithSpaces(t *testing.T) {
	const cmd = "  42  1  2.5  4096 /Applications/Some App.app/Contents/MacOS/Some App --disable-renderer-backgrounding\n"
	procs, err := ParsePSResource(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 1 {
		t.Fatalf("%+v", procs)
	}
	if procs[0].Exe != "" || procs[0].Name != "" {
		t.Fatalf("command line was split into an executable: %+v", procs[0])
	}
	if !strings.Contains(procs[0].Cmd, "/Applications/Some App.app/Contents/MacOS/Some App") || !strings.Contains(procs[0].Cmd, "--disable-renderer-backgrounding") {
		t.Fatalf("command %q", procs[0].Cmd)
	}
	paths, err := ParsePSPaths("42 /Applications/Some App.app/Contents/MacOS/Some App\n 7 /usr/local/bin/example-tool\n")
	if err != nil {
		t.Fatal(err)
	}
	procs = ApplyExePaths(procs, paths)
	const want = "/Applications/Some App.app/Contents/MacOS/Some App"
	if procs[0].Exe != want || procs[0].Name != "Some App" {
		t.Fatalf("exe %q name %q", procs[0].Exe, procs[0].Name)
	}
	if strings.HasPrefix(procs[0].Exe, "/Applications/Some ") && !strings.Contains(procs[0].Exe, "App.app") {
		t.Fatal("path was truncated at the first space")
	}
}

func TestParseLaunchctlPrint(t *testing.T) {
	text := `
gui/501/com.example.health = {
	state = not running
	last exit code = 0
	last exit time = 1700000000
}
`
	job, ok := ParseLaunchctlPrint(text)
	if !ok || !job.ExitKnown || job.ExitCode != 0 || !job.LastRunKnown || job.LastRun.Unix() != 1700000000 {
		t.Fatalf("%+v ok %v", job, ok)
	}
	bad, ok := ParseLaunchctlPrint("last exit code = 2\nlast exit time = 2026-01-02 12:00:00 +0000\n")
	if !ok || bad.ExitCode != 2 || bad.LastRun.UTC().Format("15:04") != "12:00" {
		t.Fatalf("%+v", bad)
	}
	if _, ok := ParseLaunchctlPrint("last exit code = (never exited)\n"); ok {
		t.Fatal("a job that has never exited should be unknown")
	}
}

func TestReadProcResidentMemory(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 10, 1, "example-tool", "example-tool", "")
	if err := os.WriteFile(root+"/10/statm", []byte("6 4 1 2 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/net", 0o755); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := os.WriteFile(root+"/net/tcp", []byte(header), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := ReadProc(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) != 1 || !snap.Processes[0].MemoryKnown {
		t.Fatalf("%+v", snap.Processes)
	}
	want := 4 * int64(os.Getpagesize())
	if snap.Processes[0].MemoryBytes != want {
		t.Fatalf("bytes %d want %d", snap.Processes[0].MemoryBytes, want)
	}
	if snap.Processes[0].Name != "example-tool" || strconv.Itoa(snap.Processes[0].PID) != "10" {
		t.Fatalf("%+v", snap.Processes[0])
	}
}

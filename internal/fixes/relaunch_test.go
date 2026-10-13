package fixes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type relaunchCtrl struct {
	fakeCtrl
	apps   []string
	quit   func(context.Context) error
	signal func(int) error
	launch func() error
}

func (c *relaunchCtrl) Quit(ctx context.Context, app string) error {
	c.apps = append(c.apps, app)
	if c.quit != nil {
		return c.quit(ctx)
	}
	return nil
}

func (c *relaunchCtrl) Signal(pid int, sig syscall.Signal) error {
	_ = c.fakeCtrl.Signal(pid, sig)
	if c.signal != nil {
		return c.signal(pid)
	}
	return nil
}

func (c *relaunchCtrl) Launch(ctx context.Context, path string, args []string) error {
	_ = c.fakeCtrl.Launch(ctx, path, args)
	if c.launch != nil {
		return c.launch()
	}
	return nil
}

func relaunchPlugin() plugins.Plugin {
	p := plugin("")
	p.Checks = []plugins.Check{{Type: plugins.CheckProcessRunning}, {Type: plugins.CheckLaunchedWithFlags, Flags: []string{"--required"}}}
	p.Fixes[plugins.FixRelaunch] = plugins.Fix{Kind: plugins.FixRelaunch, App: "Example App", Launcher: "/opt/example-launch", Args: []string{"--fixed", "a value"}, QuitTimeout: "20ms"}
	return p
}

func flaggedTree(healthy bool) sysprobe.Snapshot {
	snap := tree()
	for i := range snap.Processes {
		snap.Processes[i].StartTime = uint64(1000 + i)
	}
	snap.Processes[0].Cmd = "example-desktop-app"
	if healthy {
		snap.Processes[0].Cmd += " --required"
	}
	return snap
}

func relaunchRunner(src sysprobe.Source, ctrl Controller) *Runner {
	return &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
}

func TestRelaunchGracefulQuitLaunchAndFullRecheck(t *testing.T) {
	src := &sysprobe.MemSource{}
	src.Set(flaggedTree(false))
	ctrl := &relaunchCtrl{}
	ctrl.quit = func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("quit has no deadline")
		}
		src.Set(sysprobe.Snapshot{})
		return nil
	}
	ctrl.launch = func() error { src.Set(flaggedTree(true)); return nil }
	p := relaunchPlugin()
	// The final recheck includes checks beyond the startup flags.
	p.Checks = append(p.Checks, plugins.Check{Type: plugins.CheckOutboundTCP, Port: 443, Consecutive: 1})
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), p, plugins.FixRelaunch, false)
	if err != nil || res.Fixed || len(res.Outcomes) != 3 || !res.Outcomes[1].Healthy || !res.Outcomes[2].Stuck {
		t.Fatalf("full recheck: %+v %v", res, err)
	}
	if !reflect.DeepEqual(ctrl.apps, []string{"Example App"}) || len(ctrl.pids) != 0 || len(ctrl.launches) != 1 {
		t.Fatalf("controller: %+v", ctrl)
	}
	if ctrl.launches[0].Path != p.Fixes[plugins.FixRelaunch].Launcher || !reflect.DeepEqual(ctrl.launches[0].Args, []string{"--fixed", "a value"}) {
		t.Fatalf("launcher: %+v", ctrl.launches)
	}
}

func TestRelaunchWaitsForGracefulExitAndAppStartup(t *testing.T) {
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{flaggedTree(false), flaggedTree(false), {}, {}, flaggedTree(true), flaggedTree(true)}}
	p := relaunchPlugin()
	fix := p.Fixes[plugins.FixRelaunch]
	fix.QuitTimeout = "1s"
	p.Fixes[plugins.FixRelaunch] = fix
	ctrl := &relaunchCtrl{}
	ctrl.launch = func() error {
		if src.Takes != 3 {
			t.Fatalf("launched before old app exited: %d samples", src.Takes)
		}
		return nil
	}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), p, plugins.FixRelaunch, false)
	if err != nil || !res.Fixed || len(ctrl.pids) != 0 || src.Takes != 6 {
		t.Fatalf("startup: %+v %v %+v samples=%d", res, err, ctrl, src.Takes)
	}
}

func TestRelaunchKillFallbackUsesSelectorAndChildrenFirst(t *testing.T) {
	src := &sysprobe.MemSource{}
	p := relaunchPlugin()
	p.Process = plugins.ProcessMatch{Match: "node", CmdContains: "app.js", CmdRegex: `^node `}
	snap := flaggedTree(false)
	snap.Processes[0].Name, snap.Processes[0].Exe, snap.Processes[0].Cmd = "node", "node", "node app.js"
	unrelated := sysprobe.Process{PID: 8, PPID: 1, Name: "node", Exe: "node", Cmd: "node other.js"}
	snap.Processes = append(snap.Processes, unrelated)
	src.Set(snap)
	ctrl := &relaunchCtrl{}
	var deadline time.Time
	ctrl.quit = func(ctx context.Context) error {
		deadline, _ = ctx.Deadline()
		return errors.New("quit request refused")
	}
	ctrl.signal = func(pid int) error {
		if time.Now().Before(deadline) {
			t.Fatal("KILL sent before grace timeout")
		}
		if pid == 4 {
			src.Set(sysprobe.Snapshot{Processes: []sysprobe.Process{unrelated}})
		}
		return nil
	}
	ctrl.launch = func() error {
		snap.Processes[0].Cmd = "node app.js --required"
		src.Set(snap)
		return nil
	}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), p, plugins.FixRelaunch, false)
	if err != nil || !res.Fixed || res.QuitError == "" || res.Signal != "KILL" {
		t.Fatalf("fallback: %+v %v", res, err)
	}
	if !reflect.DeepEqual(ctrl.pids, []int{6, 4}) || !reflect.DeepEqual(ctrl.sigs, []syscall.Signal{syscall.SIGKILL, syscall.SIGKILL}) || len(ctrl.launches) != 1 {
		t.Fatalf("unsafe fallback: %+v", ctrl)
	}
}

func TestRelaunchWaitsForOrphanedChildren(t *testing.T) {
	src := &sysprobe.MemSource{}
	snap := flaggedTree(false)
	src.Set(snap)
	ctrl := &relaunchCtrl{quit: func(context.Context) error {
		src.Set(sysprobe.Snapshot{Processes: snap.Processes[1:]})
		return nil
	}}
	ctrl.signal = func(pid int) error { src.Set(sysprobe.Snapshot{}); return nil }
	ctrl.launch = func() error { src.Set(flaggedTree(true)); return nil }
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
	if err != nil || !res.Fixed || !reflect.DeepEqual(ctrl.pids, []int{6}) {
		t.Fatalf("orphaned helper: %+v %v %+v", res, err, ctrl)
	}
}

func TestRelaunchTracksChildrenCreatedDuringQuit(t *testing.T) {
	initial := flaggedTree(false)
	withChild := flaggedTree(false)
	child := sysprobe.Process{PID: 7, PPID: 4, Name: "new-helper", Exe: "new-helper", StartTime: 2000}
	withChild.Processes = append(withChild.Processes, child)
	child.PPID = 1
	orphan := sysprobe.Snapshot{Processes: []sysprobe.Process{child}}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{initial, withChild, orphan, orphan, {}, flaggedTree(true), flaggedTree(true)}}
	ctrl := &relaunchCtrl{}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
	if err != nil || !res.Fixed || !reflect.DeepEqual(ctrl.pids, []int{7}) {
		t.Fatalf("new helper was missed: %+v %v %+v", res, err, ctrl)
	}
}

type cancelRelaunchRecheck struct {
	*sysprobe.MemSource
	cancel context.CancelFunc
}

func (s cancelRelaunchRecheck) Take(ctx context.Context) (sysprobe.Snapshot, error) {
	snap, err := s.MemSource.Take(ctx)
	if s.Takes == 4 {
		s.cancel()
	}
	return snap, err
}

func TestRelaunchDoesNotReportFixedIfFinalSampleIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mem := &sysprobe.MemSource{}
	mem.Set(flaggedTree(false))
	src := cancelRelaunchRecheck{MemSource: mem, cancel: cancel}
	ctrl := &relaunchCtrl{
		quit:   func(context.Context) error { mem.Set(sysprobe.Snapshot{}); return nil },
		launch: func() error { mem.Set(flaggedTree(true)); return nil },
	}
	res, err := relaunchRunner(src, ctrl).Apply(ctx, relaunchPlugin(), plugins.FixRelaunch, false)
	if !errors.Is(err, context.Canceled) || res.Fixed || len(ctrl.launches) != 1 {
		t.Fatalf("cancelled recheck: %+v %v", res, err)
	}
}

func TestRelaunchDoesNotKillReplacementProcess(t *testing.T) {
	src := &sysprobe.MemSource{}
	src.Set(flaggedTree(false))
	ctrl := &relaunchCtrl{quit: func(context.Context) error {
		replacement := flaggedTree(false)
		replacement.Processes[0].Cmd += " --other"
		replacement.Processes[0].StartTime++
		src.Set(replacement)
		return nil
	}}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
	if err == nil || res.Fixed || len(ctrl.pids) != 0 || len(ctrl.launches) != 0 {
		t.Fatalf("replacement process touched: %+v %v %+v", res, err, ctrl)
	}
}

func TestRelaunchRefusesReusedPIDWithIdenticalCommand(t *testing.T) {
	for _, scenario := range []string{"app", "child", "unavailable-start", "start-lost"} {
		t.Run(scenario, func(t *testing.T) {
			initial := flaggedTree(false)
			if scenario == "unavailable-start" {
				initial.Processes[0].StartTime = 0
			}
			src := &sysprobe.MemSource{}
			src.Set(initial)
			ctrl := &relaunchCtrl{quit: func(context.Context) error {
				replacement := flaggedTree(false)
				switch scenario {
				case "app":
					replacement.Processes[0].StartTime++
				case "child":
					replacement.Processes[1].StartTime++
				case "start-lost":
					replacement.Processes[0].StartTime = 0
				}
				// PID, PPID, Name, Exe and Cmd all remain unchanged.
				src.Set(replacement)
				return nil
			}}
			res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
			if err == nil || res.Fixed || len(ctrl.pids) != 0 || len(ctrl.launches) != 0 {
				t.Fatalf("reused or unverified PID touched: %+v %v %+v", res, err, ctrl)
			}
		})
	}
}

func TestRelaunchChecksLifetimeAgainBeforeEachKill(t *testing.T) {
	src := &sysprobe.MemSource{}
	src.Set(flaggedTree(false))
	ctrl := &relaunchCtrl{signal: func(pid int) error {
		if pid != 6 {
			t.Fatalf("unexpected signal to pid %d", pid)
		}
		// The app PID is reused while its child is being stopped.
		replacement := flaggedTree(false)
		replacement.Processes = replacement.Processes[:1]
		replacement.Processes[0].StartTime++
		src.Set(replacement)
		return nil
	}}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
	if err == nil || res.Fixed || !reflect.DeepEqual(ctrl.pids, []int{6}) || len(ctrl.launches) != 0 {
		t.Fatalf("reused app PID killed: %+v %v %+v", res, err, ctrl)
	}
}

func TestSurvivingOriginalKeepsUnverifiedPIDPresent(t *testing.T) {
	initial := flaggedTree(false)
	original := processIdentities(initial, []int{4, 6})
	replacement := flaggedTree(false)
	replacement.Processes[0].StartTime++
	alive := survivingOriginal(replacement, original)
	if len(alive) != 1 || alive[6].StartTime != original[6].StartTime {
		t.Fatalf("PID reuse classified as survival: %+v", alive)
	}
	replacement.Processes[1].StartTime = 0
	if alive := survivingOriginal(replacement, original); len(alive) != 1 || alive[6].StartTime != 0 {
		t.Fatalf("unverified tracked PID treated as exited: %+v", alive)
	}
	original[6] = replacement.Processes[1]
	replacement.Processes[1].StartTime = 1001
	if alive := survivingOriginal(replacement, original); len(alive) != 1 || alive[6].StartTime != 1001 {
		t.Fatalf("unknown original lifetime treated as exited: %+v", alive)
	}
}

func TestSurvivingOriginalRecognizesExecAsSameLifetime(t *testing.T) {
	initial := flaggedTree(false)
	original := processIdentities(initial, []int{4, 6})
	execed := flaggedTree(false)
	for i := range execed.Processes {
		execed.Processes[i].Name = "worker"
		execed.Processes[i].Exe = "/opt/worker"
		execed.Processes[i].Cmd = "worker --different-args"
	}
	if alive := survivingOriginal(execed, original); len(alive) != 2 {
		t.Fatalf("exec treated as process exit: %+v", alive)
	}
	// The start time alone is not enough: the PID must also match.
	otherPID := execed.Processes[0]
	otherPID.PID++
	if sameProcess(initial.Processes[0], otherPID) {
		t.Fatal("different PID treated as the same lifetime")
	}
}

func TestRelaunchWaitsForTrackedLifetimeAfterExec(t *testing.T) {
	for _, pid := range []int{4, 6} {
		t.Run(fmt.Sprintf("pid-%d", pid), func(t *testing.T) {
			src := &sysprobe.MemSource{}
			src.Set(flaggedTree(false))
			ctrl := &relaunchCtrl{}
			var deadline time.Time
			ctrl.quit = func(ctx context.Context) error {
				deadline, _ = ctx.Deadline()
				for _, proc := range flaggedTree(false).Processes {
					if proc.PID == pid {
						// This tracked process execs and, for the child case,
						// outlives its parent. Its PID and start time stay fixed.
						proc.PPID = 1
						proc.Name, proc.Exe, proc.Cmd = "worker", "/opt/worker", "worker --different-args"
						src.Set(sysprobe.Snapshot{Processes: []sysprobe.Process{proc}})
					}
				}
				return nil
			}
			ctrl.signal = func(target int) error {
				if target != pid || time.Now().Before(deadline) {
					t.Fatalf("incorrect KILL target or grace wait: %d", target)
				}
				src.Set(sysprobe.Snapshot{})
				return nil
			}
			ctrl.launch = func() error {
				if !reflect.DeepEqual(ctrl.pids, []int{pid}) {
					return errors.New("launched while tracked lifetime was still present")
				}
				src.Set(flaggedTree(true))
				return nil
			}
			res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
			if err != nil || !res.Fixed || !reflect.DeepEqual(ctrl.pids, []int{pid}) || len(ctrl.launches) != 1 {
				t.Fatalf("exec lifetime not stopped before launch: %+v %v %+v", res, err, ctrl)
			}
		})
	}
}

func TestRelaunchWaitsThenAbortsForUnverifiedTrackedPID(t *testing.T) {
	for _, scenario := range []string{"child-start-lost", "child-start-never-known", "app-start-lost-unmatched"} {
		t.Run(scenario, func(t *testing.T) {
			initial := flaggedTree(false)
			if scenario == "child-start-never-known" {
				initial.Processes[1].StartTime = 0
			}
			src := &sysprobe.MemSource{}
			src.Set(initial)
			var deadline time.Time
			ctrl := &relaunchCtrl{launch: func() error { return errors.New("unexpected launcher") }}
			ctrl.quit = func(ctx context.Context) error {
				deadline, _ = ctx.Deadline()
				remaining := flaggedTree(false)
				if scenario == "app-start-lost-unmatched" {
					remaining.Processes = remaining.Processes[:1]
					remaining.Processes[0].Name, remaining.Processes[0].Exe, remaining.Processes[0].Cmd = "unknown", "", ""
					remaining.Processes[0].StartTime = 0
				} else {
					// The app exited, but its tracked child is still present.
					remaining.Processes = remaining.Processes[1:]
					remaining.Processes[0].PPID = 1
					if scenario == "child-start-lost" {
						remaining.Processes[0].StartTime = 0
					}
				}
				src.Set(remaining)
				return nil
			}
			res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
			if err == nil || !strings.Contains(err.Error(), "cannot verify original lifetime") || res.Fixed {
				t.Fatalf("unverified PID did not abort: %+v %v", res, err)
			}
			if time.Now().Before(deadline) {
				t.Fatal("unverified PID did not keep the exit wait active")
			}
			if len(ctrl.pids) != 0 || len(ctrl.launches) != 0 {
				t.Fatalf("unverified PID killed or launcher run: %+v", ctrl)
			}
		})
	}
}

func TestRelaunchDryRunDoesNotQuitKillOrLaunch(t *testing.T) {
	src := &sysprobe.MemSource{}
	src.Set(flaggedTree(false))
	ctrl := &relaunchCtrl{}
	res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, true)
	if err != nil || res.Fixed || res.WouldLaunch != "/opt/example-launch" || !strings.Contains(res.Detail, "dry-run") || src.Takes != 2 {
		t.Fatalf("dry-run: %+v %v", res, err)
	}
	if len(ctrl.apps)+len(ctrl.pids)+len(ctrl.launches) != 0 {
		t.Fatalf("dry-run performed work: %+v", ctrl)
	}
}

func TestRelaunchPreconditionsRefuseWithoutSideEffects(t *testing.T) {
	for _, scenario := range []string{"unapproved", "healthy", "absent", "protected", "invalid-launcher", "no-quitter"} {
		t.Run(scenario, func(t *testing.T) {
			p := relaunchPlugin()
			snap := flaggedTree(false)
			ctrl := &relaunchCtrl{}
			var control Controller = ctrl
			switch scenario {
			case "unapproved":
				delete(p.Fixes, plugins.FixRelaunch)
			case "healthy":
				snap = flaggedTree(true)
			case "absent":
				snap = sysprobe.Snapshot{}
			case "protected":
				snap.Processes[0].PID = os.Getpid()
			case "invalid-launcher":
				fix := p.Fixes[plugins.FixRelaunch]
				fix.Launcher = "/bin/sh"
				p.Fixes[plugins.FixRelaunch] = fix
			case "no-quitter":
				control = &fakeCtrl{}
			}
			src := &sysprobe.MemSource{}
			src.Set(snap)
			if _, err := relaunchRunner(src, control).Apply(context.Background(), p, plugins.FixRelaunch, false); err == nil {
				t.Fatal("invalid relaunch accepted")
			}
			if len(ctrl.apps)+len(ctrl.pids)+len(ctrl.launches) != 0 {
				t.Fatalf("refusal performed work: %+v", ctrl)
			}
		})
	}
}

func TestRelaunchCancellationStopsEveryPhase(t *testing.T) {
	for _, phase := range []string{"before", "quit", "exit-wait", "kill", "startup"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			src := &sysprobe.MemSource{}
			src.Set(flaggedTree(false))
			ctrl := &relaunchCtrl{}
			switch phase {
			case "before":
				cancel()
			case "quit":
				ctrl.quit = func(ctx context.Context) error { cancel(); <-ctx.Done(); return ctx.Err() }
			case "exit-wait":
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer deadlineCancel()
			case "kill":
				ctrl.signal = func(int) error { cancel(); return nil }
			case "startup":
				ctrl.quit = func(context.Context) error { src.Set(sysprobe.Snapshot{}); return nil }
				ctrl.launch = func() error { cancel(); return nil }
			}
			start := time.Now()
			res, err := relaunchRunner(src, ctrl).Apply(ctx, relaunchPlugin(), plugins.FixRelaunch, false)
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation: %+v %v", res, err)
			}
			if res.Fixed || time.Since(start) > time.Second {
				t.Fatalf("cancellation hung: %+v", res)
			}
			if phase != "startup" && len(ctrl.launches) != 0 {
				t.Fatal("launched after cancellation")
			}
			if phase == "kill" && len(ctrl.pids) != 1 {
				t.Fatal("continued KILL after cancellation")
			}
			if phase == "exit-wait" && len(ctrl.pids) != 0 {
				t.Fatal("parent timeout triggered KILL")
			}
		})
	}
}

func TestRelaunchKillAndLauncherFailuresDoNotReportFixed(t *testing.T) {
	for _, scenario := range []string{"kill-error", "still-running", "launch-error", "wrong-flags"} {
		t.Run(scenario, func(t *testing.T) {
			src := &sysprobe.MemSource{}
			src.Set(flaggedTree(false))
			ctrl := &relaunchCtrl{}
			switch scenario {
			case "kill-error":
				ctrl.signal = func(int) error { return errors.New("signal refused") }
			case "still-running":
			case "launch-error", "wrong-flags":
				ctrl.quit = func(context.Context) error { src.Set(sysprobe.Snapshot{}); return nil }
				ctrl.launch = func() error {
					if scenario == "launch-error" {
						return errors.New("launcher refused")
					}
					src.Set(flaggedTree(false))
					return nil
				}
			}
			res, err := relaunchRunner(src, ctrl).Apply(context.Background(), relaunchPlugin(), plugins.FixRelaunch, false)
			if res.Fixed || !strings.HasPrefix(res.Message, "Didn't work.") || len(res.Outcomes) == 0 {
				t.Fatalf("failed fix: %+v %v", res, err)
			}
			if scenario != "wrong-flags" && err == nil {
				t.Fatal("execution error was hidden")
			}
			if (scenario == "kill-error" || scenario == "still-running") && len(ctrl.launches) != 0 {
				t.Fatal("launched while old app remained")
			}
		})
	}
}

func TestAppQuitCommandTreatsNameAsDataAndHonorsCancellation(t *testing.T) {
	app := `Example "quoted" App; do shell script "ignored"`
	cmd := quitCommand(context.Background(), app)
	if len(cmd.Args) != 4 || cmd.Args[0] != "/usr/bin/osascript" || cmd.Args[2] != quitAppScript || cmd.Args[3] != app || strings.Contains(cmd.Args[2], app) {
		t.Fatalf("unsafe quit command: %q", cmd.Args)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (OSController{}).Quit(ctx, "Example App"); !errors.Is(err, context.Canceled) {
		t.Fatalf("quit ignored cancellation: %v", err)
	}
}

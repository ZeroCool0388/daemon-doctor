package fixes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func plugin(launcher string) plugins.Plugin {
	fixes := map[string]plugins.Fix{
		plugins.FixRestart:      {Kind: plugins.FixRestart, Launcher: launcher},
		plugins.FixForceRestart: {Kind: plugins.FixForceRestart, Launcher: launcher},
	}
	return plugins.Plugin{
		ID:      "example-desktop-app",
		Name:    "Example Desktop App",
		Process: plugins.ProcessMatch{Match: "example-desktop-app"},
		Checks: []plugins.Check{
			{Type: plugins.CheckProcessRunning},
			{Type: plugins.CheckOutboundTCP, Port: 443, Consecutive: 1},
		},
		Fixes: fixes,
	}
}

func tree(ports ...int) sysprobe.Snapshot {
	s := sysprobe.Snapshot{
		Processes: []sysprobe.Process{
			{PID: 4, PPID: 1, Name: "example-desktop-app", Exe: "example-desktop-app"},
			{PID: 6, PPID: 4, Name: "helper", Exe: "helper"},
		},
		OutboundPorts: map[int][]int{},
	}
	if len(ports) > 0 {
		s.OutboundPorts[6] = append([]int(nil), ports...)
	}
	return s
}

type launchCall struct {
	Path string
	Args []string
}

type fakeCtrl struct {
	sigs     []syscall.Signal
	pids     []int
	launches []launchCall
}

func (f *fakeCtrl) Signal(pid int, sig syscall.Signal) error {
	f.pids = append(f.pids, pid)
	f.sigs = append(f.sigs, sig)
	return nil
}

func (f *fakeCtrl) Launch(_ context.Context, path string, args []string) error {
	f.launches = append(f.launches, launchCall{Path: path, Args: append([]string(nil), args...)})
	return nil
}

type recordingCtrl struct {
	fakeCtrl
}

func TestDryRunDoesNotSignalAndStillRechecks(t *testing.T) {
	ctrl := &recordingCtrl{}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(), tree()}}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err := runner.Apply(context.Background(), plugin(""), plugins.FixRestart, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.pids) != 0 || len(ctrl.launches) != 0 {
		t.Fatalf("dry-run called the controller: %+v", ctrl)
	}
	if src.Takes != 2 {
		t.Fatalf("takes = %d, want 2", src.Takes)
	}
	if res.Fixed {
		t.Fatal("recheck should still see the failure")
	}
	if !strings.Contains(res.Message, "Dry run") || !strings.Contains(res.Detail, "TERM") {
		t.Fatalf("result: %+v", res)
	}
}

func TestRestartAndForceRestartAreAllowlisted(t *testing.T) {
	launch := "/opt/example-desktop-app-launch"
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{
		tree(),
		tree(443),
	}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err := runner.Apply(context.Background(), plugin(launch), plugins.FixRestart, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Fixed {
		t.Fatalf("expected a healthy recheck: %+v", res)
	}
	if !strings.HasPrefix(res.Message, "Fixed.") {
		t.Fatalf("message: %q", res.Message)
	}
	if len(ctrl.pids) != 2 || ctrl.pids[0] != 6 || ctrl.pids[1] != 4 {
		t.Fatalf("signal order: %v", ctrl.pids)
	}
	if len(ctrl.sigs) != 2 || ctrl.sigs[0] != syscall.SIGTERM {
		t.Fatalf("signals: %v", ctrl.sigs)
	}
	if len(ctrl.launches) != 1 || ctrl.launches[0].Path != launch || len(ctrl.launches[0].Args) != 0 {
		t.Fatalf("launches: %+v", ctrl.launches)
	}

	src = &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(), tree()}}
	ctrl = &recordingCtrl{}
	runner = &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err = runner.Apply(context.Background(), plugin(""), plugins.FixForceRestart, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixed || !strings.HasPrefix(res.Message, "Didn't work.") {
		t.Fatalf("result: %+v", res)
	}
	if ctrl.sigs[0] != syscall.SIGKILL {
		t.Fatalf("signals: %v", ctrl.sigs)
	}
	if len(ctrl.launches) != 0 {
		t.Fatalf("launcher should be unset: %v", ctrl.launches)
	}
}

func TestStopDoesNotLaunch(t *testing.T) {
	launch := "/opt/example-desktop-app-launch"
	p := plugin(launch)
	p.Fixes[plugins.FixStop] = plugins.Fix{Kind: plugins.FixStop, Launcher: launch}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(), tree()}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err := runner.Apply(context.Background(), p, plugins.FixStop, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.launches) != 0 || res.Launched != "" {
		t.Fatalf("stop launched: %+v launches %v", res, ctrl.launches)
	}
	if len(ctrl.sigs) != 2 || ctrl.sigs[0] != syscall.SIGTERM {
		t.Fatalf("signals %v", ctrl.sigs)
	}
	if res.Fixed {
		t.Fatal("process is still in the recheck snapshot")
	}
}

func TestApplyStopMatchesTheExactName(t *testing.T) {
	snap := sysprobe.Snapshot{Processes: []sysprobe.Process{
		{PID: 4, PPID: 1, Name: "ExampleTool", Exe: "ExampleTool"},
		{PID: 8, PPID: 1, Name: "ExampleToolbox", Exe: "ExampleToolbox"},
	}}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{snap, sysprobe.Snapshot{}}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl}
	res, err := runner.ApplyStop(context.Background(), "ExampleTool", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.pids) != 1 || ctrl.pids[0] != 4 || len(ctrl.launches) != 0 {
		t.Fatalf("pids %v launches %v", ctrl.pids, ctrl.launches)
	}
	if !res.Fixed {
		t.Fatalf("recheck should see it gone: %+v", res)
	}
	if _, err := runner.ApplyStop(context.Background(), "ExampleTool; rm", false); err == nil {
		t.Fatal("metacharacters should be refused")
	}
	if len(ctrl.pids) != 1 {
		t.Fatalf("refused name still signalled: %v", ctrl.pids)
	}
}

func TestKickstartDoesNotSignal(t *testing.T) {
	p := plugin("")
	p.Fixes[plugins.FixKickstart] = plugins.Fix{Kind: plugins.FixKickstart, Label: "com.example.health"}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(443), tree(443)}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err := runner.Apply(context.Background(), p, plugins.FixKickstart, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.pids) != 0 || len(ctrl.sigs) != 0 {
		t.Fatalf("kickstart signalled: pids %v sigs %v", ctrl.pids, ctrl.sigs)
	}
	if len(ctrl.launches) != 1 || ctrl.launches[0].Path != "launchctl" {
		t.Fatalf("launch %+v", ctrl.launches)
	}
	want := []string{"kickstart", "-k", "gui/" + strconv.Itoa(os.Getuid()) + "/com.example.health"}
	if strings.Join(ctrl.launches[0].Args, " ") != strings.Join(want, " ") {
		t.Fatalf("args %v", ctrl.launches[0].Args)
	}
	if !res.Fixed || !strings.Contains(res.Detail, "launchctl kickstart -k") {
		t.Fatalf("%+v", res)
	}

	dry := &recordingCtrl{}
	runner.Control = dry
	res, err = runner.Apply(context.Background(), p, plugins.FixKickstart, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.pids) != 0 || len(dry.launches) != 0 || !strings.Contains(res.Detail, "dry-run") {
		t.Fatalf("dry %+v launches %+v", res, dry.launches)
	}
}

func TestKickstartLabelKeepsSpaces(t *testing.T) {
	p := plugin("")
	p.Fixes[plugins.FixKickstart] = plugins.Fix{Kind: plugins.FixKickstart, Label: "Example Health"}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(443), tree(443)}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	if _, err := runner.Apply(context.Background(), p, plugins.FixKickstart, false); err != nil {
		t.Fatal(err)
	}
	if len(ctrl.launches) != 1 {
		t.Fatalf("launches %+v", ctrl.launches)
	}
	args := ctrl.launches[0].Args
	want := sysprobe.GUIServiceTarget("Example Health")
	if len(args) != 3 || args[0] != "kickstart" || args[1] != "-k" || args[2] != want {
		t.Fatalf("args %q", args)
	}
}

func TestRestartPassesFixedArgs(t *testing.T) {
	p := plugin("/opt/example-launch")
	p.Fixes[plugins.FixRestart] = plugins.Fix{
		Kind:     plugins.FixRestart,
		Launcher: "/opt/example-launch",
		Args:     []string{"--config", "/opt/example.yaml"},
	}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{tree(), tree(443)}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	if _, err := runner.Apply(context.Background(), p, plugins.FixRestart, false); err != nil {
		t.Fatal(err)
	}
	if len(ctrl.pids) != 2 || ctrl.pids[0] != 6 || ctrl.pids[1] != 4 {
		t.Fatalf("children should be signalled first: %v", ctrl.pids)
	}
	if len(ctrl.launches) != 1 || strings.Join(ctrl.launches[0].Args, " ") != "--config /opt/example.yaml" {
		t.Fatalf("%+v", ctrl.launches)
	}
}

func TestUnknownFixIsNotExecuted(t *testing.T) {
	ctrl := &recordingCtrl{}
	src := &sysprobe.MemSource{}
	src.Set(tree())
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	for _, action := range []string{"echo hello", "restart; touch /tmp/marker", plugins.FixForceRestart} {
		p := plugin("")
		if action == plugins.FixForceRestart {
			delete(p.Fixes, plugins.FixForceRestart)
		}
		if _, err := runner.Apply(context.Background(), p, action, false); err == nil {
			t.Fatalf("action %q should be refused", action)
		}
	}
	if src.Takes != 0 || len(ctrl.pids) != 0 || len(ctrl.launches) != 0 {
		t.Fatalf("refused fix still ran: takes %d pids %v launches %v", src.Takes, ctrl.pids, ctrl.launches)
	}
}

func TestRefusesToSignalInit(t *testing.T) {
	snap := sysprobe.Snapshot{Processes: []sysprobe.Process{
		{PID: 1, PPID: 0, Name: "example-desktop-app", Exe: "example-desktop-app"},
	}}
	src := &sysprobe.ScriptSource{Snaps: []sysprobe.Snapshot{snap, snap}}
	ctrl := &recordingCtrl{}
	runner := &Runner{Source: src, Control: ctrl, Checks: checks.NewRunner(checks.NewRegistry())}
	res, err := runner.Apply(context.Background(), plugin(""), plugins.FixRestart, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrl.pids) != 0 {
		t.Fatalf("signalled pids: %v", ctrl.pids)
	}
	if !strings.Contains(res.SignalError, "refusing") {
		t.Fatalf("result: %+v", res)
	}
}

func TestOSControllerRefusesPrivilegedPIDsAndLaunchesWithoutArgs(t *testing.T) {
	ctrl := OSController{}
	if err := ctrl.Signal(1, syscall.SIGTERM); err == nil {
		t.Fatal("pid 1 should be refused")
	}
	if err := ctrl.Signal(os.Getpid(), syscall.SIGTERM); err == nil {
		t.Fatal("own pid should be refused")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	script := filepath.Join(dir, "launch-example")
	body := "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$*\" > '" + marker + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ctrl.Launch(ctx, script, nil); err != nil {
		t.Fatal(err)
	}
	waitMarker(t, marker, "0\n\n")
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Launch(ctx, script, []string{"--fixed", "example"}); err != nil {
		t.Fatal(err)
	}
	waitMarker(t, marker, "2\n--fixed example\n")
}

func waitMarker(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			if string(data) != want {
				t.Fatalf("marker %q want %q", data, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("launcher did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

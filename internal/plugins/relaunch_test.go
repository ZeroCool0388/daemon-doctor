package plugins

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRelaunchLocalConfigYAMLAndTOML(t *testing.T) {
	p, err := LoadFile(filepath.Join("..", "..", "testdata", "plugins", "example-relaunch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	fix := p.Fixes[FixRelaunch]
	if !Approved(p, FixRelaunch) || fix.App != "Example App" || fix.Launcher != filepath.Join(home, "bin", "app-launch.sh") || fix.QuitTimeout != "5s" {
		t.Fatalf("config: %+v", fix)
	}
	body := `id = "example-app"
name = "Example App"
[process]
match = "example-app"
[[checks]]
type = "process_running"
[[checks]]
type = "launched_with_flags"
flags = ["--required-setting"]
[fixes.relaunch]
kind = "relaunch"
app = "Example App"
launcher = "~/bin/app-launch.sh"
`
	path := filepath.Join(t.TempDir(), "app.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil || !reflect.DeepEqual(got.Fixes[FixRelaunch], fix) {
		t.Fatalf("TOML: %+v %v", got.Fixes, err)
	}
}

func TestRelaunchConfigRejectsIncompleteOrUnsafeFixes(t *testing.T) {
	for _, scenario := range []string{"no-app", "bad-app", "no-launcher", "relative-launcher", "shell", "label", "no-flags", "no-selector", "bad-timeout", "zero-timeout", "long-timeout", "wrong-kind", "other-action-fields"} {
		t.Run(scenario, func(t *testing.T) {
			p := Plugin{ID: "example-app", Name: "Example App", Process: ProcessMatch{Match: "example-app"}, Checks: []Check{{Type: CheckProcessRunning}, {Type: CheckLaunchedWithFlags, Flags: []string{"--required"}}}}
			fix := Fix{Kind: FixRelaunch, App: "Example App", Launcher: "/opt/example-launch"}
			key := FixRelaunch
			switch scenario {
			case "no-app":
				fix.App = ""
			case "bad-app":
				fix.App = "Example\nApp"
			case "no-launcher":
				fix.Launcher = ""
			case "relative-launcher":
				fix.Launcher = "bin/app-launch.sh"
			case "shell":
				fix.Launcher = "/bin/sh"
			case "label":
				fix.Label = "com.example.job"
			case "no-flags":
				p.Checks = p.Checks[:1]
			case "no-selector":
				p.Process = ProcessMatch{}
			case "bad-timeout":
				fix.QuitTimeout = "later"
			case "zero-timeout":
				fix.QuitTimeout = "0s"
			case "long-timeout":
				fix.QuitTimeout = "31s"
			case "wrong-kind":
				fix.Kind = FixRestart
			case "other-action-fields":
				key, fix.Kind = FixRestart, FixRestart
			}
			p.Fixes = map[string]Fix{key: fix}
			if err := Validate(&p, BuiltinCosts()); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

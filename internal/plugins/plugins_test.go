package plugins

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadExampleYAMLAndTOML(t *testing.T) {
	yamlPath := filepath.Join("..", "..", "plugins", "example-desktop-app.yaml")
	tomlPath := filepath.Join("..", "..", "testdata", "plugins", "example-desktop-app.toml")
	fromYAML, err := LoadFile(yamlPath)
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	fromTOML, err := LoadFile(tomlPath)
	if err != nil {
		t.Fatalf("load toml: %v", err)
	}
	if fromYAML.ID != "example-desktop-app" || fromYAML.Name != "Example Desktop App" {
		t.Fatalf("yaml identity: %+v", fromYAML)
	}
	if fromYAML.Process.Match != "example-desktop-app" {
		t.Fatalf("process match: %q", fromYAML.Process.Match)
	}
	if len(fromYAML.Checks) != 2 || fromYAML.Checks[0].Type != CheckProcessRunning {
		t.Fatalf("checks: %+v", fromYAML.Checks)
	}
	if fromYAML.Checks[1].Type != CheckOutboundTCP || fromYAML.Checks[1].Port != 443 || fromYAML.Checks[1].Consecutive != 3 {
		t.Fatalf("outbound check: %+v", fromYAML.Checks[1])
	}
	if fromYAML.Messages.Down == "" || fromYAML.Messages.Stuck == "" || fromYAML.Messages.KeepsHappening == "" {
		t.Fatalf("messages: %+v", fromYAML.Messages)
	}
	if !Approved(fromYAML, FixRestart) || !Approved(fromYAML, FixForceRestart) {
		t.Fatalf("fixes: %+v", fromYAML.Fixes)
	}
	if fromYAML.Messages != fromTOML.Messages || fromYAML.ID != fromTOML.ID || fromYAML.Process != fromTOML.Process {
		t.Fatalf("yaml and toml differ:\n yaml=%+v\n toml=%+v", fromYAML, fromTOML)
	}
	if len(fromTOML.Checks) != len(fromYAML.Checks) {
		t.Fatalf("check count yaml %d toml %d", len(fromYAML.Checks), len(fromTOML.Checks))
	}
	for i := range fromYAML.Checks {
		if !reflect.DeepEqual(fromYAML.Checks[i], fromTOML.Checks[i]) {
			t.Fatalf("check %d yaml %+v toml %+v", i, fromYAML.Checks[i], fromTOML.Checks[i])
		}
	}
}

func TestLoadDirRejectsDuplicateID(t *testing.T) {
	dir := t.TempDir()
	body := []byte("id: example-desktop-app\nname: Example Desktop App\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: process_running\n")
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.toml"), []byte("id = \"example-desktop-app\"\nname = \"Example Desktop App\"\n[process]\nmatch = \"example-desktop-app\"\n[[checks]]\ntype = \"process_running\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestRejectsUnknownFixAndBadOrder(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"shell.yaml":    "id: example-desktop-app\nname: Example\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: process_running\nfixes:\n  shell:\n    kind: shell\n",
		"order.yaml":    "id: example-desktop-app\nname: Example\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: outbound_tcp\n    port: 443\n    consecutive: 2\n  - type: process_running\n",
		"kind.yaml":     "id: example-desktop-app\nname: Example\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: process_running\nfixes:\n  restart:\n    kind: force-restart\n",
		"field.yaml":    "id: example-desktop-app\nname: Example\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: process_running\ncommand: echo hello\n",
		"field.toml":    "id = \"example-desktop-app\"\nname = \"Example\"\ncommand = \"echo hello\"\n[process]\nmatch = \"example-desktop-app\"\n[[checks]]\ntype = \"process_running\"\n",
		"relative.yaml": "id: example-desktop-app\nname: Example\nprocess:\n  match: example-desktop-app\nchecks:\n  - type: process_running\nfixes:\n  restart:\n    kind: restart\n    launcher: bin/example-launch\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLauncherMustBeAbsoluteProgram(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := &Plugin{
		ID:      "example-desktop-app",
		Name:    "Example Desktop App",
		Process: ProcessMatch{Match: "example-desktop-app"},
		Checks:  []Check{{Type: CheckProcessRunning}},
		Fixes: map[string]Fix{
			FixRestart: {Kind: FixRestart, Launcher: "~/bin/example-launch"},
		},
	}
	if err := Validate(p, BuiltinCosts()); err != nil {
		t.Fatal(err)
	}
	got := p.Fixes[FixRestart].Launcher
	want := filepath.Join(home, "bin", "example-launch")
	if got != want {
		t.Fatalf("launcher %q want %q", got, want)
	}

	p.Fixes[FixRestart] = Fix{Kind: FixRestart, Launcher: "/bin/bash"}
	if err := Validate(p, BuiltinCosts()); err == nil || !strings.Contains(err.Error(), "shell") {
		t.Fatalf("expected shell rejection, got %v", err)
	}
}

func TestApprovedOnlyAllowlist(t *testing.T) {
	p := Plugin{
		ID: "example-desktop-app",
		Fixes: map[string]Fix{
			FixRestart: {Kind: FixRestart},
		},
	}
	if !Approved(p, FixRestart) {
		t.Fatal("restart should be approved")
	}
	if Approved(p, FixForceRestart) {
		t.Fatal("force-restart was not listed")
	}
	if Approved(p, "restart; touch /tmp/marker") {
		t.Fatal("a smuggled command must not be approved")
	}
}

func TestLoadStarterPlugins(t *testing.T) {
	list, err := LoadDir(filepath.Join("..", "..", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	hosts := 0
	for _, p := range list {
		ids = append(ids, p.ID)
		if p.Host {
			hosts++
		}
		if !p.Host && !Approved(p, FixStop) && p.ID != "example-desktop-app" {
			t.Fatalf("%s should approve stop", p.ID)
		}
	}
	want := []string{
		"ai-desktop-app", "chatgpt", "codex", "example-desktop-app",
		"local-gateway", "proton-mail-bridge", "screen-sharing", "syncthing", "this-mac",
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids %v", ids)
	}
	if hosts != 1 {
		t.Fatalf("hosts %d", hosts)
	}
	mac := list[len(list)-1]
	if mac.ID != "this-mac" || mac.Process.Match != "" || mac.Checks[2].MinFreePercent != 10 || mac.Checks[4].CPUPercent != 85 {
		t.Fatalf("this-mac: %+v", mac)
	}
	if mac.Messages.NetworkDown == "" || mac.Messages.CPUHogUnwatched == "" || mac.Messages.MemoryHog == "" {
		t.Fatalf("messages: %+v", mac.Messages)
	}
}

func TestHostPluginValidation(t *testing.T) {
	host := Plugin{
		ID:   "this-mac",
		Name: "This Mac",
		Host: true,
		Checks: []Check{
			{Type: CheckSleep},
			{Type: CheckDisk, MinFreePercent: 10},
			{Type: CheckCPU, CPUPercent: 85, Duration: "5m"},
		},
	}
	if err := Validate(&host, BuiltinCosts()); err != nil {
		t.Fatal(err)
	}
	withProcess := host
	withProcess.Process.Match = "this-mac"
	if err := Validate(&withProcess, BuiltinCosts()); err == nil {
		t.Fatal("host plug-in should reject a process match")
	}
	service := Plugin{
		ID:      "example-desktop-app",
		Name:    "Example",
		Process: ProcessMatch{Match: "example-desktop-app"},
		Checks:  []Check{{Type: CheckProcessRunning}, {Type: CheckCPU}},
	}
	if err := Validate(&service, BuiltinCosts()); err == nil {
		t.Fatal("service plug-in should reject a host check")
	}
	second := host
	second.ID = "other-mac"
	if err := ValidateAll([]Plugin{host, second}, BuiltinCosts()); err == nil || !strings.Contains(err.Error(), "one host") {
		t.Fatalf("two hosts: %v", err)
	}
	stop := Plugin{
		ID:      "example-desktop-app",
		Name:    "Example",
		Process: ProcessMatch{Match: "example-desktop-app"},
		Checks:  []Check{{Type: CheckProcessRunning}},
		Fixes:   map[string]Fix{FixStop: {Kind: FixStop, Launcher: "/opt/example-launch"}},
	}
	if err := Validate(&stop, BuiltinCosts()); err == nil || !strings.Contains(err.Error(), "launcher") {
		t.Fatalf("stop launcher: %v", err)
	}
}

func TestCommandMatchAndNewChecks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := &Plugin{
		ID:   "example-gateway",
		Name: "Example Gateway",
		Process: ProcessMatch{
			Match:       "node",
			CmdContains: "example-gateway",
			CmdRegex:    `example-gateway/server\.js`,
		},
		Checks: []Check{
			{Type: CheckProcessRunning},
			{Type: CheckLaunchedWithFlags, Flags: []string{"--config"}},
			{Type: CheckFileRecent, Path: "~/Library/example-heartbeat", MaxAge: "5m"},
		},
		Fixes: map[string]Fix{
			FixRestart: {
				Kind:     FixRestart,
				Launcher: "/opt/example-launch",
				Args:     []string{"--config", "/opt/example.yaml"},
			},
		},
	}
	if err := Validate(p, BuiltinCosts()); err != nil {
		t.Fatal(err)
	}
	if p.Process.Spec().Pattern == nil || p.Checks[2].Path != filepath.Join(home, "Library", "example-heartbeat") {
		t.Fatalf("process %+v path %q", p.Process, p.Checks[2].Path)
	}
	if strings.Join(p.Fixes[FixRestart].Args, " ") != "--config /opt/example.yaml" {
		t.Fatalf("args %+v", p.Fixes[FixRestart])
	}

	job := Plugin{
		ID:      "example-health",
		Name:    "Example Health",
		Process: ProcessMatch{CmdContains: "example-health"},
		Checks:  []Check{{Type: CheckLaunchdJob, Label: "com.example.health", MaxAge: "10m"}},
		Fixes:   map[string]Fix{FixKickstart: {Kind: FixKickstart, Label: "com.example.health"}},
	}
	if err := Validate(&job, BuiltinCosts()); err != nil {
		t.Fatal(err)
	}

	bad := []Plugin{
		{ID: "example-gateway", Name: "Example Gateway", Process: ProcessMatch{CmdRegex: "("}, Checks: []Check{{Type: CheckProcessRunning}}},
		{ID: "example-gateway", Name: "Example Gateway", Process: ProcessMatch{Match: "node"}, Checks: []Check{{Type: CheckLaunchdJob, Label: "com.example.health", MaxAge: "10m"}, {Type: CheckProcessRunning}}},
		{ID: "example-health", Name: "Example Health", Process: ProcessMatch{CmdContains: "example-health"}, Checks: []Check{{Type: CheckLaunchdJob, Label: "not a label", MaxAge: "10m"}}},
		{ID: "example-gateway", Name: "Example Gateway", Process: ProcessMatch{Match: "node"}, Checks: []Check{{Type: CheckProcessRunning}}, Fixes: map[string]Fix{FixKickstart: {Kind: FixKickstart, Label: "com.example.health", Launcher: "/bin/launchctl"}}},
		{ID: "example-gateway", Name: "Example Gateway", Process: ProcessMatch{Match: "node"}, Checks: []Check{{Type: CheckProcessRunning}}, Fixes: map[string]Fix{FixRestart: {Kind: FixRestart, Args: []string{"--config"}}}},
	}
	for i, plugin := range bad {
		if err := Validate(&plugin, BuiltinCosts()); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
}

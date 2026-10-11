package plugins

import (
	"os"
	"path/filepath"
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
		if fromYAML.Checks[i] != fromTOML.Checks[i] {
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

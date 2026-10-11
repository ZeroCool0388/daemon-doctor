// Package plugins loads per-service plug-in files (YAML or TOML).
// A plug-in names the process to watch, lists health checks cheapest first,
// and approves fix actions from a fixed allowlist.
package plugins

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

const (
	CheckProcessRunning = "process_running"
	CheckOutboundTCP    = "outbound_tcp"
	CheckSleep          = "sleep_state"
	CheckNetwork        = "network"
	CheckDisk           = "disk_free"
	CheckMemory         = "memory_pressure"
	CheckCPU            = "cpu"
	FixStop             = "stop"
	FixRestart          = "restart"
	FixForceRestart     = "force-restart"

	// DefaultCPUPercent and DefaultDuration are used when a host plug-in
	// omits them. The shipped this-mac plug-in sets both explicitly.
	DefaultCPUPercent  = 85
	DefaultDuration    = 5 * time.Minute
	DefaultMemoryLevel = "warn"
)

// FixAllowlist is the only set of fix actions the program will run.
var FixAllowlist = map[string]struct{}{
	FixStop:         {},
	FixRestart:      {},
	FixForceRestart: {},
}

// BuiltinCosts ranks built-in checks. Lower numbers are cheaper and must
// appear earlier in a plug-in file.
func BuiltinCosts() map[string]int {
	return map[string]int{
		CheckProcessRunning: 10,
		CheckSleep:          12,
		CheckNetwork:        13,
		CheckDisk:           14,
		CheckMemory:         15,
		CheckCPU:            16,
		CheckOutboundTCP:    20,
	}
}

// Plugin is one watched service. Host plug-ins describe the machine
// itself and do not name a process.
type Plugin struct {
	ID       string         `yaml:"id" toml:"id"`
	Name     string         `yaml:"name" toml:"name"`
	Host     bool           `yaml:"host" toml:"host"`
	Process  ProcessMatch   `yaml:"process" toml:"process"`
	Checks   []Check        `yaml:"checks" toml:"checks"`
	Messages Messages       `yaml:"messages" toml:"messages"`
	Fixes    map[string]Fix `yaml:"fixes" toml:"fixes"`
}

// ProcessMatch is the process name or executable path to watch.
// Matching is exact against the process name, the executable, or its base name.
type ProcessMatch struct {
	Match string `yaml:"match" toml:"match"`
}

// Check is one health check. Checks run in file order.
type Check struct {
	Type           string  `yaml:"type" toml:"type"`
	Port           int     `yaml:"port" toml:"port"`
	Consecutive    int     `yaml:"consecutive" toml:"consecutive"`
	MinFreePercent float64 `yaml:"min_free_percent" toml:"min_free_percent"`
	CPUPercent     float64 `yaml:"cpu_percent" toml:"cpu_percent"`
	Duration       string  `yaml:"duration" toml:"duration"`
	Level          string  `yaml:"level" toml:"level"`
}

// Messages are the plain-English lines used when a rule fires.
// Placeholders such as {name}, {percent}, and {duration} are filled
// from the sample that raised the alert.
type Messages struct {
	Down               string `yaml:"down" toml:"down"`
	Stuck              string `yaml:"stuck" toml:"stuck"`
	KeepsHappening     string `yaml:"keeps_happening" toml:"keeps_happening"`
	Sleep              string `yaml:"sleep" toml:"sleep"`
	Wake               string `yaml:"wake" toml:"wake"`
	NetworkDown        string `yaml:"network_down" toml:"network_down"`
	NetworkBack        string `yaml:"network_back" toml:"network_back"`
	DiskLow            string `yaml:"disk_low" toml:"disk_low"`
	CPUHog             string `yaml:"cpu_hog" toml:"cpu_hog"`
	MemoryHog          string `yaml:"memory_hog" toml:"memory_hog"`
	CPUHogUnwatched    string `yaml:"cpu_hog_unwatched" toml:"cpu_hog_unwatched"`
	MemoryHogUnwatched string `yaml:"memory_hog_unwatched" toml:"memory_hog_unwatched"`
}

// Fix is one approved action. Kind must be stop, restart, or force-restart.
// Launcher, when set, is an absolute program path executed directly
// with no shell and no arguments. stop never launches a program.
type Fix struct {
	Kind     string `yaml:"kind" toml:"kind"`
	Launcher string `yaml:"launcher" toml:"launcher"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// LoadDir reads every .yaml, .yml, and .toml plug-in in dir.
// Files are validated with BuiltinCosts. Results are sorted by id.
func LoadDir(dir string) ([]Plugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read plug-in directory: %w", err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".yaml", ".yml", ".toml":
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	sort.Strings(paths)
	plugins := make([]Plugin, 0, len(paths))
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		p, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		if prev, ok := seen[p.ID]; ok {
			return nil, fmt.Errorf("duplicate plug-in id %q in %s and %s", p.ID, prev, path)
		}
		seen[p.ID] = path
		plugins = append(plugins, p)
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].ID < plugins[j].ID })
	if err := ValidateAll(plugins, BuiltinCosts()); err != nil {
		return nil, err
	}
	return plugins, nil
}

// LoadFile reads one plug-in and validates it against BuiltinCosts.
func LoadFile(path string) (Plugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Plugin{}, fmt.Errorf("read plug-in %s: %w", path, err)
	}
	var p Plugin
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := decodeYAML(data, &p); err != nil {
			return Plugin{}, fmt.Errorf("parse plug-in %s: %w", path, err)
		}
	case ".toml":
		if err := decodeTOML(data, &p); err != nil {
			return Plugin{}, fmt.Errorf("parse plug-in %s: %w", path, err)
		}
	default:
		return Plugin{}, fmt.Errorf("plug-in %s must be .yaml, .yml, or .toml", path)
	}
	if err := Validate(&p, BuiltinCosts()); err != nil {
		return Plugin{}, fmt.Errorf("plug-in %s: %w", path, err)
	}
	return p, nil
}

func decodeYAML(data []byte, dest *Plugin) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("file contains more than one document")
		}
		return err
	}
	return nil
}

func decodeTOML(data []byte, dest *Plugin) error {
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(dest)
	if err != nil {
		return err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("unknown field %s", undecoded[0])
	}
	return nil
}

// Validate checks p and rewrites launcher paths to cleaned absolute paths.
// costs maps a check type to its cost. Checks must be non-decreasing in cost.
// A service plug-in requires process_running first. A host plug-in uses host checks only.
func Validate(p *Plugin, costs map[string]int) error {
	if p == nil {
		return fmt.Errorf("plug-in is nil")
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Process.Match = strings.TrimSpace(p.Process.Match)
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("id must be lowercase letters, digits, and hyphens")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Host {
		if p.Process.Match != "" {
			return fmt.Errorf("a host plug-in does not take a process match")
		}
	} else if p.Process.Match == "" || p.Process.Match == "." || p.Process.Match == "/" {
		return fmt.Errorf("process match is required")
	}
	if len(p.Checks) == 0 {
		return fmt.Errorf("at least one check is required")
	}
	sawProcess := false
	seenType := map[string]struct{}{}
	prevCost := -1
	for i, check := range p.Checks {
		check.Type = strings.TrimSpace(check.Type)
		p.Checks[i].Type = check.Type
		if _, dup := seenType[check.Type]; dup {
			return fmt.Errorf("check %q is listed more than once", check.Type)
		}
		seenType[check.Type] = struct{}{}
		if p.Host && !isHostCheck(check.Type) {
			return fmt.Errorf("%s is not a host check", check.Type)
		}
		if !p.Host && isHostCheck(check.Type) {
			return fmt.Errorf("%s is only valid on a host plug-in", check.Type)
		}
		cost, ok := costs[check.Type]
		if !ok {
			return fmt.Errorf("unknown check type %q", check.Type)
		}
		if cost < prevCost {
			return fmt.Errorf("checks must be ordered cheapest first: %s (cost %d) follows a more expensive check", check.Type, cost)
		}
		prevCost = cost
		if err := validateCheck(&p.Checks[i]); err != nil {
			return err
		}
		if check.Type == CheckProcessRunning {
			sawProcess = true
		}
	}
	if !p.Host {
		if !sawProcess {
			return fmt.Errorf("process_running is required and must be the first check")
		}
		if p.Checks[0].Type != CheckProcessRunning {
			return fmt.Errorf("process_running must be the first check")
		}
	}
	if err := normalizeFixes(p); err != nil {
		return err
	}
	return nil
}

// ValidateAll validates every plug-in.
func ValidateAll(list []Plugin, costs map[string]int) error {
	seen := map[string]struct{}{}
	hosts := 0
	for i := range list {
		if _, ok := seen[list[i].ID]; ok {
			return fmt.Errorf("duplicate plug-in id %q", list[i].ID)
		}
		seen[list[i].ID] = struct{}{}
		if list[i].Host {
			hosts++
		}
		if err := Validate(&list[i], costs); err != nil {
			return fmt.Errorf("%s: %w", list[i].ID, err)
		}
	}
	if hosts > 1 {
		return fmt.Errorf("only one host plug-in is allowed")
	}
	return nil
}

func isHostCheck(typ string) bool {
	switch typ {
	case CheckSleep, CheckNetwork, CheckDisk, CheckMemory, CheckCPU:
		return true
	default:
		return false
	}
}

func validateCheck(check *Check) error {
	switch check.Type {
	case CheckProcessRunning, CheckSleep, CheckNetwork:
		if check.Port != 0 || check.Consecutive != 0 || check.MinFreePercent != 0 || check.CPUPercent != 0 || check.Duration != "" || check.Level != "" {
			return fmt.Errorf("%s does not take extra settings", check.Type)
		}
	case CheckOutboundTCP:
		if check.Port < 1 || check.Port > 65535 {
			return fmt.Errorf("outbound_tcp port must be from 1 to 65535")
		}
		if check.Consecutive < 1 {
			return fmt.Errorf("outbound_tcp consecutive must be at least 1")
		}
		if check.MinFreePercent != 0 || check.CPUPercent != 0 || check.Duration != "" || check.Level != "" {
			return fmt.Errorf("outbound_tcp does not take disk, cpu, or memory settings")
		}
	case CheckDisk:
		if check.MinFreePercent <= 0 || check.MinFreePercent > 100 {
			return fmt.Errorf("disk_free min_free_percent must be above 0 and at most 100")
		}
		if check.Port != 0 || check.Consecutive != 0 || check.CPUPercent != 0 || check.Duration != "" || check.Level != "" {
			return fmt.Errorf("disk_free only takes min_free_percent")
		}
	case CheckMemory:
		if check.Level == "" {
			check.Level = DefaultMemoryLevel
		}
		if check.Level != "warn" && check.Level != "critical" {
			return fmt.Errorf("memory_pressure level must be warn or critical")
		}
		if err := fillDuration(check); err != nil {
			return err
		}
		if check.Port != 0 || check.Consecutive != 0 || check.MinFreePercent != 0 || check.CPUPercent != 0 {
			return fmt.Errorf("memory_pressure only takes level and duration")
		}
	case CheckCPU:
		if check.CPUPercent == 0 {
			check.CPUPercent = DefaultCPUPercent
		}
		if check.CPUPercent <= 0 || check.CPUPercent > 100 {
			return fmt.Errorf("cpu_percent must be above 0 and at most 100")
		}
		if err := fillDuration(check); err != nil {
			return err
		}
		if check.Port != 0 || check.Consecutive != 0 || check.MinFreePercent != 0 || check.Level != "" {
			return fmt.Errorf("cpu only takes cpu_percent and duration")
		}
	}
	return nil
}

func fillDuration(check *Check) error {
	if check.Duration == "" {
		check.Duration = DefaultDuration.String()
	}
	d, err := time.ParseDuration(check.Duration)
	if err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	if d <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	return nil
}

func normalizeFixes(p *Plugin) error {
	if len(p.Fixes) == 0 {
		return nil
	}
	cleaned := make(map[string]Fix, len(p.Fixes))
	for key, fix := range p.Fixes {
		key = strings.TrimSpace(key)
		fix.Kind = strings.TrimSpace(fix.Kind)
		if _, ok := FixAllowlist[key]; !ok {
			return fmt.Errorf("fix %q is not on the allowlist (stop, restart, force-restart)", key)
		}
		if _, dup := cleaned[key]; dup {
			return fmt.Errorf("fix %q is listed more than once", key)
		}
		if fix.Kind != key {
			return fmt.Errorf("fix %q must use kind %q", key, key)
		}
		if key == FixStop && strings.TrimSpace(fix.Launcher) != "" {
			return fmt.Errorf("stop does not take a launcher")
		}
		launcher, err := cleanLauncher(fix.Launcher)
		if err != nil {
			return fmt.Errorf("fix %s: %w", key, err)
		}
		fix.Launcher = launcher
		cleaned[key] = fix
	}
	p.Fixes = cleaned
	return nil
}

// Approved reports whether action is on the allowlist and listed for p.
func Approved(p Plugin, action string) bool {
	action = strings.TrimSpace(action)
	if _, ok := FixAllowlist[action]; !ok {
		return false
	}
	fix, ok := p.Fixes[action]
	return ok && fix.Kind == action
}

func cleanLauncher(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if strings.ContainsAny(path, "\n\r\x00") {
		return "", fmt.Errorf("launcher path contains a control character")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("launcher uses ~ but the home directory is unknown")
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	if strings.Contains(path, "~") {
		return "", fmt.Errorf("launcher must be an absolute path")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("launcher must be an absolute path")
	}
	switch strings.ToLower(filepath.Base(cleaned)) {
	case "sh", "bash", "zsh", "dash", "ksh", "cmd.exe", "powershell", "pwsh":
		return "", fmt.Errorf("launcher must be a program path, not a shell")
	}
	return cleaned, nil
}

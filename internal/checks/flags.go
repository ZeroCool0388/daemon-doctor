package checks

import (
	"strings"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type flagsCheck struct{}

func (flagsCheck) Type() string { return plugins.CheckLaunchedWithFlags }
func (flagsCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckLaunchedWithFlags] }

func (flagsCheck) Run(in Input) Outcome {
	found := sysprobe.MatchingSpec(in.Snap, in.Plugin.Process.Spec())
	if len(found) == 0 {
		return Outcome{
			Type:       plugins.CheckLaunchedWithFlags,
			NotRunning: true,
			Failed:     true,
			Detail:     in.Plugin.Name + " is not running.",
		}
	}
	for _, proc := range found {
		if !argsHaveFlags(proc.Cmd, in.Spec.Flags) {
			return Outcome{
				Type:         plugins.CheckLaunchedWithFlags,
				Failed:       true,
				MissingFlags: true,
				Detail:       in.Plugin.Name + " started without its required settings.",
			}
		}
	}
	return Outcome{
		Type:    plugins.CheckLaunchedWithFlags,
		Healthy: true,
		Detail:  in.Plugin.Name + " was started with its required settings.",
	}
}

func argsHaveFlags(cmd string, flags []string) bool {
	fields := strings.Fields(cmd)
	for _, flag := range flags {
		if !hasFlag(fields, flag) {
			return false
		}
	}
	return true
}

func hasFlag(fields []string, flag string) bool {
	prefix := flag + "="
	for _, field := range fields {
		if field == flag || strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

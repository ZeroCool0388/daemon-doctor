package checks

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

type fileRecentCheck struct{}

func (fileRecentCheck) Type() string { return plugins.CheckFileRecent }
func (fileRecentCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckFileRecent] }

func (fileRecentCheck) Run(in Input) Outcome {
	path := in.Spec.Path
	name := filepath.Base(path)
	maxAge, err := time.ParseDuration(in.Spec.MaxAge)
	if err != nil || maxAge <= 0 {
		return Outcome{
			Type:   plugins.CheckFileRecent,
			Failed: true,
			Detail: name + " has no age limit set.",
		}
	}
	stamp, ok := in.Snap.Files[path]
	if !ok || !stamp.Known {
		return Outcome{
			Type:   plugins.CheckFileRecent,
			Failed: true,
			Detail: name + " has no recorded modification time.",
		}
	}
	if stamp.Missing {
		return Outcome{
			Type:   plugins.CheckFileRecent,
			Failed: true,
			Stuck:  true,
			Detail: name + " is missing.",
		}
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	age := now.Sub(stamp.ModTime)
	window := plainAge(maxAge)
	if age > maxAge {
		return Outcome{
			Type:   plugins.CheckFileRecent,
			Failed: true,
			Stuck:  true,
			Detail: fmt.Sprintf("%s has not been modified in the last %s.", name, window),
		}
	}
	return Outcome{
		Type:    plugins.CheckFileRecent,
		Healthy: true,
		Detail:  fmt.Sprintf("%s was modified within the last %s.", name, window),
	}
}

func plainAge(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		n := int(d / time.Hour)
		if n == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", n)
	}
	if d >= time.Minute && d%time.Minute == 0 {
		n := int(d / time.Minute)
		if n == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", n)
	}
	return d.String()
}

package rules

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

func rawMessage(m plugins.Messages, kind string) string {
	switch kind {
	case KindDown:
		return m.Down
	case KindStuck:
		return m.Stuck
	case KindMissingFlags:
		return m.MissingFlags
	case KindLaunchd:
		return m.LaunchdJob
	case KindKeepsHappening:
		return m.KeepsHappening
	case KindSleep:
		return m.Sleep
	case KindWake:
		return m.Wake
	case KindNetworkDown:
		return m.NetworkDown
	case KindNetworkBack:
		return m.NetworkBack
	case KindDiskLow:
		return m.DiskLow
	case KindCPUHog:
		return m.CPUHog
	case KindMemoryHog:
		return m.MemoryHog
	case KindCPUHog + "_unwatched":
		return m.CPUHogUnwatched
	case KindMemoryHog + "_unwatched":
		return m.MemoryHogUnwatched
	default:
		return ""
	}
}

func templateFor(m plugins.Messages, kind string) string {
	msg := rawMessage(m, kind)
	if msg == "" {
		msg = defaultTemplate(kind)
	}
	return msg
}

func alertText(p plugins.Plugin, kind string, outcomes []checks.Outcome) string {
	if custom := strings.TrimSpace(rawMessage(p.Messages, kind)); custom != "" {
		return fill(custom, map[string]string{"name": p.Name})
	}
	if kind == KindMissingFlags || kind == KindLaunchd {
		for _, outcome := range outcomes {
			if outcome.Detail != "" && (outcome.MissingFlags || outcome.JobFailed) {
				return outcome.Detail
			}
		}
	}
	return message(p, kind)
}

func defaultTemplate(kind string) string {
	switch kind {
	case KindDown:
		return "{name} has stopped. It is not running."
	case KindStuck:
		return "{name} is running but its health check is failing."
	case KindMissingFlags:
		return "{name} started without its required settings."
	case KindLaunchd:
		return "{name} has not had a successful run in the last window."
	case KindKeepsHappening:
		return "{name} has failed 3 times in the last hour. Automatic fixes are paused."
	case KindSleep:
		return "The Mac went to sleep."
	case KindWake:
		return "The Mac woke up."
	case KindNetworkDown:
		return "The Mac lost its network connection at {time}. Other alerts are paused until it is back."
	case KindNetworkBack:
		return "Network back at {time}. {ok} of {total} services healthy."
	case KindDiskLow:
		return "Free disk space is low: {free}% is left."
	case KindCPUHog:
		return "{name} has used {percent}% of the CPU for {duration}."
	case KindMemoryHog:
		return "{name} is the largest memory user, and memory pressure has stayed at {level} for {duration}."
	case KindCPUHog + "_unwatched":
		return "A process that is not on the watched list ({process}) has used {percent}% of the CPU for {duration}."
	case KindMemoryHog + "_unwatched":
		return "A process that is not on the watched list ({process}) is the largest memory user, and memory pressure has stayed at {level} for {duration}."
	default:
		return ""
	}
}

func fill(template string, fields map[string]string) string {
	for key, value := range fields {
		template = strings.ReplaceAll(template, "{"+key+"}", value)
	}
	return template
}

func formatClock(t time.Time) string {
	return t.UTC().Format("15:04") + " UTC"
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d == 0 {
		return "0 seconds"
	}
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	d -= mins * time.Minute
	secs := d / time.Second
	var parts []string
	if hours > 0 {
		parts = append(parts, plural(int(hours), "hour"))
	}
	if mins > 0 {
		parts = append(parts, plural(int(mins), "minute"))
	}
	if secs > 0 {
		parts = append(parts, plural(int(secs), "second"))
	}
	return strings.Join(parts, " ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func formatPercent(v float64) string {
	if math.Abs(v-math.Round(v)) < 0.05 {
		return strconv.Itoa(int(math.Round(v)))
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func pressureWord(level string) string {
	switch level {
	case "warn":
		return "warning"
	case "critical":
		return "critical"
	case "normal":
		return "normal"
	default:
		return level
	}
}

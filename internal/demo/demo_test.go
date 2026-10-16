package demo

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestReplay(t *testing.T) {
	var buf bytes.Buffer
	if err := Run(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if strings.Contains(text, "https://") || strings.Contains(text, "relay.example") {
		t.Fatalf("demo mentioned a relay:\n%s", text)
	}
	alerts := alertLines(text)
	want := []string{
		"Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck.",
		"The Mac lost its network connection at 12:05 UTC. Other alerts are paused until it is back.",
		"Network back at 12:07 UTC. 4 of 5 services healthy.",
		"Example Mail has stopped. It is not running.",
		"A process that is not on the watched list (ExampleTool) has used 90% of the CPU for 5 minutes.",
		"Example Bridge has stopped. It is not running.",
		"Example Bridge has stopped. It is not running.",
		"Example Bridge has failed 3 times in the last hour. Automatic fixes are paused.",
	}
	if strings.Join(alerts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("alerts:\n%s\n\nfull:\n%s", strings.Join(alerts, "\n"), text)
	}
	back := "Network back at 12:07 UTC. 4 of 5 services healthy.\nOffline:\n• Example Mail\nOnline:\n• Example Bridge\n• Example Desktop App\n• Example Sync\n• This Mac"
	if !strings.Contains(text, "12:07 UTC  alert: "+back+"\n12:07 UTC  fix offered: none") {
		t.Fatalf("missing recovery service lists:\n%s", text)
	}
	if !strings.Contains(text, "outcome: Fixed. Example Desktop App looks healthy on recheck.") {
		t.Fatal("stuck app was not reported fixed")
	}
	if !strings.Contains(text, "outcome: Fixed. ExampleTool looks healthy on recheck.") {
		t.Fatal("cpu hog was not reported stopped")
	}
	if !strings.Contains(text, "fix offered: none") {
		t.Fatal("keeps happening still offered a fix")
	}
	if !strings.Contains(text, "fix offered: stop ExampleTool") {
		t.Fatal("cpu hog did not offer stop")
	}
	if !strings.Contains(text, "outcome: Example Mail stays stopped. The demo does not apply a fix.") {
		t.Fatal("mail fix was not left alone")
	}
}

func alertLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		const mark = "alert: "
		if i := strings.Index(line, mark); i >= 0 {
			out = append(out, line[i+len(mark):])
		}
	}
	return out
}

func BenchmarkCheckCycle(b *testing.B) {
	clock := &clock{t: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)}
	world := &world{appUp: true, appOut: true, syncUp: true, mailUp: true, bridgeUp: true, networkUp: true}
	src := &sysprobe.MemSource{}
	src.Set(world.snapshot())
	doc, err := doctor.New(scriptPlugins(), src, &stage{src: src, world: world}, nil, nil, clock.now)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := doc.Cycle(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := doc.Cycle(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

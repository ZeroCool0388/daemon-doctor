package doctor

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type relaunchControl struct {
	src                      *sysprobe.MemSource
	quits, launches, signals int
}

func (c *relaunchControl) Signal(int, syscall.Signal) error { c.signals++; return nil }
func (c *relaunchControl) Quit(ctx context.Context, app string) error {
	c.quits++
	c.src.Set(sysprobe.Snapshot{})
	return nil
}
func (c *relaunchControl) Launch(ctx context.Context, path string, args []string) error {
	c.launches++
	c.src.Set(relaunchSnapshot(true))
	return nil
}

func relaunchSnapshot(healthy bool) sysprobe.Snapshot {
	cmd := "example-app"
	if healthy {
		cmd += " --required-setting"
	}
	return sysprobe.Snapshot{Processes: []sysprobe.Process{{PID: 42, PPID: 1, Name: "example-app", Exe: "example-app", Cmd: cmd}}}
}

func relaunchDoctor(t *testing.T) (*Doctor, *sysprobe.MemSource, *relaunchControl, *time.Time) {
	t.Helper()
	p, err := plugins.LoadFile(filepath.Join("..", "..", "testdata", "plugins", "example-relaunch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := &sysprobe.MemSource{}
	src.Set(relaunchSnapshot(false))
	ctrl := &relaunchControl{src: src}
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	d, err := New([]plugins.Plugin{p}, src, ctrl, nil, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store, err := offers.Open(filepath.Join(t.TempDir(), "control"))
	if err != nil {
		t.Fatal(err)
	}
	d.UseOffers(store)
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d, src, ctrl, &now
}

func TestRelaunchOfferIsSingleUseAndPublishesRecheck(t *testing.T) {
	d, _, ctrl, _ := relaunchDoctor(t)
	list, err := d.OfferedFixes()
	if err != nil || len(list) != 1 || list[0].FixID != plugins.FixRelaunch {
		t.Fatalf("offers: %+v %v", list, err)
	}
	if _, err := d.ApplyOffer(context.Background(), list[0].ID, "other-service", false); err == nil {
		t.Fatal("service mismatch accepted")
	}
	if ctrl.quits != 0 {
		t.Fatal("service mismatch quit app")
	}
	res, err := d.ApplyOffer(context.Background(), list[0].ID, list[0].ServiceID, false)
	if err != nil || !res.Fixed || ctrl.quits != 1 || ctrl.launches != 1 || ctrl.signals != 0 {
		t.Fatalf("fix: %+v %v %+v", res, err, ctrl)
	}
	rows, _, err := d.Snapshot()
	if err != nil || rows[0].Status != rules.StatusOK || len(rows[0].Alerts) != 0 {
		t.Fatalf("recheck not published: %+v %v", rows, err)
	}
	if _, err := d.ApplyOffer(context.Background(), list[0].ID, "", false); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
	}
	if ctrl.quits != 1 || ctrl.launches != 1 {
		t.Fatal("replay ran app control")
	}
}

func TestRelaunchOfferHonorsExistingSafeguards(t *testing.T) {
	for _, scenario := range []string{"expired", "recovered", "allowlist", "held", "lockout", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			d, src, ctrl, now := relaunchDoctor(t)
			items, _ := d.OfferedFixes()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "expired":
				*now = now.Add(11 * time.Minute)
			case "recovered":
				src.Set(relaunchSnapshot(true))
			case "allowlist":
				delete(d.Plugins[0].Fixes, plugins.FixRelaunch)
			case "held":
				host, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "this-mac.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				d.Plugins = append(d.Plugins, host)
				snap := relaunchSnapshot(false)
				snap.Host.SleepKnown, snap.Host.Asleep = true, true
				src.Set(snap)
			case "lockout":
				for range 2 {
					src.Set(relaunchSnapshot(true))
					_, _ = d.Cycle(ctx)
					src.Set(relaunchSnapshot(false))
					_, _ = d.Cycle(ctx)
				}
			case "cancelled":
				cancel()
			}
			if _, err := d.ApplyOffer(ctx, items[0].ID, "", false); err == nil {
				t.Fatal("inactive offer accepted")
			}
			if ctrl.quits+ctrl.launches+ctrl.signals != 0 {
				t.Fatalf("refused offer performed work: %+v", ctrl)
			}
		})
	}
}

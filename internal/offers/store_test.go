package offers

import (
	"fmt"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDurableSingleUseAndAlternatives(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := security.Raised{ID: "incident", ServiceID: "example", At: now, Actions: []string{"stop", "restart"}}
	if err = s.Mint(now, a, "test"); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	items, err := second.List(now)
	if err != nil || len(items) != 2 {
		t.Fatalf("list: %v %v", items, err)
	}
	if _, err = s.Consume(now, items[0].ID, func(Offer) error { return fmt.Errorf("mismatch") }); err == nil {
		t.Fatal("validation allowed")
	}
	if _, err = second.Consume(now, items[0].ID, func(Offer) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, o := range items {
		if _, err = s.Consume(now, o.ID, func(Offer) error { return nil }); err == nil || !strings.Contains(err.Error(), "replay") {
			t.Fatalf("replay: %v", err)
		}
	}
	for _, path := range []string{dir, filepath.Join(dir, "offers.json"), filepath.Join(dir, "offers.lock")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if path == dir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode %s: %v", path, info.Mode())
		}
	}
}

func TestConcurrentStoresOnlyConsumeOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.Mint(now, security.Raised{ID: "incident", At: now, Actions: []string{"restart"}}, ""); err != nil {
		t.Fatal(err)
	}
	items, _ := s.List(now)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range 12 {
		other, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := other.Consume(now, items[0].ID, func(Offer) error { return nil }); e == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("consumed %d times", wins.Load())
	}
}

func TestExpiredAndUnknown(t *testing.T) {
	s, _ := Open("")
	now := time.Now()
	_ = s.Mint(now, security.Raised{ID: "a", At: now, Actions: []string{"stop"}}, "")
	items, _ := s.List(now)
	if _, err := s.Consume(now.Add(security.ApprovalTTL), items[0].ID, func(Offer) error { t.Fatal("expired validation called"); return nil }); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry: %v", err)
	}
	if _, err := s.Consume(now, "unknown", func(Offer) error { return nil }); err == nil {
		t.Fatal("unknown accepted")
	}
}

func TestRejectsUnsafeDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	_ = os.Mkdir(dir, 0755)
	if _, err := Open(dir); err == nil {
		t.Fatal("public dir accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	_ = os.Symlink(dir, link)
	if _, err := Open(link); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestCrossProcessConsume(t *testing.T) {
	if os.Getenv("DD_OFFER_CHILD") == "1" {
		s, err := Open(os.Getenv("DD_OFFER_DIR"))
		if err != nil {
			os.Exit(2)
		}
		_, err = s.Consume(time.Now(), os.Getenv("DD_OFFER_ID"), func(Offer) error { return nil })
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	dir := filepath.Join(t.TempDir(), "control")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = s.Mint(now, security.Raised{ID: "incident", At: now, Actions: []string{"restart"}}, ""); err != nil {
		t.Fatal(err)
	}
	items, _ := s.List(now)
	cmds := []*exec.Cmd{}
	for range 2 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrossProcessConsume$")
		cmd.Env = append(os.Environ(), "DD_OFFER_CHILD=1", "DD_OFFER_DIR="+dir, "DD_OFFER_ID="+items[0].ID)
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	wins := 0
	for _, cmd := range cmds {
		err = cmd.Wait()
		if err == nil {
			wins++
		} else if cmd.ProcessState.ExitCode() != 1 {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("cross-process consumes: %d", wins)
	}
}

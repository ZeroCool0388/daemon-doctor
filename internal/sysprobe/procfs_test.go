package sysprobe

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestReadProcCountsEstablishedOutbound(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 10, 1, "example-desktop-app", "/opt/example-desktop-app", "100")
	writeProc(t, root, 11, 10, "helper", "helper", "101")
	writeProc(t, root, 12, 1, "other-app", "other-app", "102")
	net := "" +
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:C000 00000000:01BB 01 00000000:00000000 00:00000000 00000000 0 0 100 1 00000000 100 0 0 10 0\n" +
		"   1: 00000000:C001 00000000:01BB 01 00000000:00000000 00:00000000 00000000 0 0 101 1 00000000 100 0 0 10 0\n" +
		"   2: 00000000:C002 00000000:01BB 01 00000000:00000000 00:00000000 00000000 0 0 102 1 00000000 100 0 0 10 0\n" +
		"   3: 00000000:01BB 00000000:C350 01 00000000:00000000 00:00000000 00000000 0 0 200 1 00000000 100 0 0 10 0\n" +
		"   4: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 201 1 00000000 100 0 0 10 0\n" +
		"   5: 00000000:C003 00000000:01BB 06 00000000:00000000 00:00000000 00000000 0 0 202 1 00000000 100 0 0 10 0\n"
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(net), 0o644); err != nil {
		t.Fatal(err)
	}
	tcp6 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:C010 00000000000000000000000000000000:01BB 01 00000000:00000000 00:00000000 00000000 0 0 103 1 00000000 100 0 0 10 0\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}
	// Child holds the IPv6 connection.
	if err := os.Symlink("socket:[103]", filepath.Join(root, "11", "fd", "4")); err != nil {
		t.Fatal(err)
	}

	snap, err := ReadProc(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := CountOutbound(snap, RootPIDs(snap, "example-desktop-app"), 443); n != 3 {
		t.Fatalf("example tree count = %d, want 3 (parent, child, child ipv6)", n)
	}
	if n := CountOutbound(snap, RootPIDs(snap, "other-app"), 443); n != 1 {
		t.Fatalf("other count = %d, want 1", n)
	}
	found := Matching(snap, "/opt/example-desktop-app")
	if len(found) != 1 || found[0].PID != 10 {
		t.Fatalf("path match: %+v", found)
	}
}

func TestParseStatCommWithSpaces(t *testing.T) {
	name, ppid, err := parseStat("12 (example desktop) S 7 12 12 0")
	if err != nil {
		t.Fatal(err)
	}
	if name != "example desktop" || ppid != 7 {
		t.Fatalf("name %q ppid %d", name, ppid)
	}
}

func TestLiveLinuxIncludesThisProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live procfs sample runs on linux")
	}
	snap, err := Live().Take(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	for _, proc := range snap.Processes {
		if proc.PID == self {
			return
		}
	}
	t.Fatalf("sample of %d processes did not include pid %d", len(snap.Processes), self)
}

func writeProc(t *testing.T, root string, pid, ppid int, name, exe, inode string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	stat := strconv.Itoa(pid) + " (" + name + ") S " + strconv.Itoa(ppid) + " 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(exe+"\x00--flag\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if inode != "" {
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
}

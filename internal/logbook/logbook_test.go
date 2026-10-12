package logbook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendIsAppendOnlyAndBlanksSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	book, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := Event{
		Time:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Kind:        "check",
		ServiceID:   "example-desktop-app",
		ServiceName: "Example Desktop App",
		Message:     "Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck.",
		Detail:      "token=supersecretvalue",
	}
	if err := book.Append(first); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	if err := book.Append(Event{
		Time:    first.Time.Add(time.Second),
		Kind:    "fix",
		Message: "Authorization: Bearer abcdefghijklmnop",
		Detail:  secret,
	}); err != nil {
		t.Fatal(err)
	}
	if err := book.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Append(Event{Time: first.Time.Add(2 * time.Second), Kind: "alert", Message: "still here"}); err != nil {
		t.Fatal(err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, before) {
		t.Fatalf("the first line was rewritten\n before %s\n after %s", before, data)
	}
	if strings.Contains(string(data), "supersecretvalue") || strings.Contains(string(data), "abcdefghijklmnop") || strings.Contains(string(data), "BEGIN OPENSSH") {
		t.Fatalf("secret leaked into the log: %s", data)
	}
	if !strings.Contains(string(data), "port 443") {
		t.Fatalf("ordinary text was removed: %s", data)
	}
	lines := nonEmpty(data)
	if len(lines) != 3 {
		t.Fatalf("lines = %d\n%s", len(lines), data)
	}
	var decoded Event
	if err := json.Unmarshal(lines[0], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != "check" || decoded.Detail != "token=[blanked]" {
		t.Fatalf("decoded: %+v", decoded)
	}
}

func TestRotateAtSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	book, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	book.SetMaxBytes(120)
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i := 0; i < 4; i++ {
		if err := book.Append(Event{
			Time:    start.Add(time.Duration(i) * time.Second),
			Kind:    "check",
			Message: "Example Desktop App is ok on this sample.",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := book.Close(); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(backup) == 0 || len(current) == 0 {
		t.Fatalf("backup %d current %d", len(backup), len(current))
	}
	if bytes.Contains(current, backup) {
		t.Fatal("the rotated file was copied into the new log")
	}
	events, err := Read(path)
	if err != nil || len(events) == 0 || events[0].Kind != "check" {
		t.Fatalf("current log: %+v %v", events, err)
	}
	old, err := Read(path + ".1")
	if err != nil || len(old) == 0 {
		t.Fatalf("rotated log: %+v %v", old, err)
	}
	if !old[0].Time.Before(events[0].Time) {
		t.Fatalf("rotation order old %s current %s", old[0].Time, events[0].Time)
	}
}

func TestBlankLeavesPlainEnglish(t *testing.T) {
	msg := "Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck."
	if Blank(msg) != msg {
		t.Fatalf("blanked ordinary text: %q", Blank(msg))
	}
}

func nonEmpty(data []byte) [][]byte {
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			lines = append(lines, append([]byte(nil), sc.Bytes()...))
		}
	}
	return lines
}

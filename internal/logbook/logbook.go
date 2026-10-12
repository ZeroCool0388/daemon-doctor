// Package logbook appends checks, alerts, and fixes to a local JSON-lines file.
// Secret-looking values are blanked before they are written.
package logbook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Event is one log line.
type Event struct {
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	ServiceID   string    `json:"service_id,omitempty"`
	ServiceName string    `json:"service_name,omitempty"`
	Status      string    `json:"status,omitempty"`
	AlertKind   string    `json:"alert_kind,omitempty"`
	AlertID     string    `json:"alert_id,omitempty"`
	Message     string    `json:"message,omitempty"`
	OfferFix    *bool     `json:"offer_fix,omitempty"`
	Action      string    `json:"action,omitempty"`
	Process     string    `json:"process,omitempty"`
	DryRun      *bool     `json:"dry_run,omitempty"`
	OK          *bool     `json:"ok,omitempty"`
	Fixed       *bool     `json:"fixed,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
}

// DefaultMaxBytes is the size at which the log rotates.
// The current file is renamed to the same path with a ".1" suffix.
const DefaultMaxBytes int64 = 1 << 20

// Book is a JSON-lines log. It records new lines and rotates at MaxBytes.
type Book struct {
	mu   sync.Mutex
	f    *os.File
	path string
	max  int64
}

// Open creates or opens path for appending. The file mode is 0600.
func Open(path string) (*Book, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	return &Book{f: f, path: path, max: DefaultMaxBytes}, nil
}

// SetMaxBytes changes the rotation limit. A non-positive value is ignored.
func (b *Book) SetMaxBytes(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.max = n
	b.mu.Unlock()
}

// Path returns the log file path.
func (b *Book) Path() string { return b.path }

// Close closes the file.
func (b *Book) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.f.Close()
}

// Read returns every JSON line in path. A missing file is an empty log.
func Read(path string) ([]Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read log: %w", err)
	}
	var out []Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("read log: %w", err)
		}
		out = append(out, event)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read log: %w", err)
	}
	return out, nil
}

// Append writes one JSON line. It does not rewrite earlier lines.
func (b *Book) Append(e Event) error {
	e.Message = Blank(e.Message)
	e.Detail = Blank(e.Detail)
	e.ServiceName = Blank(e.ServiceName)
	e.Action = Blank(e.Action)
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	} else {
		e.Time = e.Time.UTC()
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode log event: %w", err)
	}
	buf = append(buf, '\n')
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.rotateIfNeeded(int64(len(buf))); err != nil {
		return err
	}
	if _, err := b.f.Write(buf); err != nil {
		return fmt.Errorf("append log: %w", err)
	}
	if err := b.f.Sync(); err != nil {
		return fmt.Errorf("sync log: %w", err)
	}
	return nil
}

func (b *Book) rotateIfNeeded(next int64) error {
	if b.max <= 0 {
		return nil
	}
	info, err := b.f.Stat()
	if err != nil {
		return fmt.Errorf("stat log: %w", err)
	}
	if info.Size() == 0 || info.Size()+next <= b.max {
		return nil
	}
	if err := b.f.Close(); err != nil {
		return fmt.Errorf("close log: %w", err)
	}
	backup := b.path + ".1"
	_ = os.Remove(backup)
	if err := os.Rename(b.path, backup); err != nil {
		return fmt.Errorf("rotate log: %w", err)
	}
	f, err := os.OpenFile(b.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reopen log: %w", err)
	}
	b.f = f
	return nil
}

var (
	pemSecret = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	kvSecret  = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|\S+)`)
	bearer    = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*`)
)

// Blank replaces secret-looking values with [blanked].
func Blank(s string) string {
	s = pemSecret.ReplaceAllString(s, "[blanked]")
	s = bearer.ReplaceAllString(s, "bearer [blanked]")
	s = kvSecret.ReplaceAllString(s, "${1}${2}[blanked]")
	return s
}

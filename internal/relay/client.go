// Package relay is the Mac's outbound client for the mailbox worker.
// It posts and polls. It does not accept inbound connections, and it does
// not decide whether an approval is valid.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// MaxOutbox is how many unsent posts are kept for a retry. The oldest is
// dropped first.
const MaxOutbox = 64

// maxSeen bounds the ids remembered per box above the poll cursor. Boxes
// that are only watched, never polled, would otherwise grow without end.
const maxSeen = 1024

// Event is one mailbox record. Body is the JSON object the sender posted.
type Event struct {
	ID   int64           `json:"id"`
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

type page struct {
	Events []Event `json:"events"`
}

// StatusError is a relay reply other than 200.
type StatusError struct {
	Path string
	Code int
	Text string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("relay %s: %s", e.Path, e.Text)
}

// Client talks to one relay base URL.
// Events seen once, by Poll or Watch, are not returned again.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// RetryMin and RetryMax bound the wait between WebSocket reconnects.
	RetryMin time.Duration
	RetryMax time.Duration

	mu         sync.Mutex
	after      map[string]int64
	seen       map[string]map[int64]struct{}
	cursorPath string
	outbox     []outgoing
}

type outgoing struct {
	macID string
	kind  string
	raw   []byte
}

type cursorFile struct {
	BaseURL string           `json:"base_url"`
	After   map[string]int64 `json:"after"`
}

// New returns a client. baseURL is an http or https origin with no user info.
func New(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, fmt.Errorf("relay URL must be http or https and must not include a password")
	}
	return &Client{
		BaseURL:  baseURL,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		RetryMin: time.Second,
		RetryMax: time.Minute,
		after:    map[string]int64{},
		seen:     map[string]map[int64]struct{}{},
	}, nil
}

// UseCursorFile keeps the poll position in path so a restart does not
// read the whole mailbox again. A file written for another base URL is ignored.
func (c *Client) UseCursorFile(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cursorPath = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var file cursorFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("relay cursor: %w", err)
	}
	if file.BaseURL != c.BaseURL {
		return nil
	}
	for key, id := range file.After {
		if id > c.after[key] {
			c.after[key] = id
		}
	}
	return nil
}

// Post sends one JSON object into a mailbox. The body is stored, not run.
func (c *Client) Post(ctx context.Context, macID, kind string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return c.post(ctx, macID, kind, raw)
}

// Send posts body after any earlier posts that failed. When the relay
// cannot be reached, or answers 429 or 5xx, the body is kept for the next
// Send or Flush. Other refusals are returned and not kept.
func (c *Client) Send(ctx context.Context, macID, kind string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if err := c.Flush(ctx); err != nil {
		c.enqueue(outgoing{macID: macID, kind: kind, raw: raw})
		return err
	}
	err = c.post(ctx, macID, kind, raw)
	if err != nil && retryable(err) {
		c.enqueue(outgoing{macID: macID, kind: kind, raw: raw})
	}
	return err
}

// Flush retries kept posts in order. It stops at the first one that should
// be retried again, and drops ones the relay refused for good.
func (c *Client) Flush(ctx context.Context) error {
	var refused error
	for {
		c.mu.Lock()
		if len(c.outbox) == 0 {
			c.mu.Unlock()
			return refused
		}
		next := c.outbox[0]
		c.mu.Unlock()
		err := c.post(ctx, next.macID, next.kind, next.raw)
		if err != nil && retryable(err) {
			return err
		}
		if err != nil {
			refused = err
		}
		c.mu.Lock()
		if len(c.outbox) > 0 {
			c.outbox = c.outbox[1:]
		}
		c.mu.Unlock()
	}
}

// Pending is how many posts are waiting for a retry.
func (c *Client) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.outbox)
}

func (c *Client) enqueue(o outgoing) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbox = append(c.outbox, o)
	if len(c.outbox) > MaxOutbox {
		c.outbox = c.outbox[len(c.outbox)-MaxOutbox:]
	}
}

func retryable(err error) bool {
	var status *StatusError
	if !errors.As(err, &status) {
		return true
	}
	return status.Code == http.StatusTooManyRequests || status.Code >= 500
}

func (c *Client) post(ctx context.Context, macID, kind string, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(macID, kind), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return statusError(res)
	}
	var stored struct {
		ID int64 `json:"id"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&stored) == nil && stored.ID > 0 {
		c.noteStored(macID, stored.ID)
	}
	return nil
}

// noteStored resets this Mac's cursors when the relay hands out an id at or
// below one already read. Ids only grow, so that means the mailbox was emptied.
func (c *Client) noteStored(macID string, id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := macID + "/"
	reset := false
	for key, after := range c.after {
		if strings.HasPrefix(key, prefix) && after >= id {
			reset = true
		}
	}
	if !reset {
		return
	}
	for key := range c.after {
		if strings.HasPrefix(key, prefix) {
			delete(c.after, key)
			delete(c.seen, key)
		}
	}
	_ = c.saveLocked()
}

// Poll reads new events of one kind.
func (c *Client) Poll(ctx context.Context, macID, kind string) ([]Event, error) {
	key := macID + "/" + kind
	c.mu.Lock()
	after := c.after[key]
	c.mu.Unlock()
	endpoint := fmt.Sprintf("%s?after=%d", c.url(macID, kind), after)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, statusError(res)
	}
	var payload page
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("relay response: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, 0, len(payload.Events))
	var maxID int64
	for _, event := range payload.Events {
		if event.Kind == "" {
			event.Kind = kind
		}
		if event.Kind != kind {
			continue
		}
		if event.ID > maxID {
			maxID = event.ID
		}
		if c.freshLocked(macID, event) {
			out = append(out, event)
		}
	}
	if maxID > c.after[key] {
		c.after[key] = maxID
		for id := range c.seen[key] {
			if id <= maxID {
				delete(c.seen[key], id)
			}
		}
		if err := c.saveLocked(); err != nil {
			return out, fmt.Errorf("relay cursor: %w", err)
		}
	}
	return out, nil
}

// freshLocked marks an event as delivered. It is false for an event that
// Poll or Watch already returned, or one with no usable id.
func (c *Client) freshLocked(macID string, event Event) bool {
	if event.ID <= 0 {
		return false
	}
	key := macID + "/" + event.Kind
	if event.ID <= c.after[key] {
		return false
	}
	ids := c.seen[key]
	if ids == nil {
		ids = map[int64]struct{}{}
		c.seen[key] = ids
	}
	if _, ok := ids[event.ID]; ok {
		return false
	}
	ids[event.ID] = struct{}{}
	if len(ids) > maxSeen {
		oldest := event.ID
		for id := range ids {
			if id < oldest {
				oldest = id
			}
		}
		delete(ids, oldest)
	}
	return true
}

func (c *Client) saveLocked() error {
	if c.cursorPath == "" {
		return nil
	}
	body, err := json.Marshal(cursorFile{BaseURL: c.BaseURL, After: c.after})
	if err != nil {
		return err
	}
	tmp := c.cursorPath + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.cursorPath)
}

// Watch opens an outbound WebSocket and calls onEvent for each new event.
// It returns when ctx is cancelled or the socket closes.
func (c *Client) Watch(ctx context.Context, macID string, onEvent func(Event)) error {
	_, err := c.watch(ctx, macID, onEvent)
	return err
}

// Listen keeps a WebSocket open, reconnecting after a drop. The wait doubles
// from RetryMin to RetryMax and resets after a successful connection.
// onError may be nil. Listen returns when ctx is cancelled.
func (c *Client) Listen(ctx context.Context, macID string, onEvent func(Event), onError func(error)) {
	shortest := c.RetryMin
	if shortest <= 0 {
		shortest = time.Second
	}
	longest := max(c.RetryMax, shortest)
	wait := shortest
	for {
		connected, err := c.watch(ctx, macID, onEvent)
		if ctx.Err() != nil {
			return
		}
		if err != nil && onError != nil {
			onError(err)
		}
		if connected {
			wait = shortest
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if !connected {
			wait = min(wait*2, longest)
		}
	}
}

func (c *Client) watch(ctx context.Context, macID string, onEvent func(Event)) (bool, error) {
	conn, _, err := websocket.Dial(ctx, c.wsURL(macID), nil)
	if err != nil {
		return false, err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 16)
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return true, nil
			}
			return true, err
		}
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		c.mu.Lock()
		fresh := c.freshLocked(macID, event)
		c.mu.Unlock()
		if fresh {
			onEvent(event)
		}
	}
}

func (c *Client) url(macID, kind string) string {
	return c.BaseURL + "/v1/macs/" + url.PathEscape(macID) + "/" + url.PathEscape(kind)
}

func (c *Client) wsURL(macID string) string {
	base := c.BaseURL
	switch {
	case strings.HasPrefix(base, "https://"):
		base = "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		base = "ws://" + strings.TrimPrefix(base, "http://")
	}
	return base + "/v1/macs/" + url.PathEscape(macID) + "/ws"
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func statusError(res *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	text := strings.TrimSpace(string(body))
	if text == "" {
		text = res.Status
	}
	return &StatusError{Path: res.Request.URL.Path, Code: res.StatusCode, Text: text}
}

// Package relay is the Mac's outbound client for the mailbox worker.
// It posts and polls. It does not accept inbound connections, and it does
// not decide whether an approval is valid.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Event is one mailbox record. Body is the JSON object the sender posted.
type Event struct {
	ID   int64           `json:"id"`
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

type page struct {
	Events []Event `json:"events"`
}

const maxBody = 4096 // Matches relay/src/mailbox.ts.
const maxResponse = 1 << 20

var macIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Client talks to one relay base URL.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	mu    sync.Mutex
	after map[string]int64
}

// New returns a client. baseURL is an http or https origin with no user info.
func New(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("relay URL must be an http or https origin without user info, path, query, or fragment")
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		after:   map[string]int64{},
	}, nil
}

// Post sends one JSON object into a mailbox. The body is stored, not run.
func (c *Client) Post(ctx context.Context, macID, kind string, body any) error {
	if err := mailboxOK(macID, kind); err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(raw) > maxBody || len(raw) == 0 || raw[0] != '{' {
		return fmt.Errorf("relay body must be a JSON object of at most %d bytes", maxBody)
	}
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
	var ack struct {
		Stored bool `json:"stored"`
	}
	if err := readJSON(res.Body, &ack); err != nil {
		return err
	}
	if !ack.Stored {
		return fmt.Errorf("relay did not store the message")
	}
	return nil
}

// Poll reads new events of one kind. The cursor stays on this client.
func (c *Client) Poll(ctx context.Context, macID, kind string) ([]Event, error) {
	if err := mailboxOK(macID, kind); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	after := c.after[macID+"/"+kind]
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
	if err := readJSON(res.Body, &payload); err != nil {
		return nil, err
	}
	if payload.Events == nil {
		return nil, fmt.Errorf("relay response must contain an events array")
	}
	maxID := after
	var events []Event
	for _, event := range payload.Events {
		if event.Kind != kind || event.ID <= 0 || len(event.Body) == 0 || event.Body[0] != '{' {
			return nil, fmt.Errorf("relay response contains an invalid mailbox event")
		}
		if event.ID <= after {
			continue
		}
		if event.ID <= maxID {
			return nil, fmt.Errorf("relay events must be ordered by id")
		}
		maxID = event.ID
		events = append(events, event)
	}
	if maxID > after {
		c.after[macID+"/"+kind] = maxID
	}
	return events, nil
}

func mailboxOK(macID, kind string) error {
	if !macIDPattern.MatchString(macID) {
		return fmt.Errorf("relay requires a 32-character lowercase hex Mac id")
	}
	switch kind {
	case "pairing", "alerts", "approvals", "results":
		return nil
	default:
		return fmt.Errorf("unknown relay mailbox %q", kind)
	}
}

func readJSON(r io.Reader, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxResponse+1))
	if err != nil {
		return fmt.Errorf("relay response: %w", err)
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("relay response is too large")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("relay response: %w", err)
	}
	return nil
}

// Watch opens an outbound WebSocket and calls onEvent for each text frame.
// It returns when ctx is cancelled or the socket closes.
func (c *Client) Watch(ctx context.Context, macID string, onEvent func(Event)) error {
	conn, _, err := websocket.Dial(ctx, c.wsURL(macID), nil)
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		onEvent(event)
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
	return fmt.Errorf("relay %s: %s", res.Request.URL.Path, text)
}

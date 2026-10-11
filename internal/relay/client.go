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
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, fmt.Errorf("relay URL must be http or https and must not include a password")
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		after:   map[string]int64{},
	}, nil
}

// Post sends one JSON object into a mailbox. The body is stored, not run.
func (c *Client) Post(ctx context.Context, macID, kind string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
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
	return nil
}

// Poll reads new events of one kind. The cursor stays on this client.
func (c *Client) Poll(ctx context.Context, macID, kind string) ([]Event, error) {
	c.mu.Lock()
	after := c.after[macID+"/"+kind]
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
	var maxID int64
	for _, event := range payload.Events {
		if event.ID > maxID {
			maxID = event.ID
		}
	}
	if maxID > after {
		c.mu.Lock()
		if maxID > c.after[macID+"/"+kind] {
			c.after[macID+"/"+kind] = maxID
		}
		c.mu.Unlock()
	}
	return payload.Events, nil
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

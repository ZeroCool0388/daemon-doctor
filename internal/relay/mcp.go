package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/coder/websocket"
)

const MCPMaxBytes = 64 * 1024

func NewMCPToken() (token, hash string, err error) {
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw[:])
	return token, MCPTokenHash(token), nil
}

func MCPTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (c *Client) RegisterMCPLink(ctx context.Context, macID, secret string, proof security.MCPLinkRegistration) error {
	return c.mcpPut(ctx, macID, "mcp-link", secret, proof)
}

func (c *Client) RegisterMCPToken(ctx context.Context, macID, secret, hash string) error {
	return c.mcpPut(ctx, macID, "mcp-token", secret, map[string]string{"token_hash": hash})
}

func (c *Client) mcpPut(ctx context.Context, macID, route, secret string, body any) error {
	if !macIDPattern.MatchString(macID) {
		return fmt.Errorf("invalid Mac id")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.url(macID, route), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// Do not echo an untrusted response body that could contain the credential.
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("relay %s: HTTP %d", route, res.StatusCode)
	}
	var ack struct {
		Registered bool `json:"registered"`
	}
	if err := readJSON(res.Body, &ack); err != nil {
		return fmt.Errorf("invalid relay registration response")
	}
	if !ack.Registered {
		return fmt.Errorf("relay did not register credential")
	}
	return nil
}

type linkSocket interface {
	Read(context.Context) (websocket.MessageType, []byte, error)
	Write(context.Context, websocket.MessageType, []byte) error
	CloseNow() error
}

type linkDial func(context.Context, string, *websocket.DialOptions) (linkSocket, error)

// MCPLink only dials outward. Dispatch uses the same MCP server as stdio.
type MCPLink struct {
	Client                        *Client
	MacID, Secret                 string
	Registration                  security.MCPLinkRegistration
	Dispatch                      func(context.Context, json.RawMessage, http.Header) json.RawMessage
	dial                          linkDial
	heartbeat, retryMin, retryMax time.Duration
}

func (l *MCPLink) Run(ctx context.Context, onError func(error)) {
	min, max := l.retryMin, l.retryMax
	if min <= 0 {
		min = time.Second
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	delay := min
	for ctx.Err() == nil {
		started := time.Now()
		regCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := l.Client.RegisterMCPLink(regCtx, l.MacID, l.Secret, l.Registration)
		cancel()
		if err == nil {
			err = l.connect(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && onError != nil {
			onError(fmt.Errorf("MCP link disconnected"))
		}
		if time.Since(started) >= time.Minute {
			delay = min
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay *= 2
		if delay > max {
			delay = max
		}
	}
}

func (l *MCPLink) connect(parent context.Context) error {
	dial := l.dial
	if dial == nil {
		dial = func(ctx context.Context, endpoint string, opts *websocket.DialOptions) (linkSocket, error) {
			conn, res, err := websocket.Dial(ctx, endpoint, opts)
			if res != nil && res.Body != nil {
				res.Body.Close()
			}
			if err != nil {
				return nil, err
			}
			conn.SetReadLimit(MCPMaxBytes + 1024)
			return conn, nil
		}
	}
	endpoint := strings.TrimSuffix(l.Client.wsURL(l.MacID), "/ws") + "/mcp-link"
	dialCtx, cancelDial := context.WithTimeout(parent, 15*time.Second)
	conn, err := dial(dialCtx, endpoint, &websocket.DialOptions{HTTPClient: l.Client.http(), HTTPHeader: http.Header{"Authorization": {"Bearer " + l.Secret}}})
	cancelDial()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer conn.CloseNow()
	defer cancel()
	beat := l.heartbeat
	if beat <= 0 {
		beat = 30 * time.Second
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	// Cancel and close before waiting for request workers.
	defer func() { cancel(); conn.CloseNow() }()
	pong := make(chan time.Time, 1)
	slots := make(chan struct{}, 16)
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(beat)
		defer ticker.Stop()
		lastPong := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-pong:
				lastPong = at
			case <-ticker.C:
				if time.Since(lastPong) > 3*beat {
					cancel()
					conn.CloseNow()
					return
				}
				writeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Write(writeCtx, websocket.MessageText, []byte(`{"type":"ping"}`))
				stop()
				if err != nil {
					cancel()
					conn.CloseNow()
					return
				}
			}
		}
	}()
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageText || len(data) > MCPMaxBytes+1024 {
			return fmt.Errorf("invalid MCP frame")
		}
		var frame struct {
			ID              string            `json:"id"`
			Request         json.RawMessage   `json:"request"`
			Type            string            `json:"type"`
			MCPHeaders      map[string]string `json:"mcp_headers"`
			ProtocolVersion string            `json:"protocol_version"`
			DeadlineUnixMS  int64             `json:"deadline_unix_ms"`
		}
		if json.Unmarshal(data, &frame) != nil {
			continue
		}
		if frame.Type == "pong" {
			select {
			case pong <- time.Now():
			default:
			}
			continue
		}
		if frame.ID == "" || len(frame.ID) > 128 || len(frame.Request) == 0 {
			continue
		}
		// Bound concurrent requests and stop accepting work when the link closes.
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		workers.Add(1)
		deadline := time.Now().Add(14 * time.Second)
		if frame.DeadlineUnixMS > 0 {
			remoteDeadline := time.UnixMilli(frame.DeadlineUnixMS)
			if remoteDeadline.Before(deadline) {
				deadline = remoteDeadline
			}
		}
		headers := make(http.Header)
		if frame.ProtocolVersion != "" {
			headers.Set("MCP-Protocol-Version", frame.ProtocolVersion)
		}
		for name, value := range frame.MCPHeaders {
			key := strings.ToLower(name)
			if key == "mcp-method" || key == "mcp-name" || strings.HasPrefix(key, "mcp-param-") {
				headers.Set(name, value)
			}
		}
		go func(id string, request json.RawMessage, headers http.Header, deadline time.Time) {
			defer workers.Done()
			defer func() { <-slots }()
			callCtx, stop := context.WithDeadline(ctx, deadline)
			defer stop()
			if callCtx.Err() != nil {
				return
			}
			reply := l.Dispatch(callCtx, request, headers)
			if len(reply) == 0 || callCtx.Err() != nil {
				return
			}
			raw, err := json.Marshal(struct {
				ID       string          `json:"id"`
				Response json.RawMessage `json:"response"`
			}{id, reply})
			if err == nil && len(raw) <= MCPMaxBytes+1024 {
				writeCtx, stopWrite := context.WithTimeout(ctx, 5*time.Second)
				defer stopWrite()
				if conn.Write(writeCtx, websocket.MessageText, raw) != nil {
					cancel()
					conn.CloseNow()
				}
			}
		}(frame.ID, frame.Request, headers, deadline)
	}
}

// Package notify publishes optional, outbound-only phone notifications.
package notify

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
)

const DefaultServer = "https://ntfy.sh"
const SendTimeout = 2 * time.Second

var topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Config struct {
	Server  string `yaml:"server" toml:"server"`
	Topic   string `yaml:"topic" toml:"topic"`
	Enabled bool   `yaml:"enabled" toml:"enabled"`
}

// Prevent accidental topic disclosure when a config is formatted for diagnostics.
func (c Config) String() string   { return fmt.Sprintf("ntfy(enabled=%t, topic=[private])", c.Enabled) }
func (c Config) GoString() string { return c.String() }

func (c Config) Clean() (Config, error) {
	c.Server = strings.TrimRight(strings.TrimSpace(c.Server), "/")
	if c.Server == "" {
		c.Server = DefaultServer
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return Config{}, errors.New("notify.ntfy.server must be an http or https origin without credentials, path, query or fragment")
	}
	if c.Topic != "" && !topicPattern.MatchString(c.Topic) {
		return Config{}, errors.New("notify.ntfy.topic must contain 1 to 64 letters, numbers, underscores or dashes")
	}
	if c.Enabled && c.Topic == "" {
		return Config{}, errors.New("notify.ntfy.topic is required when enabled; run ntfy-setup")
	}
	return c, nil
}

func GenerateTopic() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("could not generate ntfy topic")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

type Event struct{ ServiceName, State, Message string }
type Sender interface {
	Send(context.Context, Event) error
}
type Ntfy struct {
	config Config
	HTTP   *http.Client
}

// New returns nil for disabled notifications. It never contacts the server.
func New(raw Config) (*Ntfy, error) {
	cfg, err := raw.Clean()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	return &Ntfy{config: cfg, HTTP: &http.Client{Timeout: SendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (n *Ntfy) Send(ctx context.Context, event Event) error {
	name := n.cleanText(event.ServiceName, 80)
	if name == "" {
		name = "A watched service"
	}
	var message string
	switch event.State {
	case "down":
		message = name + " is down. It is not running."
	case "stuck":
		message = name + " looks stuck. It is running but not responding as expected."
	case "ok":
		message = name + " has recovered and looks healthy."
	case "alert":
		if strings.TrimSpace(event.Message) == "" {
			return errors.New("phone notification alert requires a message")
		}
	default:
		return errors.New("unsupported phone notification state")
	}
	if event.Message != "" && (event.State == "alert" || event.State == "ok") {
		message = n.cleanText(event.Message, 1024)
	}
	sendCtx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, n.config.Server+"/"+n.config.Topic, strings.NewReader(message))
	if err != nil {
		return errors.New("ntfy delivery failed")
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", "Daemon Doctor")
	// Refuse redirects even if an injected client would otherwise follow them.
	client := n.HTTP
	if client == nil {
		client = &http.Client{Timeout: SendTimeout}
	}
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := safe.Do(req)
	if err != nil {
		return errors.New("ntfy delivery failed")
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("ntfy delivery failed")
	}
	return nil
}

func (n *Ntfy) cleanText(raw string, limit int) string {
	text := logbook.Blank(strings.ReplaceAll(raw, n.config.Topic, "[private]"))
	text = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text))
	chars := []rune(text)
	if len(chars) > limit {
		text = string(chars[:limit])
	}
	return text
}

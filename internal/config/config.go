// Package config reads the local daemon-doctor config file.
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"gopkg.in/yaml.v3"
)

// Config is the on-disk program config.
// RelayURL is optional. An empty value keeps the program local.
type Config struct {
	PluginsDir        string
	LogPath           string
	Interval          time.Duration
	RelayURL          string
	StateDir          string
	ControlEnabled    bool
	ControlAllowFixes bool
	ControlSocket     string
}

type controlConfig struct {
	Enabled    *bool `yaml:"enabled" toml:"enabled"`
	AllowFixes bool  `yaml:"allow_fixes" toml:"allow_fixes"`
}

type file struct {
	Control    *controlConfig `yaml:"control" toml:"control"`
	PluginsDir string         `yaml:"plugins_dir" toml:"plugins_dir"`
	LogPath    string         `yaml:"log_path" toml:"log_path"`
	Interval   string         `yaml:"interval" toml:"interval"`
	RelayURL   string         `yaml:"relay_url" toml:"relay_url"`
	Relay      *relayConfig   `yaml:"relay" toml:"relay"`
	StateDir   string         `yaml:"state_dir" toml:"state_dir"`
}

type relayConfig struct {
	URL string `yaml:"url" toml:"url"`
}

// Load reads a YAML or TOML config. Relative paths are resolved from the
// directory that contains the file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var raw file
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&raw); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
		var extra yaml.Node
		if err := dec.Decode(&extra); err != io.EOF {
			if err == nil {
				return Config{}, fmt.Errorf("parse config: file contains more than one document")
			}
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	case ".toml":
		md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			return Config{}, fmt.Errorf("parse config: unknown field %s", undecoded[0])
		}
	default:
		return Config{}, fmt.Errorf("config %s must be .yaml, .yml, or .toml", path)
	}
	if strings.TrimSpace(raw.PluginsDir) == "" {
		return Config{}, fmt.Errorf("plugins_dir is required")
	}
	if strings.TrimSpace(raw.LogPath) == "" {
		return Config{}, fmt.Errorf("log_path is required")
	}
	if strings.TrimSpace(raw.Interval) == "" {
		return Config{}, fmt.Errorf("interval is required")
	}
	interval, err := time.ParseDuration(raw.Interval)
	if err != nil {
		return Config{}, fmt.Errorf("interval: %w", err)
	}
	if interval <= 0 {
		return Config{}, fmt.Errorf("interval must be positive")
	}
	base, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	dir := filepath.Dir(base)
	if raw.Relay != nil {
		if raw.RelayURL != "" {
			return Config{}, fmt.Errorf("use relay.url only; remove relay_url")
		}
		raw.RelayURL = raw.Relay.URL
	}
	relayURL, err := cleanRelayURL(raw.RelayURL)
	if err != nil {
		return Config{}, err
	}
	stateDir := dir
	if strings.TrimSpace(raw.StateDir) != "" {
		stateDir = resolve(dir, raw.StateDir)
	}
	enabled, allowFixes := true, false
	if raw.Control != nil {
		if raw.Control.Enabled != nil {
			enabled = *raw.Control.Enabled
		}
		allowFixes = raw.Control.AllowFixes
	}
	return Config{
		ControlEnabled: enabled, ControlAllowFixes: allowFixes, ControlSocket: filepath.Join(stateDir, "control", "control.sock"),
		PluginsDir: resolve(dir, raw.PluginsDir),
		LogPath:    resolve(dir, raw.LogPath),
		Interval:   interval,
		RelayURL:   relayURL,
		StateDir:   stateDir,
	}, nil
}

func cleanRelayURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	client, err := relay.New(raw)
	if err != nil {
		return "", fmt.Errorf("relay.url: %w", err)
	}
	return client.BaseURL, nil
}

func resolve(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

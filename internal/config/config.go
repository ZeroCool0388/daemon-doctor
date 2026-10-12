// Package config reads the local daemon-doctor config file.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Config is the on-disk program config.
// RelayURL is optional. An empty value keeps the program local.
type Config struct {
	PluginsDir string
	LogPath    string
	Interval   time.Duration
	RelayURL   string
	StateDir   string
}

type file struct {
	PluginsDir string `yaml:"plugins_dir" toml:"plugins_dir"`
	LogPath    string `yaml:"log_path" toml:"log_path"`
	Interval   string `yaml:"interval" toml:"interval"`
	RelayURL   string `yaml:"relay_url" toml:"relay_url"`
	StateDir   string `yaml:"state_dir" toml:"state_dir"`
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
	relayURL, err := cleanRelayURL(raw.RelayURL)
	if err != nil {
		return Config{}, err
	}
	stateDir := dir
	if strings.TrimSpace(raw.StateDir) != "" {
		stateDir = resolve(dir, raw.StateDir)
	}
	return Config{
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
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("relay_url must be an http or https URL")
	}
	if u.User != nil {
		return "", fmt.Errorf("relay_url must not include a user or password")
	}
	return u.String(), nil
}

func resolve(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

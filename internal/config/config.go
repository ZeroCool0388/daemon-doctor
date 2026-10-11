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
	"gopkg.in/yaml.v3"
)

// Config is the on-disk program config. It holds paths only.
type Config struct {
	PluginsDir string
	LogPath    string
	Interval   time.Duration
}

type file struct {
	PluginsDir string `yaml:"plugins_dir" toml:"plugins_dir"`
	LogPath    string `yaml:"log_path" toml:"log_path"`
	Interval   string `yaml:"interval" toml:"interval"`
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
	return Config{
		PluginsDir: resolve(dir, raw.PluginsDir),
		LogPath:    resolve(dir, raw.LogPath),
		Interval:   interval,
	}, nil
}

func resolve(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

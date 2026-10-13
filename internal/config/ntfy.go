package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ZeroCool0388/daemon-doctor/internal/notify"
	"gopkg.in/yaml.v3"
)

// SetupNtfy is invoked explicitly by the local setup command. The topic is
// written only to the private config, never to a checkout, log or sidecar file.
func SetupNtfy(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("could not locate local config")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("could not read local config")
	}
	if inCheckout(absolute) || inCheckout(resolved) {
		return "", errors.New("ntfy-setup requires a local config outside a Git checkout")
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", errors.New("could not read local config")
	}
	topic, err := notify.GenerateTopic()
	if err != nil {
		return "", err
	}
	var encoded []byte
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		encoded, err = setupYAML(data, topic)
	case ".toml":
		encoded, err = setupTOML(data, topic)
	default:
		return "", errors.New("local config must be YAML or TOML")
	}
	if err != nil {
		return "", errors.New("could not update ntfy configuration")
	}
	cfg, err := loadData(path, encoded)
	if err != nil {
		return "", errors.New("local config is invalid; ntfy setup was not saved")
	}
	f, err := os.CreateTemp(filepath.Dir(resolved), ".ntfy-config-*")
	if err != nil {
		return "", errors.New("could not save local config")
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", errors.New("could not save local config")
	}
	if err = os.Rename(temp, resolved); err != nil {
		return "", errors.New("could not save local config")
	}
	return cfg.Ntfy.Server + "/" + cfg.Ntfy.Topic, nil
}

func inCheckout(path string) bool {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		} else if !os.IsNotExist(err) {
			return true
		}
		if filepath.Dir(dir) == dir {
			return false
		}
	}
}

func setupYAML(data []byte, topic string) ([]byte, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("one document required")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config mapping required")
	}
	ntfy, err := yamlMapping(doc.Content[0], "notify")
	if err != nil {
		return nil, err
	}
	ntfy, err = yamlMapping(ntfy, "ntfy")
	if err != nil {
		return nil, err
	}
	setYAMLScalar(ntfy, "topic", topic, "!!str")
	setYAMLScalar(ntfy, "enabled", "true", "!!bool")
	if yamlValue(ntfy, "server") == nil {
		setYAMLScalar(ntfy, "server", notify.DefaultServer, "!!str")
	}
	return yaml.Marshal(&doc)
}
func yamlValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
func yamlMapping(node *yaml.Node, key string) (*yaml.Node, error) {
	value := yamlValue(node, key)
	if value == nil {
		value = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
	}
	if value.Kind != yaml.MappingNode {
		return nil, errors.New("config mapping required")
	}
	return value, nil
}
func setYAMLScalar(node *yaml.Node, key, value, tag string) {
	scalar := yamlValue(node, key)
	if scalar == nil {
		scalar = &yaml.Node{}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, scalar)
	}
	scalar.Style = 0
	scalar.Kind = yaml.ScalarNode
	scalar.Tag = tag
	scalar.Value = value
	scalar.Content = nil
}
func setupTOML(data []byte, topic string) ([]byte, error) {
	var values map[string]any
	if _, err := toml.Decode(string(data), &values); err != nil {
		return nil, err
	}
	ntfy, err := tomlMap(values, "notify")
	if err != nil {
		return nil, err
	}
	ntfy, err = tomlMap(ntfy, "ntfy")
	if err != nil {
		return nil, err
	}
	ntfy["topic"] = topic
	ntfy["enabled"] = true
	if _, ok := ntfy["server"]; !ok {
		ntfy["server"] = notify.DefaultServer
	}
	var out bytes.Buffer
	if err := toml.NewEncoder(&out).Encode(values); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func tomlMap(parent map[string]any, key string) (map[string]any, error) {
	if value, ok := parent[key]; ok {
		if table, ok := value.(map[string]any); ok {
			return table, nil
		}
		return nil, errors.New("config table required")
	}
	table := map[string]any{}
	parent[key] = table
	return table, nil
}

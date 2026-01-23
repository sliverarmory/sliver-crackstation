package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConnectConfig struct {
	OperatorConfig string   `yaml:"operatorConfig"`
	Args           []string `yaml:"args"`
}

type Config struct {
	Connect ConnectConfig `yaml:"connect"`
}

func DefaultPath(appDir string) string {
	return filepath.Join(appDir, "config.yml")
}

func LoadDefault(appDir string) (*Config, string, error) {
	path := DefaultPath(appDir)
	cfg, err := Load(path)
	return cfg, path, err
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) ConnectArgs() ([]string, error) {
	if c == nil {
		return nil, errors.New("config is nil")
	}
	args := make([]string, 0, len(c.Connect.Args)+2)
	if c.Connect.OperatorConfig != "" && !hasConfigFlag(c.Connect.Args) {
		args = append(args, "--config", c.Connect.OperatorConfig)
	}
	args = append(args, c.Connect.Args...)
	return args, nil
}

func hasConfigFlag(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" || args[i] == "-c" {
			return true
		}
		if strings.HasPrefix(args[i], "--config=") {
			return true
		}
	}
	return false
}

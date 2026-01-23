package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ConnectConfig struct {
	OperatorConfig                   string         `yaml:"operatorConfig"`
	Args                             []string       `yaml:"args"`
	ForceBenchmark                   bool           `yaml:"forceBenchmark"`
	GrpcKeepaliveTime                *time.Duration `yaml:"grpcKeepaliveTime"`
	GrpcKeepaliveTimeout             *time.Duration `yaml:"grpcKeepaliveTimeout"`
	GrpcKeepalivePermitWithoutStream *bool          `yaml:"grpcKeepalivePermitWithoutStream"`
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
	if c.Connect.ForceBenchmark && !hasFlag(c.Connect.Args, "--force-benchmark") {
		args = append(args, "--force-benchmark")
	}
	if c.Connect.GrpcKeepaliveTime != nil && !hasFlag(c.Connect.Args, "--grpc-keepalive-time") {
		args = append(args, "--grpc-keepalive-time", c.Connect.GrpcKeepaliveTime.String())
	}
	if c.Connect.GrpcKeepaliveTimeout != nil && !hasFlag(c.Connect.Args, "--grpc-keepalive-timeout") {
		args = append(args, "--grpc-keepalive-timeout", c.Connect.GrpcKeepaliveTimeout.String())
	}
	if c.Connect.GrpcKeepalivePermitWithoutStream != nil && !hasFlag(c.Connect.Args, "--grpc-keepalive-permit-without-stream") {
		args = append(args, "--grpc-keepalive-permit-without-stream", strconv.FormatBool(*c.Connect.GrpcKeepalivePermitWithoutStream))
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

func hasFlag(args []string, flag string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			return true
		}
		if strings.HasPrefix(args[i], flag+"=") {
			return true
		}
	}
	return false
}

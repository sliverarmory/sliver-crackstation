package operatorconfig

import (
	"encoding/json"
	"fmt"
	"os"
)

// ClientWGConfig holds the optional WireGuard wrapper parameters for a
// multiplayer client connection.
type ClientWGConfig struct {
	ServerPubKey     string `json:"server_pub_key"`
	ClientPrivateKey string `json:"client_private_key"`
	ClientPubKey     string `json:"client_pub_key"`
	ClientIP         string `json:"client_ip"`
	ServerIP         string `json:"server_ip"`
}

// ClientConfig mirrors the Sliver operator config format used by crackstation.
type ClientConfig struct {
	Operator      string          `json:"operator"`
	LHost         string          `json:"lhost"`
	LPort         int             `json:"lport"`
	Token         string          `json:"token"`
	CACertificate string          `json:"ca_certificate"`
	PrivateKey    string          `json:"private_key"`
	Certificate   string          `json:"certificate"`
	WG            *ClientWGConfig `json:"wg,omitempty"`
}

// ReadConfig loads an operator config from disk.
func ReadConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf := &ClientConfig{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("parse operator config: %w", err)
	}
	return conf, nil
}

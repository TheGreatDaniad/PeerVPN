package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Config holds the configuration for the PeerVPN application
type Config struct {
	// Node identification
	PeerID           string `json:"peer_id"`
	WireguardPrivKey string `json:"wireguard_priv_key"`
	WireguardPubKey  string `json:"wireguard_pub_key"`

	// Network configuration
	WireguardPort    int      `json:"wireguard_port"`
	WireguardAddress string   `json:"wireguard_address"`
	StunServers      []string `json:"stun_servers"`

	// Mode configuration
	IsExitNode bool `json:"is_exit_node"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		WireguardPort:    51820,
		WireguardAddress: "10.0.0.1/24",
		StunServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun2.l.google.com:19302",
			"stun3.l.google.com:19302",
		},
		IsExitNode: false,
	}
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveToFile saves the configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0600)
}

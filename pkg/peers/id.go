package peers

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// PeerInfo holds information about a peer
type PeerInfo struct {
	PeerID         string `json:"peer_id"`
	PublicKey      string `json:"public_key"`
	Endpoint       string `json:"endpoint,omitempty"`
	AllowedSubnets string `json:"allowed_subnets,omitempty"`
	IsExitNode     bool   `json:"is_exit_node"`
}

// GeneratePeerID generates a unique, human-readable ID for a peer
func GeneratePeerID() (string, error) {
	// Generate 6 bytes of random data (48 bits)
	randomBytes := make([]byte, 6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Convert to a numerical format with separators
	// Format will be XXX-XXX-XXX (3 groups of 3 digits)
	numericID := ""
	for i, b := range randomBytes {
		numericID += fmt.Sprintf("%03d", int(b))
		if i < len(randomBytes)-1 && (i+1)%2 == 0 {
			numericID += "-"
		}
	}

	return numericID, nil
}

// GeneratePeerIDFromKey generates a consistent ID from a WireGuard public key
func GeneratePeerIDFromKey(publicKey string) string {
	// Hash the public key
	hash := sha256.Sum256([]byte(publicKey))

	// Take the first 6 bytes of the hash
	idBytes := hash[:6]

	// Convert to a numerical format with separators
	numericID := ""
	for i, b := range idBytes {
		numericID += fmt.Sprintf("%03d", int(b))
		if i < len(idBytes)-1 && (i+1)%2 == 0 {
			numericID += "-"
		}
	}

	return numericID
}

// ReadLocalPeerInfo reads the local peer info from a file
func ReadLocalPeerInfo(filePath string) (*PeerInfo, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("peer info file does not exist: %s", filePath)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read peer info file: %v", err)
	}

	// Parse the file content
	lines := strings.Split(string(data), "\n")
	info := &PeerInfo{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "peer_id":
			info.PeerID = value
		case "public_key":
			info.PublicKey = value
		case "endpoint":
			info.Endpoint = value
		case "allowed_subnets":
			info.AllowedSubnets = value
		case "is_exit_node":
			info.IsExitNode = value == "true"
		}
	}

	// Validate required fields
	if info.PeerID == "" || info.PublicKey == "" {
		return nil, fmt.Errorf("peer info file is missing required fields")
	}

	return info, nil
}

// WriteLocalPeerInfo writes the local peer info to a file
func WriteLocalPeerInfo(filePath string, info *PeerInfo) error {
	// Create the file content
	var builder strings.Builder

	builder.WriteString("# PeerVPN peer information\n")
	builder.WriteString(fmt.Sprintf("peer_id=%s\n", info.PeerID))
	builder.WriteString(fmt.Sprintf("public_key=%s\n", info.PublicKey))

	if info.Endpoint != "" {
		builder.WriteString(fmt.Sprintf("endpoint=%s\n", info.Endpoint))
	}

	if info.AllowedSubnets != "" {
		builder.WriteString(fmt.Sprintf("allowed_subnets=%s\n", info.AllowedSubnets))
	}

	builder.WriteString(fmt.Sprintf("is_exit_node=%t\n", info.IsExitNode))

	// Write to file
	err := os.WriteFile(filePath, []byte(builder.String()), 0600)
	if err != nil {
		return fmt.Errorf("failed to write peer info file: %v", err)
	}

	return nil
}

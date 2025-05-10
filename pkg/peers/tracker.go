package peers

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danialdehvan/PeerVPN/pkg/wireguard"
)

// PeerStats represents stats for a connected peer
type PeerStats struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	BytesReceived uint64
	BytesSent     uint64
	LastUpdate    time.Time
}

// ConnTracker tracks connected peers and their statistics
type ConnTracker struct {
	interfaceName string
	peers         map[string]*PeerStats
	mutex         sync.RWMutex
	stopChan      chan struct{}
}

// NewConnTracker creates a new connection tracker for the specified interface
func NewConnTracker(interfaceName string) *ConnTracker {
	return &ConnTracker{
		interfaceName: interfaceName,
		peers:         make(map[string]*PeerStats),
		stopChan:      make(chan struct{}),
	}
}

// StartTracking begins tracking peer connections and stats
func (ct *ConnTracker) StartTracking(interval time.Duration, callback func([]*PeerStats)) {
	// First perform an immediate check
	initialStats := ct.UpdateStats()
	if callback != nil && len(initialStats) > 0 {
		callback(initialStats)
	} else {
		fmt.Println("Connection tracker: No peers initially detected")
	}

	// Then do some fast checks at first (every second for 10 seconds)
	go func() {
		// Initial fast polling to detect connections quickly
		fastTicker := time.NewTicker(1 * time.Second)
		defer fastTicker.Stop()

		fmt.Println("Connection tracker: Starting fast connection detection...")
		startTime := time.Now()

		for time.Since(startTime) < 10*time.Second {
			select {
			case <-fastTicker.C:
				stats := ct.UpdateStats()
				if len(stats) > 0 {
					fmt.Printf("Connection tracker: Found %d peers during fast detection\n", len(stats))
					if callback != nil {
						callback(stats)
					}
				}
			case <-ct.stopChan:
				return
			}
		}
		fmt.Println("Connection tracker: Switching to normal polling interval...")
	}()

	// Then continue with the regular interval
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				stats := ct.UpdateStats()
				if callback != nil && len(stats) > 0 {
					callback(stats)
				}
			case <-ct.stopChan:
				return
			}
		}
	}()
}

// StopTracking stops the tracking goroutine
func (ct *ConnTracker) StopTracking() {
	close(ct.stopChan)
}

// UpdateStats updates the statistics for all connected peers
func (ct *ConnTracker) UpdateStats() []*PeerStats {
	// Use the BinaryPath function to locate the wg tool
	wgBinary := wireguard.BinaryPath("wg")

	// Use the right binary path
	output, err := exec.Command(wgBinary, "show", ct.interfaceName, "dump").Output()
	if err != nil {
		// Log the error to help diagnose issues
		fmt.Printf("Connection tracker: Error getting WireGuard stats: %v\n", err)
		return []*PeerStats{}
	}

	// Debug: Print raw output to help diagnose issues
	if os.Getenv("PEERVPN_DEBUG") == "1" {
		fmt.Printf("Connection tracker: Raw WireGuard output: %s\n", string(output))
	}

	// If there's no output or it's too short, try getting more info with a different command
	if len(output) < 10 {
		fmt.Println("Connection tracker: Using alternate method to get peer info...")
		altOutput, altErr := exec.Command(wgBinary, "show", ct.interfaceName).Output()
		if altErr == nil && len(altOutput) > 0 {
			fmt.Printf("Connection tracker: Alternate output:\n%s\n", string(altOutput))
		}
	}

	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	// Track which peers are still connected
	currentPeers := make(map[string]bool)

	// Parse the output
	lines := strings.Split(string(output), "\n")
	var updatedStats []*PeerStats

	// Skip the first line as it contains interface info
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 7 {
			// This might be a partial line or error
			fmt.Printf("Connection tracker: Skipping incomplete line: %s\n", line)
			continue
		}

		// Fields: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx
		publicKey := fields[0]
		endpoint := fields[2]
		latestHandshake, _ := strconv.ParseInt(fields[4], 10, 64)
		bytesReceived, _ := strconv.ParseUint(fields[5], 10, 64)
		bytesSent, _ := strconv.ParseUint(fields[6], 10, 64)

		currentPeers[publicKey] = true

		// Check if peer already exists
		peer, exists := ct.peers[publicKey]
		if !exists {
			// New peer connection
			fmt.Printf("Connection tracker: New peer detected with key %s at endpoint %s\n",
				publicKey[:8]+"...", endpoint)
			peer = &PeerStats{
				PublicKey: publicKey,
				Endpoint:  endpoint,
			}
			ct.peers[publicKey] = peer
		}

		// Update stats
		handshakeTime := time.Unix(latestHandshake, 0)
		wasNewHandshake := peer.LastHandshake.Before(handshakeTime)

		// Check if the endpoint changed
		if exists && peer.Endpoint != endpoint && endpoint != "(none)" {
			fmt.Printf("Connection tracker: Peer endpoint changed from %s to %s\n",
				peer.Endpoint, endpoint)
		}

		// Log traffic changes
		if exists && (bytesReceived > peer.BytesReceived || bytesSent > peer.BytesSent) {
			rxDelta := bytesReceived - peer.BytesReceived
			txDelta := bytesSent - peer.BytesSent

			if rxDelta > 0 || txDelta > 0 {
				fmt.Printf("Connection tracker: Traffic with peer %s: +%s received, +%s sent\n",
					endpoint, FormatTrafficBytes(rxDelta), FormatTrafficBytes(txDelta))
			}
		}

		// Show handshake status
		if wasNewHandshake {
			sinceLastHandshake := time.Since(handshakeTime)
			fmt.Printf("Connection tracker: Peer %s handshake %s ago\n",
				endpoint, humanDuration(sinceLastHandshake))
		}

		peer.Endpoint = endpoint
		peer.LastHandshake = handshakeTime
		peer.BytesReceived = bytesReceived
		peer.BytesSent = bytesSent
		peer.LastUpdate = time.Now()

		// Add to list of updated stats
		updatedStats = append(updatedStats, peer)

		// Detect new connections or reconnections
		if wasNewHandshake && !exists {
			// This is a newly connected peer
			fmt.Printf("\n[%s] New peer connected: %s\n", time.Now().Format("15:04:05"), endpoint)
		} else if wasNewHandshake && exists && peer.Endpoint != endpoint {
			// This is a reconnection with a different endpoint
			fmt.Printf("\n[%s] Peer reconnected: %s (previously %s)\n",
				time.Now().Format("15:04:05"), endpoint, peer.Endpoint)
		}
	}

	// Detect and report disconnected peers
	for key, peer := range ct.peers {
		if !currentPeers[key] {
			fmt.Printf("\n[%s] Peer disconnected: %s\n", time.Now().Format("15:04:05"), peer.Endpoint)
			delete(ct.peers, key)
		}
	}

	return updatedStats
}

// GetConnectedPeers returns all currently connected peers
func (ct *ConnTracker) GetConnectedPeers() []*PeerStats {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	peers := make([]*PeerStats, 0, len(ct.peers))
	for _, peer := range ct.peers {
		peers = append(peers, peer)
	}

	return peers
}

// FormatTrafficBytes formats bytes into a human-readable string
func FormatTrafficBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// humanDuration formats a duration into a human-readable string
func humanDuration(d time.Duration) string {
	if d.Hours() > 24 {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days", days)
	} else if d.Hours() >= 1 {
		return fmt.Sprintf("%.1f hours", d.Hours())
	} else if d.Minutes() >= 1 {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	} else {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	}
}

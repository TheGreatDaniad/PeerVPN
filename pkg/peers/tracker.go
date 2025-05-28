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
	}

	// Then do some fast checks at first (every second for 10 seconds)
	go func() {
		// Initial fast polling to detect connections quickly
		fastTicker := time.NewTicker(1 * time.Second)
		defer fastTicker.Stop()

		// Only show this in debug mode
		if os.Getenv("PEERVPN_DEBUG") == "1" {
			fmt.Println("Connection tracker: Starting fast connection detection...")
		}
		startTime := time.Now()

		for time.Since(startTime) < 10*time.Second {
			select {
			case <-fastTicker.C:
				stats := ct.UpdateStats()
				if len(stats) > 0 && callback != nil {
					callback(stats)
				}
			case <-ct.stopChan:
				return
			}
		}
		// Only show this in debug mode
		if os.Getenv("PEERVPN_DEBUG") == "1" {
			fmt.Println("Connection tracker: Switching to normal polling interval...")
		}
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
	wgBinary := wireguard.BinaryPath("wg")

	// Capture raw WireGuard dump output for connection analysis
	output, err := exec.Command(wgBinary, "show", ct.interfaceName, "dump").Output()
	if err != nil {
		// Only log errors if debug mode is enabled
		if os.Getenv("PEERVPN_DEBUG") == "1" {
			fmt.Printf("Connection tracker: Error getting WireGuard stats: %v\n", err)
		}
		return []*PeerStats{}
	}

	// Debug: Print raw output to help diagnose issues (only in debug mode)
	if os.Getenv("PEERVPN_DEBUG") == "1" {
		fmt.Printf("Connection tracker: Raw WireGuard output: %s\n", string(output))
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
			// Only log incomplete lines in debug mode
			if os.Getenv("PEERVPN_DEBUG") == "1" {
				fmt.Printf("Connection tracker: Skipping incomplete line: %s\n", line)
			}
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
			// New peer connection - this is important to show
			fmt.Printf("[%s] 🔗 New peer connected: %s (key: %s...)\n",
				time.Now().Format("15:04:05"), endpoint, publicKey[:8])
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
			fmt.Printf("[%s] 📍 Peer endpoint changed: %s -> %s\n",
				time.Now().Format("15:04:05"), peer.Endpoint, endpoint)
		}

		// Log significant traffic changes (only if substantial)
		if exists && (bytesReceived > peer.BytesReceived || bytesSent > peer.BytesSent) {
			rxDelta := bytesReceived - peer.BytesReceived
			txDelta := bytesSent - peer.BytesSent

			// Only log if there's meaningful traffic (>1KB change)
			if rxDelta > 1024 || txDelta > 1024 {
				fmt.Printf("[%s] 📊 Traffic with %s: ↓%s ↑%s\n",
					time.Now().Format("15:04:05"), endpoint,
					FormatTrafficBytes(rxDelta), FormatTrafficBytes(txDelta))
			}
		}

		// Show successful handshakes
		if wasNewHandshake && latestHandshake > 0 {
			fmt.Printf("[%s] ✅ Handshake successful with %s\n",
				time.Now().Format("15:04:05"), endpoint)
		}

		peer.Endpoint = endpoint
		peer.LastHandshake = handshakeTime
		peer.BytesReceived = bytesReceived
		peer.BytesSent = bytesSent
		peer.LastUpdate = time.Now()

		// Add to list of updated stats
		updatedStats = append(updatedStats, peer)
	}

	// Detect and report disconnected peers
	for key, peer := range ct.peers {
		if !currentPeers[key] {
			fmt.Printf("[%s] ❌ Peer disconnected: %s\n",
				time.Now().Format("15:04:05"), peer.Endpoint)
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

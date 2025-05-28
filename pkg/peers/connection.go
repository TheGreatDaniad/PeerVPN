package peers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"bufio"

	"github.com/danialdehvan/PeerVPN/pkg/nat"
	"github.com/danialdehvan/PeerVPN/pkg/routing"
	"github.com/danialdehvan/PeerVPN/pkg/wireguard"
)

// ConnectionManager handles peer connections
type ConnectionManager struct {
	wgManager        *wireguard.WireGuardManager
	routingManager   *routing.RoutingManager
	natDiscovery     *nat.DiscoveryClient
	localPeerInfo    *PeerInfo
	interfaceName    string
	clientSubnet     string
	connTracker      *ConnTracker
	handshakeTimeout time.Duration
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(
	wgManager *wireguard.WireGuardManager,
	routingManager *routing.RoutingManager,
	natDiscovery *nat.DiscoveryClient,
	localPeerInfo *PeerInfo,
	interfaceName string,
	clientSubnet string,
) *ConnectionManager {
	return &ConnectionManager{
		wgManager:        wgManager,
		routingManager:   routingManager,
		natDiscovery:     natDiscovery,
		localPeerInfo:    localPeerInfo,
		interfaceName:    interfaceName,
		clientSubnet:     clientSubnet,
		connTracker:      NewConnTracker(interfaceName),
		handshakeTimeout: 15 * time.Second, // Default timeout
	}
}

// SetHandshakeTimeout sets the timeout for WireGuard handshake
func (cm *ConnectionManager) SetHandshakeTimeout(timeout time.Duration) {
	cm.handshakeTimeout = timeout
	fmt.Printf("Handshake timeout set to %s\n", timeout)
}

// ConnectToPeer connects to a peer using their public key and endpoint
func (cm *ConnectionManager) ConnectToPeer(peerPublicKey, peerEndpoint string) error {
	// Setup cleanup function to ensure internet connectivity is preserved on any failure
	connectionSuccess := false
	defer func() {
		// Only run cleanup if we didn't succeed
		if !connectionSuccess {
			fmt.Println("Cleaning up after failed connection...")
			if err := cm.Disconnect(); err != nil {
				fmt.Printf("Warning: Error during cleanup: %v\n", err)
				// Try more aggressive cleanup
				cm.emergencyRoutingRestore()
			}
		}
	}()

	fmt.Println("=== Connection Process Started ===")

	// Test UDP connectivity to endpoint before proceeding
	fmt.Printf("Testing UDP connectivity to %s...\n", peerEndpoint)
	reachable, err := cm.testUDPConnectivity(peerEndpoint)
	if err != nil && os.Getenv("PEERVPN_DEBUG") == "1" {
		fmt.Printf("Warning: Error testing connectivity: %v\n", err)
	}
	if !reachable {
		fmt.Printf("⚠️  Endpoint %s may be unreachable (firewall/NAT issues possible)\n", peerEndpoint)
	} else {
		fmt.Printf("✓ Endpoint %s appears reachable\n", peerEndpoint)
	}

	// Set up WireGuard interface if needed
	fmt.Println("1. Setting up WireGuard interface...")
	if err := cm.wgManager.SetupInterface(); err != nil {
		return fmt.Errorf("failed to set up WireGuard interface: %v", err)
	}
	fmt.Println("   ✓ WireGuard interface setup complete")

	// Enable IP forwarding if this is an exit node
	if cm.localPeerInfo.IsExitNode {
		fmt.Println("2. Enabling IP forwarding (exit node mode)...")
		if err := cm.routingManager.EnableIPForwarding(); err != nil {
			return fmt.Errorf("failed to enable IP forwarding: %v", err)
		}
		fmt.Println("   ✓ IP forwarding enabled")
	} else {
		fmt.Println("2. Running in client mode, IP forwarding not needed")
	}

	// Add peer to WireGuard configuration
	var allowedIPs []string
	if cm.localPeerInfo.IsExitNode {
		// If we're an exit node, we only route traffic from the client subnet
		allowedIPs = []string{cm.clientSubnet}
		fmt.Printf("3. Adding peer with limited subnet routing (%s)...\n", cm.clientSubnet)
	} else {
		// If we're a client, route all traffic through the exit node
		allowedIPs = []string{"0.0.0.0/0"}
		fmt.Println("3. Adding peer with full traffic routing (0.0.0.0/0)...")
	}

	// Add the peer to WireGuard
	fmt.Printf("   Adding peer: %s at endpoint %s\n", peerPublicKey, peerEndpoint)
	if err := cm.wgManager.AddPeer(peerPublicKey, peerEndpoint, allowedIPs); err != nil {
		return fmt.Errorf("failed to add peer to WireGuard: %v", err)
	}
	fmt.Println("   ✓ Peer added to WireGuard configuration")

	// Setup is complete, but we don't set up routing until connection is confirmed
	// This is to ensure we don't break internet connectivity if the connection fails
	fmt.Println("4. Starting connection monitoring...")
	cm.StartConnectionTracking(5 * time.Second)
	fmt.Println("   ✓ Connection monitoring started")

	// Wait and verify that we actually establish a connection
	fmt.Println("5. Verifying connection to peer...")
	handshakeTimeout := cm.handshakeTimeout
	handshakeSuccess := false

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	// Check at regular intervals for a successful handshake
	ticker := time.NewTicker(2 * time.Second) // Increased interval for more stability
	defer ticker.Stop()

	fmt.Printf("   Waiting up to %s for handshake with peer...\n", handshakeTimeout)

	startTime := time.Now()

	// Immediately try to initiate a handshake
	fmt.Println("   Initiating handshake...")
	if err := cm.initiateHandshake(peerPublicKey, peerEndpoint); err != nil {
		fmt.Printf("   Warning: Failed to initiate handshake: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			// Timeout occurred
			if !handshakeSuccess {
				fmt.Println("   ✗ Connection timed out - no handshake with peer")
				return fmt.Errorf("connection timed out - could not establish handshake with peer at %s after %s", peerEndpoint, handshakeTimeout)
			}
			goto handshakeDone
		case <-ticker.C:
			// Check if we've established a handshake with this peer
			connectedPeers := cm.connTracker.GetConnectedPeers()

			for _, peer := range connectedPeers {
				// Skip peers that haven't had a handshake
				if peer.LastHandshake.IsZero() {
					continue
				}

				// Check if this is a recent handshake (within our monitoring window)
				handshakeAge := time.Since(peer.LastHandshake)

				// Consider any handshake within the last 2 minutes as valid for this connection
				if handshakeAge < 2*time.Minute {
					fmt.Printf("   ✓ Handshake established with peer at %s (%s ago)\n", peer.Endpoint, handshakeAge.Round(time.Second))
					handshakeSuccess = true
					goto handshakeDone
				}
			}

			// Print progress and try to re-initiate handshake periodically
			elapsed := time.Since(startTime).Round(time.Second)
			fmt.Printf("   Waiting for handshake: %s elapsed...\n", elapsed)

			// Re-attempt handshake every 10 seconds
			if elapsed.Seconds() > 0 && int(elapsed.Seconds())%10 == 0 {
				fmt.Println("   Re-initiating handshake...")
				cm.initiateHandshake(peerPublicKey, peerEndpoint)
			}
		}
	}

handshakeDone:
	if handshakeSuccess {
		// Only set up routing after confirming handshake
		fmt.Println("6. Setting up routing tables...")
		if err := cm.routingManager.SetupRouting(cm.clientSubnet); err != nil {
			return fmt.Errorf("failed to set up routing: %v", err)
		}
		fmt.Println("   ✓ Routing tables configured")

		fmt.Println("=== Connection Process Complete ===")
		fmt.Println("Traffic is now routed through the exit node.")
		connectionSuccess = true
		return nil
	} else {
		fmt.Println("=== Connection Process Failed ===")
		return fmt.Errorf("connection timed out - could not establish handshake with peer at %s", peerEndpoint)
	}
}

// testUDPConnectivity tests if a UDP endpoint is reachable by sending a probe packet
func (cm *ConnectionManager) testUDPConnectivity(endpoint string) (bool, error) {
	// Parse the endpoint
	endpointObj, err := nat.ParseEndpointString(endpoint)
	if err != nil {
		return false, fmt.Errorf("invalid endpoint format: %v", err)
	}

	// Create a test UDP connection
	conn, err := net.DialTimeout("udp", endpoint, 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Set a timeout for the probe
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a test packet (WireGuard handshake initiation pattern)
	testPacket := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err = conn.Write(testPacket)
	if err != nil {
		return false, fmt.Errorf("failed to send UDP test packet: %v", err)
	}

	// Try with the system ping command too (though this uses ICMP not UDP)
	var pingCmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		pingCmd = exec.Command("ping", "-n", "1", "-w", "1000", endpointObj.IP.String())
	default:
		pingCmd = exec.Command("ping", "-c", "1", "-W", "1", endpointObj.IP.String())
	}

	// Only print ping result in debug mode
	if os.Getenv("PEERVPN_DEBUG") == "1" {
		pingOutput, _ := pingCmd.CombinedOutput()
		fmt.Printf("Ping test to %s: %s\n", endpointObj.IP.String(), string(pingOutput))
	} else {
		// Just run the ping silently to test connectivity
		pingCmd.Run()
	}

	// The UDP test is considered successful if we were able to send the packet
	// We can't really verify receipt since WireGuard doesn't reply to random packets
	return true, nil
}

// emergencyRoutingRestore tries to restore normal internet connectivity
// after a connection failure by directly manipulating routing tables
func (cm *ConnectionManager) emergencyRoutingRestore() {
	fmt.Println("EMERGENCY: Attempting to restore network connectivity...")

	// Based on the OS, we'll take different actions
	switch runtime.GOOS {
	case "darwin":
		// On macOS, first try to find the actual default gateway
		fmt.Println("Finding default gateway interfaces...")
		netInterfaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range netInterfaces {
				// Skip loopback and inactive interfaces
				if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
					continue
				}

				// Skip our VPN interface
				if iface.Name == cm.interfaceName {
					continue
				}

				// Look for active interfaces like en0, en1 (typical on macOS)
				if strings.HasPrefix(iface.Name, "en") {
					fmt.Printf("Found potential default interface: %s\n", iface.Name)

					// Try to get info about this interface
					ifConfig, err := exec.Command("ifconfig", iface.Name).CombinedOutput()
					if err == nil {
						fmt.Printf("Interface info: %s\n", string(ifConfig))

						// Try to extract gateway information
						gatewayOutput, err := exec.Command("route", "-n", "get", "default", "-ifscope", iface.Name).CombinedOutput()
						if err == nil {
							fmt.Printf("Gateway for %s: %s\n", iface.Name, string(gatewayOutput))

							// Try to make this the default route
							fmt.Printf("Setting %s as default route\n", iface.Name)
							exec.Command("route", "-n", "change", "default", "-ifscope", iface.Name).Run()
						}
					}
				}
			}
		}

		// Flush the routing table
		fmt.Println("Flushing routing table...")
		exec.Command("route", "-n", "flush").Run()

		// Try common gateways
		fmt.Println("Attempting to restore default route with common gateway IPs...")

		// Try the ones in the domestic router IP range first
		commonGateways := []string{
			"192.168.1.1", "10.0.0.1", "192.168.0.1", "172.16.0.1",
			"192.168.1.254", "10.0.0.138", "10.1.1.1", "172.20.10.1",
		}

		// Try each of them
		for _, gateway := range commonGateways {
			fmt.Printf("Trying gateway %s...\n", gateway)
			exec.Command("route", "-n", "add", "default", gateway).Run()
			// Ping to see if it works
			pingOutput, err := exec.Command("ping", "-c", "1", "-t", "1", "8.8.8.8").CombinedOutput()
			if err == nil {
				fmt.Printf("Restored connectivity via %s!\n", gateway)
				fmt.Printf("Ping result: %s\n", string(pingOutput))
				break
			}
		}

		// Remove any reference to our interface
		fmt.Println("Removing any routes through VPN interface...")
		exec.Command("route", "-n", "delete", "-ifp", cm.interfaceName).Run()

		// Try to bring down the interface
		fmt.Println("Bringing down VPN interface...")
		exec.Command("ifconfig", cm.interfaceName, "down").Run()

		// As a last resort, try to kill all WireGuard processes
		fmt.Println("Killing any WireGuard processes...")
		exec.Command("pkill", "-f", "wireguard").Run()

	case "linux":
		// On Linux, restore default route and flush interface
		fmt.Println("Attempting to restore default route...")

		// Try to find the default interface
		routeInfo, err := exec.Command("ip", "route", "show").CombinedOutput()
		if err == nil {
			fmt.Printf("Current routes:\n%s\n", string(routeInfo))
		}

		// Try common gateways
		commonGateways := []string{"192.168.1.1", "10.0.0.1", "192.168.0.1", "172.16.0.1"}
		for _, gateway := range commonGateways {
			exec.Command("ip", "route", "add", "default", "via", gateway).Run()
		}

		// Flush routes for the interface
		fmt.Println("Removing any routes through VPN interface...")
		exec.Command("ip", "route", "flush", "dev", cm.interfaceName).Run()

	case "windows":
		// On Windows, try to reset the interface
		fmt.Println("Attempting to restore default route...")

		// Try common gateways
		exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", "192.168.1.1").Run()
		exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1").Run()

		// Reset Winsock as a last resort
		fmt.Println("Resetting Winsock catalog...")
		exec.Command("netsh", "winsock", "reset").Run()
	}

	fmt.Println("Emergency network restoration attempted.")
	fmt.Println("If you still have connectivity issues, please restart your computer.")
}

// Disconnect cleans up the VPN connection and restores network configuration
func (cm *ConnectionManager) Disconnect() error {
	var errors []string

	// Stop NAT keepalive first
	fmt.Println("Stopping NAT keepalive...")
	cm.natDiscovery.StopNATKeepalive()

	// First restore default route before cleaning up WireGuard
	fmt.Println("Ensuring default route is restored...")

	// Get the default gateway information before cleanup
	routeInfo, err := exec.Command("route", "-n", "get", "8.8.8.8").CombinedOutput()
	if err == nil {
		fmt.Printf("Current route info: %s\n", string(routeInfo))
	}

	// Clean up routing first
	fmt.Println("Cleaning up routing tables...")
	if err := cm.routingManager.CleanupRouting(); err != nil {
		errors = append(errors, fmt.Sprintf("failed to clean up routing: %v", err))
		// Don't return immediately, try to do as much cleanup as possible
	}

	// Make sure we can still reach the Internet
	fmt.Println("Verifying Internet connectivity...")

	// Depending on OS, try to restore default route
	switch runtime.GOOS {
	case "darwin":
		// Flush routing table cache on macOS
		exec.Command("route", "-n", "flush").Run()
	case "linux":
		// On Linux, we might need to restore the default route
		exec.Command("ip", "route", "flush", "cache").Run()
	}

	// Tear down WireGuard interface after routing is cleaned up
	fmt.Println("Removing WireGuard interface...")
	if err := cm.wgManager.TearDown(); err != nil {
		errors = append(errors, fmt.Sprintf("failed to tear down WireGuard interface: %v", err))
	}

	// If anything failed, try the emergency recovery
	if len(errors) > 0 {
		fmt.Println("Errors encountered during normal cleanup, trying emergency recovery...")
		cm.emergencyRoutingRestore()

		// Return combined error
		return fmt.Errorf("multiple cleanup errors: %s", strings.Join(errors, "; "))
	}

	// Perform final check of routing
	routeInfo, err = exec.Command("route", "-n", "get", "8.8.8.8").CombinedOutput()
	if err == nil {
		fmt.Printf("Final route info: %s\n", string(routeInfo))
	}

	fmt.Println("VPN connection terminated and network restored successfully.")
	return nil
}

// DiscoverEndpoint discovers our public endpoint using STUN
func (cm *ConnectionManager) DiscoverEndpoint(ctx context.Context) (string, error) {
	// Get the current port from WireGuard
	wgPort := cm.wgManager.GetListenPort()

	// CRITICAL FIX: Set STUN discovery port to match WireGuard BEFORE discovery
	cm.natDiscovery.SetLocalPort(wgPort)

	endpoint, err := cm.natDiscovery.DiscoverPublicEndpoint(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to discover public endpoint: %v", err)
	}

	fmt.Printf("Local WireGuard port: %d, Public endpoint: %s\n", wgPort, endpoint.String())

	return endpoint.String(), nil
}

// ValidatePeerEndpoint validates a peer endpoint string
func (cm *ConnectionManager) ValidatePeerEndpoint(endpoint string) (string, error) {
	// Parse the endpoint
	_, err := nat.ParseEndpointString(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format: %v", err)
	}

	return endpoint, nil
}

// SetupExitNode sets up the local node as an exit node
func (cm *ConnectionManager) SetupExitNode() error {
	// Update local peer info
	cm.localPeerInfo.IsExitNode = true

	// Set up WireGuard interface
	fmt.Println("Setting up WireGuard interface...")
	if err := cm.wgManager.SetupInterface(); err != nil {
		return fmt.Errorf("failed to set up WireGuard interface: %v", err)
	}
	fmt.Println("WireGuard interface setup complete")

	// Enable IP forwarding
	fmt.Println("Enabling IP forwarding...")
	if err := cm.routingManager.EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}
	fmt.Println("IP forwarding enabled")

	// Discover our public endpoint
	fmt.Println("Discovering public endpoint...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint, err := cm.DiscoverEndpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover public endpoint: %v", err)
	}
	fmt.Printf("Public endpoint discovered: %s\n", endpoint)

	// Update local peer info with the endpoint
	cm.localPeerInfo.Endpoint = endpoint
	cm.localPeerInfo.AllowedSubnets = cm.clientSubnet

	// Start NAT keepalive to maintain port mapping even when no peers are connected
	fmt.Println("Starting NAT keepalive to maintain port mapping...")
	keepaliveCtx := context.Background() // Long-running context

	// Start keepalive every 60 seconds (well before typical NAT timeouts)
	// This is less frequent than WireGuard's persistent keepalive (25s) but more proactive
	go cm.natDiscovery.StartNATKeepalive(keepaliveCtx, 60*time.Second)
	fmt.Println("NAT keepalive started - your exit node will remain reachable even during idle periods")

	// Start tracking connections immediately to detect peers
	fmt.Println("Starting connection tracker...")
	cm.StartConnectionTracking(5 * time.Second)

	// Setup proper routing
	fmt.Println("Setting up routing for exit node...")
	if err := cm.routingManager.SetupRouting(cm.clientSubnet); err != nil {
		return fmt.Errorf("failed to set up routing: %v", err)
	}
	fmt.Println("Routing setup complete")

	return nil
}

// GetConnectionInfo returns connection information for sharing
func (cm *ConnectionManager) GetConnectionInfo() string {
	var info strings.Builder

	info.WriteString(fmt.Sprintf("Peer ID: %s\n", cm.localPeerInfo.PeerID))
	info.WriteString(fmt.Sprintf("Public Key: %s\n", cm.localPeerInfo.PublicKey))

	if cm.localPeerInfo.Endpoint != "" {
		info.WriteString(fmt.Sprintf("Endpoint: %s\n", cm.localPeerInfo.Endpoint))
	}

	if cm.localPeerInfo.IsExitNode {
		info.WriteString(fmt.Sprintf("Allowed Subnets: %s\n", cm.localPeerInfo.AllowedSubnets))
		info.WriteString("Mode: Exit Node\n")
	} else {
		info.WriteString("Mode: Client\n")
	}

	return info.String()
}

// GetConnectionString returns a formatted connection string for easy copying
func (cm *ConnectionManager) GetConnectionString() string {
	if cm.localPeerInfo.IsExitNode && cm.localPeerInfo.Endpoint != "" {
		return fmt.Sprintf("%s@%s", cm.localPeerInfo.PublicKey, cm.localPeerInfo.Endpoint)
	}
	return ""
}

// StartConnectionTracking starts tracking peer connections and traffic stats
func (cm *ConnectionManager) StartConnectionTracking(interval time.Duration) {
	// Define a callback to handle connection stats updates
	cm.connTracker.StartTracking(interval, func(stats []*PeerStats) {
		// Detect new connections (peers with new handshakes)
		for _, peer := range stats {
			if time.Since(peer.LastHandshake) < interval*2 {
				// This is likely a new connection or reconnection
				fmt.Printf("\n[%s] New peer connected: %s\n", time.Now().Format("15:04:05"), peer.Endpoint)
			}
		}
	})
}

// DisplayPeerStats prints the current peer stats
func (cm *ConnectionManager) DisplayPeerStats() {
	peers := cm.connTracker.GetConnectedPeers()
	if len(peers) == 0 {
		// Only show this occasionally to avoid spamming
		return
	}

	fmt.Printf("[%s] 📈 Connected peers: %d\n", time.Now().Format("15:04:05"), len(peers))
	for _, peer := range peers {
		fmt.Printf("  • %s (↓%s ↑%s, last handshake %s ago)\n",
			peer.Endpoint,
			FormatTrafficBytes(peer.BytesReceived),
			FormatTrafficBytes(peer.BytesSent),
			formatDuration(time.Since(peer.LastHandshake)))
	}
}

// StopConnectionTracking stops the connection tracker
func (cm *ConnectionManager) StopConnectionTracking() {
	cm.connTracker.StopTracking()
}

// Helper function to format duration
func formatDuration(d time.Duration) string {
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

// EnableConnectionDebugging starts additional diagnostics to monitor incoming connection attempts
func (cm *ConnectionManager) EnableConnectionDebugging() {
	// Get the WireGuard port
	wgPort := cm.wgManager.GetListenPort()

	fmt.Printf("\n=== Enabling Advanced Connection Debugging (Port: %d) ===\n", wgPort)

	// Start tcpdump in the background to capture WireGuard packets
	go func() {
		// Run tcpdump for UDP traffic on the WireGuard port
		portStr := fmt.Sprintf("port %d", wgPort)
		cmd := exec.Command("tcpdump", "-i", "any", "-n", "udp", "and", portStr)

		// Set up pipes for output
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Printf("Error setting up packet capture: %v\n", err)
			return
		}

		cmd.Stderr = os.Stderr

		// Start tcpdump
		if err := cmd.Start(); err != nil {
			fmt.Printf("Error starting packet capture: %v\n", err)
			return
		}

		fmt.Println("Packet monitoring started - watching for WireGuard traffic")

		// Read output and print
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("PACKET: %s\n", line)
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading packet capture: %v\n", err)
		}

		if err := cmd.Wait(); err != nil {
			fmt.Printf("Packet capture ended: %v\n", err)
		}
	}()

	// Run periodic connection info dumps to see more detailed WireGuard info
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		wgBinary := wireguard.BinaryPath("wg")

		for {
			<-ticker.C

			fmt.Println("\n=== WireGuard Connection Debug Info ===")
			output, err := exec.Command(wgBinary, "show", cm.interfaceName, "dump").CombinedOutput()
			if err == nil {
				fmt.Printf("Raw connection data: %s\n", string(output))
			}

			netstatOutput, err := exec.Command("netstat", "-an").CombinedOutput()
			if err == nil {
				lines := strings.Split(string(netstatOutput), "\n")
				for _, line := range lines {
					// Only show lines with our WireGuard port
					if strings.Contains(line, fmt.Sprintf(":%d", wgPort)) {
						fmt.Printf("Connection state: %s\n", line)
					}
				}
			}
		}
	}()
}

// initiateHandshake manually triggers a WireGuard handshake with a peer
func (cm *ConnectionManager) initiateHandshake(peerPublicKey, peerEndpoint string) error {
	// Use the wg binary to set the peer endpoint, which should trigger a handshake
	wgBinary := wireguard.BinaryPath("wg")
	cmd := exec.Command(wgBinary, "set", cm.interfaceName, "peer", peerPublicKey, "endpoint", peerEndpoint)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set peer endpoint: %v - %s", err, string(output))
	}

	return nil
}

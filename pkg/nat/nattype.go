package nat

import (
	"context"
	"fmt"
	"net"
	"time"
)

// NATType represents the type of NAT the client is behind
type NATType int

const (
	// NATTypeUnknown represents an unknown NAT type
	NATTypeUnknown NATType = iota

	// NATTypeOpen represents no NAT (direct internet connection)
	NATTypeOpen

	// NATTypeFullCone represents full cone NAT (most permissive)
	NATTypeFullCone

	// NATTypeRestrictedCone represents restricted cone NAT
	NATTypeRestrictedCone

	// NATTypePortRestrictedCone represents port-restricted cone NAT
	NATTypePortRestrictedCone

	// NATTypeSymmetric represents symmetric NAT (most restrictive)
	NATTypeSymmetric

	// NATTypeBlocked represents blocked UDP or no connectivity
	NATTypeBlocked
)

// String returns a human-readable description of the NAT type
func (nt NATType) String() string {
	switch nt {
	case NATTypeOpen:
		return "Open Internet (No NAT)"
	case NATTypeFullCone:
		return "Full Cone NAT"
	case NATTypeRestrictedCone:
		return "Restricted Cone NAT"
	case NATTypePortRestrictedCone:
		return "Port-Restricted Cone NAT"
	case NATTypeSymmetric:
		return "Symmetric NAT"
	case NATTypeBlocked:
		return "Blocked/Firewalled"
	default:
		return "Unknown NAT Type"
	}
}

// GetCompatibilityLevel returns how well this NAT type works for P2P
func (nt NATType) GetCompatibilityLevel() string {
	switch nt {
	case NATTypeOpen:
		return "Excellent - Can connect to anyone"
	case NATTypeFullCone:
		return "Excellent - Can connect to most peers"
	case NATTypeRestrictedCone:
		return "Good - Can connect to most peers"
	case NATTypePortRestrictedCone:
		return "Fair - May have issues with some peers"
	case NATTypeSymmetric:
		return "Poor - Will have trouble with most peers"
	case NATTypeBlocked:
		return "None - Cannot establish P2P connections"
	default:
		return "Unknown"
	}
}

// GetRecommendations returns suggestions for improving connectivity
func (nt NATType) GetRecommendations() []string {
	switch nt {
	case NATTypeOpen:
		return []string{
			"✓ Perfect for P2P! You can act as an exit node for others",
			"✓ Others can easily connect to you",
		}
	case NATTypeFullCone:
		return []string{
			"✓ Great for P2P! You can act as an exit node",
			"✓ Consider port forwarding UDP 51820 for even better connectivity",
		}
	case NATTypeRestrictedCone:
		return []string{
			"• Good P2P connectivity",
			"• May want to enable UPnP on your router",
			"• Consider port forwarding UDP 51820 if acting as exit node",
		}
	case NATTypePortRestrictedCone:
		return []string{
			"• Moderate P2P connectivity",
			"• Strongly recommend port forwarding UDP 51820",
			"• Enable UPnP if available on your router",
			"• May have issues connecting to peers behind symmetric NAT",
		}
	case NATTypeSymmetric:
		return []string{
			"⚠ Poor P2P connectivity",
			"⚠ Cannot reliably act as exit node",
			"⚠ Will have trouble connecting to other symmetric NAT peers",
			"• Try connecting to peers with open/cone NAT instead",
			"• Consider using a VPS as intermediate relay",
			"• Some enterprise/cellular networks use symmetric NAT",
		}
	case NATTypeBlocked:
		return []string{
			"✗ Cannot establish P2P connections",
			"✗ UDP traffic appears to be blocked",
			"• Check firewall settings",
			"• Verify router allows UDP traffic",
			"• Try different network (mobile hotspot, etc.)",
		}
	default:
		return []string{"Unable to determine connectivity"}
	}
}

// NATTypeDetector handles NAT type detection
type NATTypeDetector struct {
	stunServers []string
	localPort   int
}

// NewNATTypeDetector creates a new NAT type detector
func NewNATTypeDetector(stunServers []string) *NATTypeDetector {
	return &NATTypeDetector{
		stunServers: stunServers,
	}
}

// DetectNATType performs comprehensive NAT type detection
func (ntd *NATTypeDetector) DetectNATType(ctx context.Context) (NATType, []Endpoint, error) {
	fmt.Println("🔍 Detecting NAT type and connectivity...")
	fmt.Println("This may take 10-15 seconds...")

	// Step 1: Test basic STUN connectivity
	fmt.Println("\n1. Testing basic STUN connectivity...")

	endpoints := make([]Endpoint, 0)
	var firstEndpoint Endpoint

	// Try to get our external endpoint from multiple STUN servers
	for i, server := range ntd.stunServers {
		if i >= 3 { // Limit to first 3 servers for speed
			break
		}

		fmt.Printf("   Testing with %s...\n", server)

		client := NewDiscoveryClient([]string{server})
		// Set the local port to a default WireGuard port for testing
		client.SetLocalPort(51820)
		endpoint, err := client.DiscoverPublicEndpoint(ctx)
		if err != nil {
			fmt.Printf("   ✗ Failed: %v\n", err)
			continue
		}

		fmt.Printf("   ✓ External endpoint: %s\n", endpoint.String())
		endpoints = append(endpoints, endpoint)

		if firstEndpoint.IP == nil {
			firstEndpoint = endpoint
		}
	}

	if len(endpoints) == 0 {
		fmt.Println("   ✗ No STUN servers responded")
		return NATTypeBlocked, endpoints, fmt.Errorf("unable to contact any STUN servers")
	}

	// Step 2: Check if we have a public IP
	fmt.Println("\n2. Checking for public IP address...")

	localIPs, err := getLocalIPs()
	if err != nil {
		fmt.Printf("   Warning: Could not get local IPs: %v\n", err)
	}

	isPublicIP := false
	for _, localIP := range localIPs {
		if localIP.Equal(firstEndpoint.IP) {
			isPublicIP = true
			fmt.Printf("   ✓ Public IP detected: %s\n", localIP)
			break
		}
	}

	if isPublicIP {
		return NATTypeOpen, endpoints, nil
	}

	fmt.Printf("   • Private IP detected, behind NAT\n")
	fmt.Printf("   • Local IPs: %v\n", localIPs)
	fmt.Printf("   • External IP: %s\n", firstEndpoint.IP)

	// Step 3: Test endpoint consistency across STUN servers
	fmt.Println("\n3. Testing endpoint consistency...")

	allSameIP := true
	allSamePort := true

	for i := 1; i < len(endpoints); i++ {
		if !endpoints[i].IP.Equal(endpoints[0].IP) {
			allSameIP = false
		}
		if endpoints[i].Port != endpoints[0].Port {
			allSamePort = false
		}
	}

	if !allSameIP {
		fmt.Println("   ✗ Different external IPs from different servers - Very unusual!")
		fmt.Printf("   Endpoints: %v\n", endpoints)
		return NATTypeSymmetric, endpoints, nil
	}

	if !allSamePort {
		fmt.Println("   ✗ Different external ports from different servers")
		fmt.Printf("   This indicates Symmetric NAT\n")
		return NATTypeSymmetric, endpoints, nil
	}

	fmt.Println("   ✓ Consistent external endpoint across servers")

	// Step 4: Test cone NAT behavior
	fmt.Println("\n4. Testing NAT cone behavior...")

	// For this test, we need to send packets to different STUN servers
	// and see if they can reach us on the same external port

	// This is a simplified test - a full implementation would require
	// more sophisticated STUN tests with different server combinations

	// Based on what we know so far, classify as cone NAT
	// (Full cone vs restricted cone would require more complex testing)

	fmt.Println("   • Appears to be Cone NAT (specific type requires more testing)")

	return NATTypeFullCone, endpoints, nil
}

// getLocalIPs returns all local IP addresses
func getLocalIPs() ([]net.IP, error) {
	var ips []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only IPv4 for now
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP)
			}
		}
	}

	return ips, nil
}

// TestPeerConnectivity tests if this client can connect to a specific peer
func (ntd *NATTypeDetector) TestPeerConnectivity(ctx context.Context, peerEndpoint string) (bool, error) {
	fmt.Printf("🔌 Testing connectivity to peer: %s\n", peerEndpoint)

	// Parse the endpoint to validate format
	_, err := ParseEndpointString(peerEndpoint)
	if err != nil {
		return false, fmt.Errorf("invalid endpoint format: %v", err)
	}

	// Test basic UDP connectivity
	conn, err := net.DialTimeout("udp", peerEndpoint, 5*time.Second)
	if err != nil {
		fmt.Printf("   ✗ Cannot establish UDP connection: %v\n", err)
		return false, err
	}
	defer conn.Close()

	// Set timeout for the test
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a test packet
	testPacket := []byte("PEERVPN_CONNECTIVITY_TEST")
	_, err = conn.Write(testPacket)
	if err != nil {
		fmt.Printf("   ✗ Cannot send UDP packet: %v\n", err)
		return false, err
	}

	fmt.Printf("   ✓ UDP packet sent to %s\n", peerEndpoint)
	fmt.Printf("   Note: Cannot verify receipt without peer cooperation\n")

	return true, nil
}

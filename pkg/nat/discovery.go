package nat

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

// Endpoint represents a public endpoint (IP:port)
type Endpoint struct {
	IP   net.IP
	Port int
}

// String returns a string representation of the endpoint
func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.IP.String(), e.Port)
}

// DiscoveryClient handles NAT traversal discovery
type DiscoveryClient struct {
	stunServers []string
}

// NewDiscoveryClient creates a new NAT discovery client
func NewDiscoveryClient(stunServers []string) *DiscoveryClient {
	return &DiscoveryClient{
		stunServers: stunServers,
	}
}

// DiscoverPublicEndpoint attempts to discover the public endpoint using STUN
func (c *DiscoveryClient) DiscoverPublicEndpoint(ctx context.Context) (Endpoint, error) {
	var endpoint Endpoint
	var lastErr error

	// Try each STUN server until we get a successful response
	for _, serverAddr := range c.stunServers {
		select {
		case <-ctx.Done():
			return endpoint, ctx.Err()
		default:
			ep, err := c.discoverWithServer(serverAddr)
			if err == nil {
				return ep, nil
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return endpoint, fmt.Errorf("all STUN servers failed: %v", lastErr)
	}
	return endpoint, fmt.Errorf("no STUN servers available")
}

// discoverWithServer attempts to discover the public endpoint using a specific STUN server
func (c *DiscoveryClient) discoverWithServer(serverAddr string) (Endpoint, error) {
	var endpoint Endpoint

	// Create a connection to the STUN server
	conn, err := net.Dial("udp4", serverAddr)
	if err != nil {
		return endpoint, fmt.Errorf("failed to connect to STUN server %s: %v", serverAddr, err)
	}
	defer conn.Close()

	// Set a timeout for the STUN request
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return endpoint, fmt.Errorf("failed to set deadline: %v", err)
	}

	// Create a STUN message
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Send the STUN message
	if _, err := conn.Write(message.Raw); err != nil {
		return endpoint, fmt.Errorf("failed to send STUN request: %v", err)
	}

	// Create a buffer to receive the response
	buf := make([]byte, 1024)

	// Read the response
	n, err := conn.Read(buf)
	if err != nil {
		return endpoint, fmt.Errorf("failed to read STUN response: %v", err)
	}

	// Parse the response
	response := &stun.Message{Raw: buf[:n]}
	if err := response.Decode(); err != nil {
		return endpoint, fmt.Errorf("failed to decode STUN response: %v", err)
	}

	// Extract the XOR-MAPPED-ADDRESS attribute
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(response); err != nil {
		return endpoint, fmt.Errorf("failed to get XOR-MAPPED-ADDRESS: %v", err)
	}

	endpoint.IP = xorAddr.IP
	endpoint.Port = xorAddr.Port

	return endpoint, nil
}

// ParseEndpointString parses a string in the format "IP:port" into an Endpoint
func ParseEndpointString(s string) (Endpoint, error) {
	var endpoint Endpoint

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return endpoint, fmt.Errorf("invalid endpoint format: %v", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Try to resolve the hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return endpoint, fmt.Errorf("invalid IP address or hostname: %s", host)
		}
		ip = ips[0]
	}

	// Parse the port
	var portNum int
	_, err = fmt.Sscanf(port, "%d", &portNum)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return endpoint, fmt.Errorf("invalid port: %s", port)
	}

	endpoint.IP = ip
	endpoint.Port = portNum
	return endpoint, nil
}

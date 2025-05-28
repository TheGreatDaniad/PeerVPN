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
	stunServers     []string
	localPort       int
	keepaliveStop   chan struct{}
	lastEndpoint    *Endpoint
	keepaliveActive bool
}

// NewDiscoveryClient creates a new NAT discovery client
func NewDiscoveryClient(stunServers []string) *DiscoveryClient {
	return &DiscoveryClient{
		stunServers:   stunServers,
		localPort:     0, // 0 means any available port
		keepaliveStop: make(chan struct{}),
	}
}

// SetLocalPort sets the local port for the DiscoveryClient
// This ensures that STUN uses the same port that WireGuard is using
func (c *DiscoveryClient) SetLocalPort(port int) {
	c.localPort = port
	fmt.Printf("STUN client will use local port %d for NAT detection\n", port)
}

// StartNATKeepalive starts periodic NAT mapping refresh to prevent timeout
// This ensures the NAT mapping stays active even when no peers are connected
func (c *DiscoveryClient) StartNATKeepalive(ctx context.Context, interval time.Duration) {
	if c.keepaliveActive {
		return // Already running
	}

	c.keepaliveActive = true

	go func() {
		defer func() {
			c.keepaliveActive = false
		}()

		fmt.Printf("Starting NAT keepalive every %v to maintain port mapping\n", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				fmt.Println("NAT keepalive stopping due to context cancellation")
				return
			case <-c.keepaliveStop:
				fmt.Println("NAT keepalive stopping due to explicit stop")
				return
			case <-ticker.C:
				// Refresh NAT mapping by doing a quick STUN discovery
				if c.localPort > 0 {
					endpoint, err := c.DiscoverPublicEndpoint(context.WithValue(ctx, "keepalive", true))
					if err != nil {
						fmt.Printf("NAT keepalive failed: %v\n", err)
					} else {
						c.lastEndpoint = &endpoint
						fmt.Printf("NAT keepalive successful - endpoint refreshed: %s\n", endpoint.String())
					}
				}
			}
		}
	}()
}

// StartNATMonitoring starts frequent monitoring of the public endpoint for testing
// This logs the public endpoint every specified interval to verify NAT persistence
func (c *DiscoveryClient) StartNATMonitoring(ctx context.Context, interval time.Duration) {
	go func() {
		fmt.Printf("Starting NAT monitoring every %v to verify port persistence\n", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				fmt.Println("NAT monitoring stopping due to context cancellation")
				return
			case <-ticker.C:
				if c.localPort > 0 {
					// Use a short timeout for monitoring checks
					monitorCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					endpoint, err := c.DiscoverPublicEndpoint(context.WithValue(monitorCtx, "monitoring", true))
					cancel()

					if err != nil {
						fmt.Printf("[%s] ❌ NAT monitoring failed: %v\n", time.Now().Format("15:04:05"), err)
					} else {
						// Check if endpoint changed
						if c.lastEndpoint != nil {
							if c.lastEndpoint.IP.Equal(endpoint.IP) && c.lastEndpoint.Port == endpoint.Port {
								fmt.Printf("[%s] ✅ NAT port persistent: %s (unchanged)\n",
									time.Now().Format("15:04:05"), endpoint.String())
							} else {
								fmt.Printf("[%s] ⚠️  NAT port changed: %s -> %s\n",
									time.Now().Format("15:04:05"), c.lastEndpoint.String(), endpoint.String())
							}
						} else {
							fmt.Printf("[%s] 🔍 NAT port discovered: %s\n",
								time.Now().Format("15:04:05"), endpoint.String())
						}
						c.lastEndpoint = &endpoint
					}
				} else {
					fmt.Printf("[%s] ⏸️  NAT monitoring paused (no local port set)\n", time.Now().Format("15:04:05"))
				}
			}
		}
	}()
}

// StopNATKeepalive stops the NAT keepalive mechanism
func (c *DiscoveryClient) StopNATKeepalive() {
	if c.keepaliveActive {
		close(c.keepaliveStop)
		// Create new channel for next use
		c.keepaliveStop = make(chan struct{})
	}
}

// GetLastKnownEndpoint returns the last successfully discovered endpoint
func (c *DiscoveryClient) GetLastKnownEndpoint() *Endpoint {
	return c.lastEndpoint
}

// DiscoverPublicEndpoint attempts to discover the public endpoint using STUN
func (c *DiscoveryClient) DiscoverPublicEndpoint(ctx context.Context) (Endpoint, error) {
	var endpoint Endpoint
	var lastErr error

	// If no local port is set, return an error - we need to know which port WireGuard is using
	if c.localPort <= 0 {
		return endpoint, fmt.Errorf("local WireGuard port must be set before STUN discovery")
	}

	// Check if this is a keepalive or monitoring call (less verbose logging)
	isKeepalive := ctx.Value("keepalive") != nil
	isMonitoring := ctx.Value("monitoring") != nil
	isQuiet := isKeepalive || isMonitoring

	// Try each STUN server until we get a successful response
	for _, serverAddr := range c.stunServers {
		select {
		case <-ctx.Done():
			return endpoint, ctx.Err()
		default:
			ep, err := c.discoverWithServer(serverAddr, isQuiet)
			if err == nil {
				// CRITICAL FIX: Ensure the endpoint uses the WireGuard port
				// The STUN-discovered port might be different due to NAT, but peers
				// should connect to the port that WireGuard is actually listening on
				ep.Port = c.localPort
				if !isQuiet {
					fmt.Printf("Final public endpoint (adjusted for WireGuard): %s\n", ep.String())
				}

				// Store the endpoint for keepalive reference
				c.lastEndpoint = &ep
				return ep, nil
			}
			lastErr = err
			if !isQuiet {
				fmt.Printf("STUN server %s failed: %v\n", serverAddr, err)
			}
		}
	}

	if lastErr != nil {
		return endpoint, fmt.Errorf("all STUN servers failed: %v", lastErr)
	}
	return endpoint, fmt.Errorf("no STUN servers available")
}

// discoverWithServer attempts to discover the public endpoint using a specific STUN server
func (c *DiscoveryClient) discoverWithServer(serverAddr string, isQuiet bool) (Endpoint, error) {
	var endpoint Endpoint

	// Create a connection to the STUN server, binding to our specified local port if set
	var conn net.Conn
	var err error

	if c.localPort > 0 {
		// Create a specific local address to bind to
		localAddr := &net.UDPAddr{
			IP:   net.ParseIP("0.0.0.0"),
			Port: c.localPort,
		}

		// Resolve the STUN server address
		stunAddr, err := net.ResolveUDPAddr("udp4", serverAddr)
		if err != nil {
			return endpoint, fmt.Errorf("failed to resolve STUN server address %s: %v", serverAddr, err)
		}

		// Create a connection with the specific local address
		conn, err = net.DialUDP("udp4", localAddr, stunAddr)
		if err != nil {
			if !isQuiet {
				fmt.Printf("Warning: Failed to bind to local port %d for STUN: %v\n", c.localPort, err)
			}
			// Fall back to any port
			conn, err = net.Dial("udp4", serverAddr)
			if err != nil {
				return endpoint, fmt.Errorf("failed to connect to STUN server %s: %v", serverAddr, err)
			}
		} else {
			if !isQuiet {
				fmt.Printf("Successfully bound to local port %d for STUN\n", c.localPort)
			}
		}
	} else {
		// Use any available port
		conn, err = net.Dial("udp4", serverAddr)
		if err != nil {
			return endpoint, fmt.Errorf("failed to connect to STUN server %s: %v", serverAddr, err)
		}
	}
	defer conn.Close()

	// Get the local address we're using
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if !isQuiet {
		fmt.Printf("Using local port %d for STUN discovery\n", localAddr.Port)
	}

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

	if !isQuiet {
		fmt.Printf("STUN server %s reports public endpoint: %s:%d\n",
			serverAddr, endpoint.IP.String(), endpoint.Port)
	}

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

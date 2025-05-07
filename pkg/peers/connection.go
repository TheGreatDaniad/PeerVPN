package peers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/danialdehvan/PeerVPN/pkg/nat"
	"github.com/danialdehvan/PeerVPN/pkg/routing"
	"github.com/danialdehvan/PeerVPN/pkg/wireguard"
)

// ConnectionManager handles peer connections
type ConnectionManager struct {
	wgManager      *wireguard.WireGuardManager
	routingManager *routing.RoutingManager
	natDiscovery   *nat.DiscoveryClient
	localPeerInfo  *PeerInfo
	interfaceName  string
	clientSubnet   string
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
		wgManager:      wgManager,
		routingManager: routingManager,
		natDiscovery:   natDiscovery,
		localPeerInfo:  localPeerInfo,
		interfaceName:  interfaceName,
		clientSubnet:   clientSubnet,
	}
}

// ConnectToPeer connects to a peer using their public key and endpoint
func (cm *ConnectionManager) ConnectToPeer(peerPublicKey, peerEndpoint string) error {
	// Set up WireGuard interface if needed
	if err := cm.wgManager.SetupInterface(); err != nil {
		return fmt.Errorf("failed to set up WireGuard interface: %v", err)
	}

	// Enable IP forwarding if this is an exit node
	if cm.localPeerInfo.IsExitNode {
		if err := cm.routingManager.EnableIPForwarding(); err != nil {
			return fmt.Errorf("failed to enable IP forwarding: %v", err)
		}
	}

	// Add peer to WireGuard configuration
	var allowedIPs []string
	if cm.localPeerInfo.IsExitNode {
		// If we're an exit node, we only route traffic from the client subnet
		allowedIPs = []string{cm.clientSubnet}
	} else {
		// If we're a client, route all traffic through the exit node
		allowedIPs = []string{"0.0.0.0/0"}
	}

	// Add the peer to WireGuard
	if err := cm.wgManager.AddPeer(peerPublicKey, peerEndpoint, allowedIPs); err != nil {
		return fmt.Errorf("failed to add peer to WireGuard: %v", err)
	}

	// Set up routing
	if err := cm.routingManager.SetupRouting(cm.clientSubnet); err != nil {
		return fmt.Errorf("failed to set up routing: %v", err)
	}

	return nil
}

// Disconnect disconnects from the VPN
func (cm *ConnectionManager) Disconnect() error {
	// Clean up routing
	if err := cm.routingManager.CleanupRouting(); err != nil {
		return fmt.Errorf("failed to clean up routing: %v", err)
	}

	// Tear down WireGuard interface
	if err := cm.wgManager.TearDown(); err != nil {
		return fmt.Errorf("failed to tear down WireGuard interface: %v", err)
	}

	return nil
}

// DiscoverEndpoint discovers our public endpoint using STUN
func (cm *ConnectionManager) DiscoverEndpoint(ctx context.Context) (string, error) {
	endpoint, err := cm.natDiscovery.DiscoverPublicEndpoint(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to discover public endpoint: %v", err)
	}

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
	if err := cm.wgManager.SetupInterface(); err != nil {
		return fmt.Errorf("failed to set up WireGuard interface: %v", err)
	}

	// Enable IP forwarding
	if err := cm.routingManager.EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Discover our public endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint, err := cm.DiscoverEndpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover public endpoint: %v", err)
	}

	// Update local peer info with the endpoint
	cm.localPeerInfo.Endpoint = endpoint
	cm.localPeerInfo.AllowedSubnets = cm.clientSubnet

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

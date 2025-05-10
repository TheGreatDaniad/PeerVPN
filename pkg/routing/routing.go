package routing

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// RoutingManager handles the routing and network configuration for the VPN
type RoutingManager struct {
	interfaceName string
	isExitNode    bool
}

// NewRoutingManager creates a new routing manager
func NewRoutingManager(interfaceName string, isExitNode bool) *RoutingManager {
	return &RoutingManager{
		interfaceName: interfaceName,
		isExitNode:    isExitNode,
	}
}

// EnableIPForwarding enables IP forwarding for the exit node
func (r *RoutingManager) EnableIPForwarding() error {
	if !r.isExitNode {
		return nil // Only exit nodes need IP forwarding
	}

	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("enabling IP forwarding requires root privileges")
	}

	var err error
	switch runtime.GOOS {
	case "linux":
		err = r.enableIPForwardingLinux()
	case "darwin":
		err = r.enableIPForwardingDarwin()
	case "windows":
		err = r.enableIPForwardingWindows()
	default:
		err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return err
}

// SetupRouting configures the routing based on the node type
func (r *RoutingManager) SetupRouting(clientSubnet string) error {
	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("setting up routing requires root privileges")
	}

	var err error
	if r.isExitNode {
		switch runtime.GOOS {
		case "linux":
			err = r.setupExitRoutingLinux(clientSubnet)
		case "darwin":
			err = r.setupExitRoutingDarwin(clientSubnet)
		case "windows":
			err = r.setupExitRoutingWindows(clientSubnet)
		default:
			err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	} else {
		switch runtime.GOOS {
		case "linux":
			err = r.setupClientRoutingLinux()
		case "darwin":
			err = r.setupClientRoutingDarwin()
		case "windows":
			err = r.setupClientRoutingWindows()
		default:
			err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	}

	return err
}

// CleanupRouting removes the routing configuration
func (r *RoutingManager) CleanupRouting() error {
	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("cleaning up routing requires root privileges")
	}

	var err error
	switch runtime.GOOS {
	case "linux":
		err = r.cleanupRoutingLinux()
	case "darwin":
		err = r.cleanupRoutingDarwin()
	case "windows":
		err = r.cleanupRoutingWindows()
	default:
		err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return err
}

// Linux implementations
func (r *RoutingManager) enableIPForwardingLinux() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}
	return nil
}

func (r *RoutingManager) setupExitRoutingLinux(clientSubnet string) error {
	// Set up NAT for packets coming from VPN clients
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", clientSubnet, "-o", "eth0", "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set up NAT: %v", err)
	}

	// Allow forwarding through the firewall
	cmd = exec.Command("iptables", "-A", "FORWARD", "-i", r.interfaceName, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure forwarding: %v", err)
	}

	cmd = exec.Command("iptables", "-A", "FORWARD", "-o", r.interfaceName, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure forwarding: %v", err)
	}

	return nil
}

func (r *RoutingManager) setupClientRoutingLinux() error {
	// Get the default gateway
	gatewayBytes, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}

	gateway := strings.Fields(string(gatewayBytes))[2]

	// Add a route for all traffic through the WireGuard interface
	cmd := exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", r.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	cmd = exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", r.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	// Preserve the route to the gateway
	cmd = exec.Command("ip", "route", "add", gateway, "via", gateway)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to preserve gateway route: %v", err)
	}

	return nil
}

func (r *RoutingManager) cleanupRoutingLinux() error {
	if r.isExitNode {
		// Clean up NAT rules
		cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/24", "-o", "eth0", "-j", "MASQUERADE")
		_ = cmd.Run() // Ignore errors as the rule might not exist

		// Clean up forwarding rules
		cmd = exec.Command("iptables", "-D", "FORWARD", "-i", r.interfaceName, "-j", "ACCEPT")
		_ = cmd.Run()

		cmd = exec.Command("iptables", "-D", "FORWARD", "-o", r.interfaceName, "-j", "ACCEPT")
		_ = cmd.Run()
	} else {
		// Remove the routes we added
		cmd := exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", r.interfaceName)
		_ = cmd.Run()

		cmd = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", r.interfaceName)
		_ = cmd.Run()
	}

	return nil
}

// macOS implementations
func (r *RoutingManager) enableIPForwardingDarwin() error {
	cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}
	return nil
}

func (r *RoutingManager) setupExitRoutingDarwin(clientSubnet string) error {
	fmt.Println("Setting up exit node routing on macOS...")

	// Get the main interface name
	ifconfigBytes, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default interface: %v", err)
	}

	ifconfigStr := string(ifconfigBytes)
	fmt.Printf("Default route info:\n%s\n", ifconfigStr)

	var mainInterface string
	for _, line := range strings.Split(ifconfigStr, "\n") {
		if strings.Contains(line, "interface") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				mainInterface = fields[len(fields)-1]
				break
			}
		}
	}

	if mainInterface == "" {
		return fmt.Errorf("could not determine main interface")
	}

	fmt.Printf("Using main interface: %s\n", mainInterface)

	// Get information about the main interface
	ifconfigMainBytes, err := exec.Command("ifconfig", mainInterface).Output()
	if err != nil {
		return fmt.Errorf("failed to get main interface info: %v", err)
	}

	fmt.Printf("Main interface details:\n%s\n", string(ifconfigMainBytes))

	// Enable NAT for traffic coming from VPN clients
	fmt.Println("Setting up NAT for client traffic...")

	// Create PF rules using anchors
	pfRules := fmt.Sprintf(`# PeerVPN NAT configuration
nat on %s from %s to any -> (%s)
pass out on %s from %s to any
pass in on %s from any to %s
pass on %s from %s to any
pass inet proto icmp all
`, mainInterface, clientSubnet, mainInterface, mainInterface, clientSubnet, r.interfaceName, clientSubnet, r.interfaceName, clientSubnet)

	fmt.Printf("Setting up PF rules:\n%s\n", pfRules)

	// Write the NAT rules to a temporary file
	natFile, err := os.CreateTemp("", "peervpn-nat-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create NAT rules file: %v", err)
	}

	natPath := natFile.Name()
	fmt.Printf("Writing NAT rules to: %s\n", natPath)

	if _, err := natFile.WriteString(pfRules); err != nil {
		natFile.Close()
		os.Remove(natPath)
		return fmt.Errorf("failed to write NAT rules file: %v", err)
	}
	natFile.Close()

	// First check if PF is enabled
	_, err = exec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		// Try to enable PF if it's not already enabled
		fmt.Println("Enabling PF...")
		enableCmd := exec.Command("pfctl", "-e")
		if err := enableCmd.Run(); err != nil {
			fmt.Printf("Warning: Could not enable PF, will try to continue: %v\n", err)
		}
	}

	// Create anchor if it doesn't exist
	fmt.Println("Ensuring anchor exists...")
	anchorCmd := exec.Command("pfctl", "-N", "com.peervpn")
	anchorCmd.Run() // Ignore error as anchor might already exist

	// Apply the NAT rules to the anchor
	fmt.Println("Applying NAT rules to anchor...")
	cmd := exec.Command("pfctl", "-a", "com.peervpn", "-f", natPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(natPath)
		return fmt.Errorf("failed to apply NAT rules to anchor: %v\nOutput: %s", err, string(output))
	}

	// Keep the NAT file for reference and debugging
	fmt.Printf("NAT rules applied successfully. Rules file: %s\n", natPath)

	// Verify the anchor is loaded
	fmt.Println("Verifying anchor status...")
	anchorStatus, err := exec.Command("pfctl", "-a", "com.peervpn", "-s", "rules").CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Failed to get anchor status: %v\n", err)
	} else {
		fmt.Printf("Anchor rules:\n%s\n", string(anchorStatus))
	}

	fmt.Println("Exit node routing setup complete")
	return nil
}

func (r *RoutingManager) setupClientRoutingDarwin() error {
	fmt.Println("Setting up client routing on macOS...")

	// Get the default gateway and interface
	routeBytes, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}

	routeStr := string(routeBytes)
	fmt.Printf("Default route info:\n%s\n", routeStr)

	var gateway, gatewayInterface string
	for _, line := range strings.Split(routeStr, "\n") {
		if strings.Contains(line, "gateway") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				gateway = fields[len(fields)-1]
			}
		}
		if strings.Contains(line, "interface") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				gatewayInterface = fields[len(fields)-1]
			}
		}
	}

	if gateway == "" {
		return fmt.Errorf("could not determine default gateway")
	}
	if gatewayInterface == "" {
		return fmt.Errorf("could not determine default interface")
	}

	fmt.Printf("Found gateway %s on interface %s\n", gateway, gatewayInterface)

	// First preserve routes to the gateway's network to maintain connectivity
	// Get netmask for gateway network
	gatewayNetworkBytes, err := exec.Command("ifconfig", gatewayInterface).Output()
	if err != nil {
		return fmt.Errorf("failed to get gateway interface info: %v", err)
	}

	fmt.Printf("Gateway interface info:\n%s\n", string(gatewayNetworkBytes))

	var gatewayNetwork string
	for _, line := range strings.Split(string(gatewayNetworkBytes), "\n") {
		if strings.Contains(line, "inet ") && strings.Contains(line, "netmask") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				ipParts := strings.Split(parts[1], ".")
				// Assuming a class C network
				if len(ipParts) == 4 {
					gatewayNetwork = fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
				}
			}
		}
	}

	if gatewayNetwork == "" {
		// Fallback to assuming a /24 network based on gateway IP
		ipParts := strings.Split(gateway, ".")
		if len(ipParts) == 4 {
			gatewayNetwork = fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
		} else {
			return fmt.Errorf("could not determine gateway network")
		}
	}

	fmt.Printf("Preserving route to gateway network %s\n", gatewayNetwork)

	// Add a direct route to the gateway's network
	cmd := exec.Command("route", "-n", "add", "-net", gatewayNetwork, "-interface", gatewayInterface)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to add route to gateway network: %v\n", err)
		// Continue anyway as this might not be critical
	}

	// Add a specific route for the gateway itself
	cmd = exec.Command("route", "-n", "add", gateway, "-interface", gatewayInterface)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to add direct route to gateway: %v\n", err)
		// Continue anyway
	}

	// Add routes for DNS servers to ensure they're reachable
	// Get DNS servers
	resolvConfBytes, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(resolvConfBytes), "\n") {
			if strings.HasPrefix(line, "nameserver ") {
				dnsServer := strings.TrimPrefix(line, "nameserver ")
				fmt.Printf("Adding direct route to DNS server %s\n", dnsServer)
				cmd = exec.Command("route", "-n", "add", dnsServer, "-interface", gatewayInterface)
				_ = cmd.Run() // Ignore errors
			}
		}
	}

	// Now add routes for all traffic through the WireGuard interface
	fmt.Println("Adding routes for general traffic via WireGuard interface...")
	cmd = exec.Command("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", r.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route 0.0.0.0/1: %v", err)
	}

	cmd = exec.Command("route", "-n", "add", "-net", "128.0.0.0/1", "-interface", r.interfaceName)
	if err := cmd.Run(); err != nil {
		// If this fails, try to clean up the previous route
		_ = exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1").Run()
		return fmt.Errorf("failed to add route 128.0.0.0/1: %v", err)
	}

	fmt.Println("Client routing setup complete")

	return nil
}

func (r *RoutingManager) cleanupRoutingDarwin() error {
	fmt.Println("Cleaning up routing on macOS...")

	if r.isExitNode {
		// Clean up anchor
		fmt.Println("Cleaning up NAT rules from anchor...")
		cmd := exec.Command("pfctl", "-a", "com.peervpn", "-F", "all")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to flush anchor rules: %v\n", err)
		}
	} else {
		// Remove the routes we added
		fmt.Println("Removing client routes...")

		// First try to restore default route
		// Get the default gateway and interface
		routeBytes, err := exec.Command("route", "-n", "get", "8.8.8.8").Output()
		if err == nil {
			// Try to parse the gateway from the route
			routeStr := string(routeBytes)
			fmt.Printf("Default route info (before cleanup):\n%s\n", routeStr)
		}

		// Remove split tunnel routes
		fmt.Println("Removing route 0.0.0.0/1...")
		cmd := exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Could not remove route 0.0.0.0/1: %v\n", err)
		}

		fmt.Println("Removing route 128.0.0.0/1...")
		cmd = exec.Command("route", "-n", "delete", "-net", "128.0.0.0/1")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Could not remove route 128.0.0.0/1: %v\n", err)
		}

		// Flush the routing table cache
		fmt.Println("Flushing routing table cache...")
		cmd = exec.Command("route", "-n", "flush")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Could not flush routing table: %v\n", err)
		}

		// Check if default route is still there
		routeBytes, err = exec.Command("route", "-n", "get", "default").Output()
		if err == nil {
			routeStr := string(routeBytes)
			fmt.Printf("Default route info (after cleanup):\n%s\n", routeStr)
		} else {
			fmt.Printf("Warning: Could not get default route after cleanup: %v\n", err)
		}
	}

	fmt.Println("Routing cleanup complete")
	return nil
}

// Windows implementations
func (r *RoutingManager) enableIPForwardingWindows() error {
	// On Windows, IP forwarding is usually configured per interface in the registry
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters -Name IPEnableRouter -Value 1"))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Restart the routing service to apply changes
	cmd = exec.Command("net", "stop", "RemoteAccess")
	_ = cmd.Run() // Ignore errors as the service might not be running

	cmd = exec.Command("net", "start", "RemoteAccess")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart routing service: %v", err)
	}

	return nil
}

func (r *RoutingManager) setupExitRoutingWindows(clientSubnet string) error {
	// Get the index of the WireGuard interface
	interfaceIdxBytes, err := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", r.interfaceName)).Output()
	if err != nil {
		return fmt.Errorf("failed to get interface index: %v", err)
	}
	interfaceIdx := strings.TrimSpace(string(interfaceIdxBytes))

	// Get the index of the internet-connected interface
	internetIfIdxBytes, err := exec.Command("powershell", "-Command",
		"(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Wireguard'} | Select-Object -First 1).ifIndex").Output()
	if err != nil {
		return fmt.Errorf("failed to get internet interface index: %v", err)
	}
	internetIfIdx := strings.TrimSpace(string(internetIfIdxBytes))

	// Set up IP routing
	cmd := exec.Command("route", "add", clientSubnet, "mask", "255.255.255.0", "0.0.0.0", "METRIC", "3", "IF", interfaceIdx)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route for client subnet: %v", err)
	}

	// Enable NAT
	cmd = exec.Command("netsh", "interface", "portproxy", "reset")
	_ = cmd.Run() // Ignore errors as no config might exist

	cmd = exec.Command("netsh", "interface", "nat", "add", "full", internetIfIdx, interfaceIdx)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set up NAT: %v", err)
	}

	return nil
}

func (r *RoutingManager) setupClientRoutingWindows() error {
	// Get the index of the WireGuard interface
	interfaceIdxBytes, err := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", r.interfaceName)).Output()
	if err != nil {
		return fmt.Errorf("failed to get interface index: %v", err)
	}
	interfaceIdx := strings.TrimSpace(string(interfaceIdxBytes))

	// Get the default gateway
	gatewayBytes, err := exec.Command("powershell", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop").Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}
	gateway := strings.TrimSpace(string(gatewayBytes))

	// Route traffic through the WireGuard interface
	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "METRIC", "3", "IF", interfaceIdx)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	cmd = exec.Command("route", "add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "METRIC", "3", "IF", interfaceIdx)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	// Preserve the route to the gateway
	cmd = exec.Command("route", "add", gateway, "mask", "255.255.255.255", gateway, "METRIC", "1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to preserve gateway route: %v", err)
	}

	return nil
}

func (r *RoutingManager) cleanupRoutingWindows() error {
	if r.isExitNode {
		// Clean up NAT
		cmd := exec.Command("netsh", "interface", "nat", "reset")
		_ = cmd.Run() // Ignore errors
	} else {
		// Remove the routes we added
		cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
		_ = cmd.Run()

		cmd = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
		_ = cmd.Run()
	}

	return nil
}

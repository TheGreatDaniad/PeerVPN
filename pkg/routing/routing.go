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
	// Get the main interface name
	ifconfigBytes, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default interface: %v", err)
	}

	ifconfigStr := string(ifconfigBytes)
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

	// Enable NAT for traffic coming from VPN clients
	cmd := exec.Command("pfctl", "-t", "nat-anchor", "nat-rules", "-Tflush")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush NAT rules: %v", err)
	}

	natRules := fmt.Sprintf("nat on %s from %s to any -> (%s)\n", mainInterface, clientSubnet, mainInterface)

	// Write the NAT rules to a temporary file
	natFile, err := os.CreateTemp("", "nat-rules-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create NAT rules file: %v", err)
	}
	defer os.Remove(natFile.Name())

	if _, err := natFile.WriteString(natRules); err != nil {
		return fmt.Errorf("failed to write NAT rules file: %v", err)
	}
	natFile.Close()

	// Apply the NAT rules
	cmd = exec.Command("pfctl", "-f", natFile.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply NAT rules: %v", err)
	}

	return nil
}

func (r *RoutingManager) setupClientRoutingDarwin() error {
	// Get the default gateway
	routeBytes, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}

	routeStr := string(routeBytes)
	var gateway string
	for _, line := range strings.Split(routeStr, "\n") {
		if strings.Contains(line, "gateway") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				gateway = fields[len(fields)-1]
				break
			}
		}
	}

	if gateway == "" {
		return fmt.Errorf("could not determine default gateway")
	}

	// Add routes for all traffic through the WireGuard interface
	cmd := exec.Command("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", r.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	cmd = exec.Command("route", "-n", "add", "-net", "128.0.0.0/1", "-interface", r.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	// Preserve the route to the gateway
	cmd = exec.Command("route", "-n", "add", gateway, gateway)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to preserve gateway route: %v", err)
	}

	return nil
}

func (r *RoutingManager) cleanupRoutingDarwin() error {
	if r.isExitNode {
		// Clean up NAT rules (this is simplified and may need adjustment)
		cmd := exec.Command("pfctl", "-t", "nat-anchor", "nat-rules", "-Tflush")
		_ = cmd.Run() // Ignore errors as it might not exist
	} else {
		// Remove the routes we added
		cmd := exec.Command("route", "-n", "delete", "-net", "0.0.0.0/1")
		_ = cmd.Run()

		cmd = exec.Command("route", "-n", "delete", "-net", "128.0.0.0/1")
		_ = cmd.Run()
	}

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

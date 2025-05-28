package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// BinaryPath returns the path to the WireGuard binaries based on the OS
func BinaryPath(binary string) string {
	// Get the directory of the executable
	exePath, err := os.Executable()
	if err != nil {
		// Fallback to current working directory
		cwd, err := os.Getwd()
		if err != nil {
			return binary // Just return the binary name and hope it's in PATH
		}
		exePath = cwd
	}

	// Determine the OS-specific path
	var osDir string
	switch runtime.GOOS {
	case "linux":
		osDir = "linux"
	case "darwin":
		osDir = "darwin"
	case "windows":
		osDir = "windows"
		// Add .exe extension for Windows
		if !strings.HasSuffix(binary, ".exe") {
			binary += ".exe"
		}
	default:
		return binary // Unknown OS, hope it's in PATH
	}

	// Construct the path to the bundled binary
	bundledPath := filepath.Join(filepath.Dir(exePath), "bin", osDir, binary)

	// Check if the bundled binary exists
	if _, err := os.Stat(bundledPath); err == nil {
		return bundledPath
	}

	// Try one level up (for development environments)
	projectRootPath := filepath.Join(filepath.Dir(exePath), "..", "bin", osDir, binary)
	if _, err := os.Stat(projectRootPath); err == nil {
		return projectRootPath
	}

	// As a fallback, look in the project directory relative to the current directory
	cwdPath := filepath.Join("bin", osDir, binary)
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath
	}

	// Last resort, hope it's in PATH
	return binary
}

// WireGuardManager handles WireGuard interface operations
type WireGuardManager struct {
	interfaceName string
	privateKey    wgtypes.Key
	listenPort    int
	addresses     []string
}

// NewWireGuardManager creates a new WireGuard manager
func NewWireGuardManager(interfaceName string, privateKeyStr string, listenPort int, addresses []string) (*WireGuardManager, error) {
	var privateKey wgtypes.Key
	var err error

	// If private key is provided, parse it; otherwise, generate a new one
	if privateKeyStr != "" {
		privateKey, err = wgtypes.ParseKey(privateKeyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}
	}

	// Use a default port if none is specified
	if listenPort <= 0 {
		listenPort = 51820
	}

	// Simple port availability check and fallback
	finalPort := listenPort
	if !isPortAvailable(listenPort) {
		fmt.Printf("Port %d is in use, finding alternative...\n", listenPort)

		// Try a few common alternatives
		alternatives := []int{51821, 51822, 51823, 41194, 1194}
		found := false

		for _, port := range alternatives {
			if isPortAvailable(port) {
				finalPort = port
				found = true
				fmt.Printf("Using alternative port: %d\n", finalPort)
				break
			}
		}

		if !found {
			// Find any available port in a reasonable range
			for port := 30000; port <= 35000; port++ {
				if isPortAvailable(port) {
					finalPort = port
					found = true
					fmt.Printf("Using available port: %d\n", finalPort)
					break
				}
			}
		}

		if !found {
			return nil, fmt.Errorf("could not find any available UDP port for WireGuard")
		}
	} else {
		fmt.Printf("Using requested port: %d\n", finalPort)
	}

	return &WireGuardManager{
		interfaceName: interfaceName,
		privateKey:    privateKey,
		listenPort:    finalPort,
		addresses:     addresses,
	}, nil
}

// isPortAvailable checks if a UDP port is available
func isPortAvailable(port int) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GetPrivateKey returns the private key as a string
func (wg *WireGuardManager) GetPrivateKey() string {
	return wg.privateKey.String()
}

// GetPublicKey returns the public key as a string
func (wg *WireGuardManager) GetPublicKey() string {
	return wg.privateKey.PublicKey().String()
}

// GetListenPort returns the current listening port
func (wg *WireGuardManager) GetListenPort() int {
	return wg.listenPort
}

// VerifyDependencies checks if required WireGuard tools are available
func VerifyDependencies() error {
	// Check for wg binary
	wgBinary := BinaryPath("wg")
	if _, err := exec.LookPath(wgBinary); err != nil {
		// Try to find wg in PATH as fallback
		if _, err := exec.LookPath("wg"); err != nil {
			return fmt.Errorf("WireGuard 'wg' binary not found. Please install WireGuard tools")
		}
	}

	// Test if wg binary actually works
	cmd := exec.Command(wgBinary, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WireGuard binary test failed: %v - %s", err, string(output))
	}

	fmt.Printf("WireGuard tools verified: %s\n", strings.TrimSpace(string(output)))

	// Platform-specific checks
	switch runtime.GOOS {
	case "darwin":
		// Check for wireguard-go
		wgGoBinary := BinaryPath("wireguard-go")
		if _, err := exec.LookPath(wgGoBinary); err != nil {
			if _, err := exec.LookPath("wireguard-go"); err != nil {
				return fmt.Errorf("WireGuard-go binary not found. Please install: brew install wireguard-tools")
			}
		}

		// Test wireguard-go
		cmd := exec.Command(wgGoBinary, "--version")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: wireguard-go test failed: %v\n", err)
		}

	case "linux":
		// Check if WireGuard kernel module is available
		if _, err := os.Stat("/sys/module/wireguard"); err != nil {
			fmt.Println("Warning: WireGuard kernel module not detected. Make sure WireGuard is installed.")
		}

	case "windows":
		// On Windows, we need the WireGuard service
		wgBinary := BinaryPath("wireguard")
		if _, err := exec.LookPath(wgBinary); err != nil {
			return fmt.Errorf("WireGuard Windows binary not found. Please install WireGuard for Windows")
		}
	}

	return nil
}

// SetupInterface creates and configures the WireGuard interface
func (wg *WireGuardManager) SetupInterface() error {
	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("WireGuard setup requires root privileges")
	}

	var err error
	switch runtime.GOOS {
	case "linux":
		err = wg.setupLinux()
	case "darwin":
		err = wg.setupDarwin()
	case "windows":
		err = wg.setupWindows()
	default:
		err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return err
}

// AddPeer adds a peer to the WireGuard interface
func (wg *WireGuardManager) AddPeer(publicKey string, endpoint string, allowedIPs []string) error {
	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("WireGuard configuration requires root privileges")
	}

	fmt.Printf("Adding WireGuard peer:\n")
	fmt.Printf("  Interface:  %s\n", wg.interfaceName)
	fmt.Printf("  Peer:       %s\n", publicKey)
	fmt.Printf("  Endpoint:   %s\n", endpoint)
	fmt.Printf("  AllowedIPs: %s\n", strings.Join(allowedIPs, ", "))

	// First check if interface exists and is up
	cmd := exec.Command("ifconfig", wg.interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Interface check failed: %v\n%s\n", err, string(output))
		// Continue anyway, as the error might be just in checking, not a real problem
	} else {
		fmt.Printf("Interface %s status:\n%s\n", wg.interfaceName, string(output))
	}

	var addErr error
	switch runtime.GOOS {
	case "linux":
		addErr = wg.addPeerLinux(publicKey, endpoint, allowedIPs)
	case "darwin":
		addErr = wg.addPeerDarwin(publicKey, endpoint, allowedIPs)
	case "windows":
		addErr = wg.addPeerWindows(publicKey, endpoint, allowedIPs)
	default:
		addErr = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	if addErr != nil {
		fmt.Printf("Error adding peer: %v\n", addErr)
		return addErr
	}

	fmt.Println("Peer added successfully")

	// Verify the peer was added by showing the wireguard configuration
	wgBinary := BinaryPath("wg")
	cmd = exec.Command(wgBinary, "show", wg.interfaceName)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Could not verify peer configuration: %v\n", err)
	} else {
		fmt.Printf("WireGuard configuration after adding peer:\n%s\n", string(output))
	}

	// Force an initial handshake to establish the connection
	fmt.Println("Attempting to initiate handshake...")
	if endpoint != "" {
		cmd = exec.Command(wgBinary, "set", wg.interfaceName, "peer", publicKey, "endpoint", endpoint)
		output, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Warning: Could not initiate handshake: %v\n%s\n", err, string(output))
		} else {
			fmt.Println("Handshake initiation request sent")
		}
	}

	return nil
}

// TearDown removes the WireGuard interface
func (wg *WireGuardManager) TearDown() error {
	// Check if we have sufficient permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("WireGuard teardown requires root privileges")
	}

	var err error
	switch runtime.GOOS {
	case "linux":
		err = wg.tearDownLinux()
	case "darwin":
		err = wg.tearDownDarwin()
	case "windows":
		err = wg.tearDownWindows()
	default:
		err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return err
}

// Platform-specific implementations
func (wg *WireGuardManager) setupLinux() error {
	// Create WireGuard interface using ip command
	cmd := exec.Command("ip", "link", "add", wg.interfaceName, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %v", err)
	}

	// Configure WireGuard interface using bundled wg binary
	wgBinary := BinaryPath("wg")
	cmd = exec.Command(wgBinary, "set", wg.interfaceName,
		"private-key", "/dev/stdin",
		"listen-port", fmt.Sprintf("%d", wg.listenPort))
	cmd.Stdin = strings.NewReader(wg.privateKey.String())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure WireGuard interface: %v", err)
	}

	// Configure IP addresses
	for _, addr := range wg.addresses {
		cmd = exec.Command("ip", "address", "add", "dev", wg.interfaceName, addr)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure IP address %s: %v", addr, err)
		}
	}

	// Set interface up
	cmd = exec.Command("ip", "link", "set", wg.interfaceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set interface up: %v", err)
	}

	return nil
}

func (wg *WireGuardManager) setupDarwin() error {
	// macOS implementation uses wireguard-go and the wireguard-tools package

	// Get the path to bundled binaries
	wgGoBinary := BinaryPath("wireguard-go")
	wgBinary := BinaryPath("wg")

	// Make sure we have a utun interface name on macOS
	if !strings.HasPrefix(wg.interfaceName, "utun") {
		return fmt.Errorf("on macOS, WireGuard interface name must start with 'utun' followed by a number")
	}

	// First check if the interface already exists and try to clean it up
	fmt.Printf("Checking if interface %s already exists...\n", wg.interfaceName)
	checkCmd := exec.Command("ifconfig", wg.interfaceName)
	if err := checkCmd.Run(); err == nil {
		// Interface exists, try to clean it up
		fmt.Printf("Interface %s already exists, attempting to clean up...\n", wg.interfaceName)

		// First try to find and kill the wireguard-go process
		fmt.Println("Looking for wireguard-go processes...")
		psCmd := exec.Command("pgrep", "-f", fmt.Sprintf("wireguard-go %s", wg.interfaceName))
		if pidBytes, err := psCmd.Output(); err == nil && len(pidBytes) > 0 {
			pid := strings.TrimSpace(string(pidBytes))
			fmt.Printf("Found wireguard-go process (PID: %s), terminating...\n", pid)
			killCmd := exec.Command("kill", pid)
			if err := killCmd.Run(); err != nil {
				fmt.Printf("Warning: Failed to kill process: %v\n", err)
			}
			// Wait a moment for the process to terminate
			time.Sleep(500 * time.Millisecond)
		}

		// Try to remove the interface directly
		removeCmd := exec.Command("ifconfig", wg.interfaceName, "destroy")
		if err := removeCmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to destroy interface: %v\n", err)
			// Try a different interface name as fallback
			newName := wg.interfaceName
			for i := 0; i < 5; i++ {
				// Try incrementing the number at the end
				parts := strings.Split(newName, "utun")
				if len(parts) == 2 {
					num, err := strconv.Atoi(parts[1])
					if err == nil {
						newName = fmt.Sprintf("utun%d", num+1)
						fmt.Printf("Will try alternative interface name: %s\n", newName)
						wg.interfaceName = newName
						break
					}
				}
			}
		} else {
			fmt.Printf("Successfully removed existing interface %s\n", wg.interfaceName)
			// Wait a moment to ensure cleanup is complete
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Generate a temporary configuration file
	configFile, err := os.CreateTemp("", "wg-config-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write configuration
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d
`, wg.privateKey.String(), wg.listenPort)

	if _, err := configFile.WriteString(config); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	configFile.Close()

	// Double-check for any existing processes with the same interface
	fmt.Println("Double-checking for any existing wireguard-go processes...")
	killCmd := exec.Command("pkill", "-f", fmt.Sprintf("wireguard-go.*%s", wg.interfaceName))
	_ = killCmd.Run() // Ignore any errors

	// Set up the WireGuard interface
	fmt.Printf("Creating WireGuard interface %s...\n", wg.interfaceName)
	cmd := exec.Command(wgGoBinary, wg.interfaceName)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %v - %s", err, string(cmdOutput))
	}

	// Wait for the interface to be ready
	time.Sleep(500 * time.Millisecond)

	// Apply the configuration
	fmt.Printf("Applying WireGuard configuration (port %d)...\n", wg.listenPort)
	cmd = exec.Command(wgBinary, "setconf", wg.interfaceName, configFile.Name())
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		// If this fails, we need to clean up the interface we just created
		fmt.Printf("Error configuring WireGuard: %v - %s\n", err, string(cmdOutput))
		fmt.Println("Cleaning up...")
		teardownCmd := exec.Command("pkill", "-f", fmt.Sprintf("wireguard-go %s", wg.interfaceName))
		_ = teardownCmd.Run()

		// See if port is the issue
		if strings.Contains(string(cmdOutput), "Address already in use") {
			fmt.Println("Port conflict detected. You may need to restart your computer or choose a different port.")
			fmt.Println("Trying a temporary workaround...")

			// Try with a new random port by creating a new config file
			newPort := wg.listenPort + 100 // Just add 100 to get a likely unused port
			fmt.Printf("Trying with port %d instead...\n", newPort)

			newConfigFile, err := os.CreateTemp("", "wg-config-*.conf")
			if err != nil {
				return fmt.Errorf("failed to create new config file: %v", err)
			}
			defer os.Remove(newConfigFile.Name())

			newConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d
`, wg.privateKey.String(), newPort)

			if _, err := newConfigFile.WriteString(newConfig); err != nil {
				return fmt.Errorf("failed to write new config file: %v", err)
			}
			newConfigFile.Close()

			// Try with the new port
			cmd = exec.Command(wgBinary, "setconf", wg.interfaceName, newConfigFile.Name())
			cmdOutput, err = cmd.CombinedOutput()
			if err != nil {
				// Give up
				return fmt.Errorf("failed to configure WireGuard with alternate port: %v - %s", err, string(cmdOutput))
			}

			// Update the port if it worked
			wg.listenPort = newPort
			fmt.Printf("Successfully configured WireGuard with port %d\n", newPort)
		} else {
			// Some other error
			return fmt.Errorf("failed to configure WireGuard interface: %v - %s", err, string(cmdOutput))
		}
	}

	// Configure IP addresses
	for _, addr := range wg.addresses {
		// Parse the CIDR notation to get IP and netmask
		ipAddr, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("failed to parse IP address %s: %v", addr, err)
		}

		// Format for macOS ifconfig: ifconfig interface inet IP DEST netmask MASK
		// For point-to-point interfaces like utun, both IP and destination are the same
		fmt.Printf("Configuring IP address %s on interface %s...\n", addr, wg.interfaceName)
		cmd = exec.Command("ifconfig", wg.interfaceName, "inet", ipAddr.String(),
			ipAddr.String(), "netmask", fmt.Sprintf("0x%x", binary.BigEndian.Uint32(ipNet.Mask)))
		cmdOutput, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to configure IP address %s: %v - %s", addr, err, string(cmdOutput))
		}
	}

	// Set interface up
	fmt.Printf("Setting interface %s up...\n", wg.interfaceName)
	cmd = exec.Command("ifconfig", wg.interfaceName, "up")
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set interface up: %v - %s", err, string(cmdOutput))
	}

	// Verify the configuration was applied correctly
	fmt.Println("Verifying WireGuard configuration...")
	cmd = exec.Command(wgBinary, "show", wg.interfaceName)
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Could not verify WireGuard configuration: %v\n", err)
	} else {
		fmt.Printf("WireGuard configuration:\n%s\n", string(cmdOutput))
	}

	fmt.Printf("WireGuard interface %s is ready on port %d\n", wg.interfaceName, wg.listenPort)
	return nil
}

func (wg *WireGuardManager) setupWindows() error {
	// Windows implementation uses the WireGuard for Windows application

	// Get the path to bundled binary
	wgBinary := BinaryPath("wireguard")

	// Generate a temporary configuration file
	configFile, err := os.CreateTemp("", "wg-config-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	// Write configuration
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d
`, wg.privateKey.String(), wg.listenPort)

	// Add addresses
	for _, addr := range wg.addresses {
		config += fmt.Sprintf("Address = %s\n", addr)
	}

	if _, err := configFile.WriteString(config); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	configFile.Close()

	// Apply the configuration using wireguard.exe
	cmd := exec.Command(wgBinary, "/installtunnelservice", configFile.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure WireGuard interface: %v", err)
	}

	return nil
}

func (wg *WireGuardManager) addPeerLinux(publicKey, endpoint string, allowedIPs []string) error {
	// Build the command to add a peer
	wgBinary := BinaryPath("wg")
	args := []string{"set", wg.interfaceName, "peer", publicKey}

	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}

	if len(allowedIPs) > 0 {
		args = append(args, "allowed-ips")
		args = append(args, strings.Join(allowedIPs, ","))
	}

	// Add persistent keepalive to help with NAT traversal
	args = append(args, "persistent-keepalive", "25")

	// Show the command being executed
	fmt.Printf("Executing: %s %s\n", wgBinary, strings.Join(args, " "))

	// Execute the command
	cmd := exec.Command(wgBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Command output: %s\n", string(output))
		return fmt.Errorf("failed to add peer: %v", err)
	}

	// Verify peer was added
	fmt.Println("Verifying peer connection...")
	cmd = exec.Command(wgBinary, "show", wg.interfaceName, "peers")
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Failed to verify peers: %v\n", err)
	} else {
		peers := strings.Split(strings.TrimSpace(string(output)), "\n")
		peerFound := false
		for _, p := range peers {
			if strings.TrimSpace(p) == publicKey {
				peerFound = true
				break
			}
		}

		if peerFound {
			fmt.Println("✓ Peer added and verified")
		} else {
			fmt.Println("⚠️ Peer added but not found in verification")
			// Proceed anyway as sometimes it takes a moment for the peer to show up
		}
	}

	return nil
}

func (wg *WireGuardManager) addPeerDarwin(publicKey, endpoint string, allowedIPs []string) error {
	fmt.Println("Adding WireGuard peer on macOS...")

	// macOS implementation is similar to Linux
	wgBinary := BinaryPath("wg")
	args := []string{"set", wg.interfaceName, "peer", publicKey}

	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}

	if len(allowedIPs) > 0 {
		args = append(args, "allowed-ips")
		args = append(args, strings.Join(allowedIPs, ","))
	}

	// Add persistent keepalive to help with NAT
	args = append(args, "persistent-keepalive", "25")

	// Show the command being executed
	fmt.Printf("Executing: %s %s\n", wgBinary, strings.Join(args, " "))

	// Execute the command
	cmd := exec.Command(wgBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Command output: %s\n", string(output))
		return fmt.Errorf("failed to add peer: %v", err)
	}

	// Verify peer was added
	fmt.Println("Verifying peer connection...")
	cmd = exec.Command(wgBinary, "show", wg.interfaceName, "peers")
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: Failed to verify peers: %v\n", err)
	} else {
		peers := strings.Split(strings.TrimSpace(string(output)), "\n")
		peerFound := false
		for _, p := range peers {
			if strings.TrimSpace(p) == publicKey {
				peerFound = true
				break
			}
		}

		if peerFound {
			fmt.Println("✓ Peer added and verified")
		} else {
			fmt.Println("⚠️ Peer added but not found in verification")
			// Proceed anyway as sometimes it takes a moment for the peer to show up
		}
	}

	return nil
}

func (wg *WireGuardManager) addPeerWindows(publicKey, endpoint string, allowedIPs []string) error {
	// Get the path to bundled binary
	wgBinary := BinaryPath("wireguard")

	// Read the current configuration
	configBytes, err := exec.Command(wgBinary, "/dumpconfig", wg.interfaceName).Output()
	if err != nil {
		return fmt.Errorf("failed to read current configuration: %v", err)
	}

	config := string(configBytes)

	// Add peer configuration
	peerConfig := fmt.Sprintf("\n[Peer]\nPublicKey = %s\n", publicKey)

	if endpoint != "" {
		peerConfig += fmt.Sprintf("Endpoint = %s\n", endpoint)
	}

	if len(allowedIPs) > 0 {
		peerConfig += fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowedIPs, ","))
	}

	// Create a new configuration file
	newConfig := config + peerConfig

	configFile, err := os.CreateTemp("", "wg-config-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(newConfig); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	configFile.Close()

	// Apply the new configuration
	cmd := exec.Command(wgBinary, "/uninstalltunnelservice", wg.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove existing configuration: %v", err)
	}

	cmd = exec.Command(wgBinary, "/installtunnelservice", configFile.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply new configuration: %v", err)
	}

	return nil
}

func (wg *WireGuardManager) tearDownLinux() error {
	cmd := exec.Command("ip", "link", "delete", wg.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove WireGuard interface: %v", err)
	}
	return nil
}

func (wg *WireGuardManager) tearDownDarwin() error {
	fmt.Printf("Tearing down WireGuard interface %s...\n", wg.interfaceName)

	// First try to kill the wireguard-go process
	fmt.Println("Stopping wireguard-go process...")
	cmd := exec.Command("pkill", "-f", fmt.Sprintf("wireguard-go %s", wg.interfaceName))
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Could not find wireguard-go process: %v\n", err)
		// Continue anyway as the process might not exist
	}

	// Wait a moment for the process to terminate
	time.Sleep(100 * time.Millisecond)

	// Try to destroy the interface
	fmt.Printf("Removing interface %s...\n", wg.interfaceName)
	cmd = exec.Command("ifconfig", wg.interfaceName, "destroy")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to destroy interface %s: %v\n", wg.interfaceName, err)
		// Continue anyway as the interface might already be gone
	}

	// Double-check that the interface is gone
	time.Sleep(100 * time.Millisecond)
	checkCmd := exec.Command("ifconfig", wg.interfaceName)
	if err := checkCmd.Run(); err == nil {
		fmt.Printf("Warning: Interface %s still exists after teardown\n", wg.interfaceName)
	} else {
		fmt.Printf("Interface %s successfully removed\n", wg.interfaceName)
	}

	return nil
}

func (wg *WireGuardManager) tearDownWindows() error {
	wgBinary := BinaryPath("wireguard")
	cmd := exec.Command(wgBinary, "/uninstalltunnelservice", wg.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove WireGuard interface: %v", err)
	}
	return nil
}

// GenerateKey generates a new WireGuard key pair
func GenerateKey() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	return key.String(), key.PublicKey().String(), nil
}

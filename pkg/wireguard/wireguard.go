package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	return &WireGuardManager{
		interfaceName: interfaceName,
		privateKey:    privateKey,
		listenPort:    listenPort,
		addresses:     addresses,
	}, nil
}

// GetPrivateKey returns the private key as a string
func (wg *WireGuardManager) GetPrivateKey() string {
	return wg.privateKey.String()
}

// GetPublicKey returns the public key as a string
func (wg *WireGuardManager) GetPublicKey() string {
	return wg.privateKey.PublicKey().String()
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

	var err error
	switch runtime.GOOS {
	case "linux":
		err = wg.addPeerLinux(publicKey, endpoint, allowedIPs)
	case "darwin":
		err = wg.addPeerDarwin(publicKey, endpoint, allowedIPs)
	case "windows":
		err = wg.addPeerWindows(publicKey, endpoint, allowedIPs)
	default:
		err = fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return err
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

	// Set up the WireGuard interface
	cmd := exec.Command(wgGoBinary, wg.interfaceName)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %v - %s", err, string(cmdOutput))
	}

	// Wait for the interface to be ready
	time.Sleep(500 * time.Millisecond)

	// Apply the configuration
	cmd = exec.Command(wgBinary, "setconf", wg.interfaceName, configFile.Name())
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard interface: %v - %s", err, string(cmdOutput))
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
		cmd = exec.Command("ifconfig", wg.interfaceName, "inet", ipAddr.String(),
			ipAddr.String(), "netmask", fmt.Sprintf("0x%x", binary.BigEndian.Uint32(ipNet.Mask)))
		cmdOutput, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to configure IP address %s: %v - %s", addr, err, string(cmdOutput))
		}
	}

	// Set interface up
	cmd = exec.Command("ifconfig", wg.interfaceName, "up")
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set interface up: %v - %s", err, string(cmdOutput))
	}

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

	// Execute the command
	cmd := exec.Command(wgBinary, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	return nil
}

func (wg *WireGuardManager) addPeerDarwin(publicKey, endpoint string, allowedIPs []string) error {
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

	// Execute the command
	cmd := exec.Command(wgBinary, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
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
	cmd := exec.Command("pkill", "-f", fmt.Sprintf("wireguard-go %s", wg.interfaceName))
	_ = cmd.Run() // Ignore errors as the process might not exist
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

package routing

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RouteEntry represents a single route in the routing table
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
	Flags       string `json:"flags"`
}

// RoutingState represents the complete routing state of the system
type RoutingState struct {
	DefaultGateway string       `json:"default_gateway"`
	DefaultIface   string       `json:"default_interface"`
	Routes         []RouteEntry `json:"routes"`
	Timestamp      time.Time    `json:"timestamp"`
	OS             string       `json:"os"`
}

// RoutingStateManager handles backup and restoration of routing state
type RoutingStateManager struct {
	backupPath string
	state      *RoutingState
}

// NewRoutingStateManager creates a new routing state manager
func NewRoutingStateManager() *RoutingStateManager {
	// Create backup directory in user's home or temp
	backupDir := getBackupDirectory()
	backupPath := filepath.Join(backupDir, "peervpn_routing_backup.json")

	return &RoutingStateManager{
		backupPath: backupPath,
	}
}

// getBackupDirectory returns the directory to store routing backups
func getBackupDirectory() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to temp directory
		return os.TempDir()
	}

	backupDir := filepath.Join(homeDir, ".peervpn")
	os.MkdirAll(backupDir, 0700)
	return backupDir
}

// BackupRoutingState captures and saves the current routing state
func (rsm *RoutingStateManager) BackupRoutingState() error {
	fmt.Println("Backing up current routing state...")

	state := &RoutingState{
		Timestamp: time.Now(),
		OS:        runtime.GOOS,
		Routes:    []RouteEntry{},
	}

	var err error
	switch runtime.GOOS {
	case "darwin":
		err = rsm.backupDarwin(state)
	case "linux":
		err = rsm.backupLinux(state)
	case "windows":
		err = rsm.backupWindows(state)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	if err != nil {
		return fmt.Errorf("failed to backup routing state: %v", err)
	}

	// Save to file
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal routing state: %v", err)
	}

	if err := os.WriteFile(rsm.backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save routing backup: %v", err)
	}

	rsm.state = state
	fmt.Printf("Routing state backed up to: %s\n", rsm.backupPath)
	fmt.Printf("Default gateway: %s via %s\n", state.DefaultGateway, state.DefaultIface)
	return nil
}

// RestoreRoutingState restores the previously backed up routing state
func (rsm *RoutingStateManager) RestoreRoutingState() error {
	if rsm.state == nil {
		// Try to load from file
		if err := rsm.loadBackupFromFile(); err != nil {
			return fmt.Errorf("no routing state to restore: %v", err)
		}
	}

	fmt.Println("Restoring original routing state...")
	fmt.Printf("Restoring default gateway: %s via %s\n", rsm.state.DefaultGateway, rsm.state.DefaultIface)

	var err error
	switch runtime.GOOS {
	case "darwin":
		err = rsm.restoreDarwin()
	case "linux":
		err = rsm.restoreLinux()
	case "windows":
		err = rsm.restoreWindows()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	if err != nil {
		return fmt.Errorf("failed to restore routing state: %v", err)
	}

	// Verify restoration
	if err := rsm.verifyRestoration(); err != nil {
		fmt.Printf("Warning: Routing restoration verification failed: %v\n", err)
	} else {
		fmt.Println("Routing state successfully restored and verified")
	}

	// Clean up backup file
	if err := os.Remove(rsm.backupPath); err != nil {
		fmt.Printf("Warning: Could not remove backup file: %v\n", err)
	}

	return nil
}

// loadBackupFromFile loads routing state from the backup file
func (rsm *RoutingStateManager) loadBackupFromFile() error {
	data, err := os.ReadFile(rsm.backupPath)
	if err != nil {
		return err
	}

	var state RoutingState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	rsm.state = &state
	return nil
}

// Platform-specific backup implementations
func (rsm *RoutingStateManager) backupDarwin(state *RoutingState) error {
	// Get default route information
	output, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				state.DefaultGateway = parts[1]
			}
		} else if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				state.DefaultIface = parts[1]
			}
		}
	}

	// We only need the default route - don't capture individual routes
	// that contain ARP entries and complex link-local information
	fmt.Printf("Captured default route: %s via %s\n", state.DefaultGateway, state.DefaultIface)

	return nil
}

func (rsm *RoutingStateManager) backupLinux(state *RoutingState) error {
	// Get default route
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %v", err)
	}

	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			state.DefaultGateway = fields[i+1]
		}
		if field == "dev" && i+1 < len(fields) {
			state.DefaultIface = fields[i+1]
		}
	}

	// We only need the default route - don't capture individual routes
	fmt.Printf("Captured default route: %s via %s\n", state.DefaultGateway, state.DefaultIface)

	return nil
}

func (rsm *RoutingStateManager) backupWindows(state *RoutingState) error {
	// Get default route
	output, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return fmt.Errorf("failed to get default route: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				state.DefaultGateway = fields[2]
				if len(fields) >= 4 {
					state.DefaultIface = fields[3]
				}
			}
			break
		}
	}

	// We only need the default route - don't capture individual routes
	fmt.Printf("Captured default route: %s via %s\n", state.DefaultGateway, state.DefaultIface)

	return nil
}

// Platform-specific restore implementations
func (rsm *RoutingStateManager) restoreDarwin() error {
	if rsm.state.DefaultGateway == "" || rsm.state.DefaultIface == "" {
		return fmt.Errorf("invalid backup state: missing default gateway or interface")
	}

	// Restore default route
	fmt.Printf("Restoring default route via %s on %s...\n", rsm.state.DefaultGateway, rsm.state.DefaultIface)
	cmd := exec.Command("route", "-n", "add", "default", rsm.state.DefaultGateway)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Failed to restore default route: %v - %s\n", err, string(output))

		// Try alternative method
		fmt.Println("Trying alternative default route restoration...")
		cmd = exec.Command("route", "-n", "add", "-net", "0.0.0.0/0", rsm.state.DefaultGateway)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to restore default route: %v - %s", err, string(output))
		}
	}

	// Don't restore individual routes - the system will recreate them automatically
	// This prevents errors with ARP entries, link-local routes, and MAC addresses
	fmt.Println("Allowing system to recreate local routes automatically...")

	return nil
}

func (rsm *RoutingStateManager) restoreLinux() error {
	if rsm.state.DefaultGateway == "" {
		return fmt.Errorf("invalid backup state: missing default gateway")
	}

	// Remove any existing default routes
	fmt.Println("Removing existing default routes...")
	exec.Command("ip", "route", "del", "default").Run()

	// Restore default route
	fmt.Printf("Restoring default route via %s", rsm.state.DefaultGateway)
	if rsm.state.DefaultIface != "" {
		fmt.Printf(" on %s", rsm.state.DefaultIface)
	}
	fmt.Println()

	var cmd *exec.Cmd
	if rsm.state.DefaultIface != "" {
		cmd = exec.Command("ip", "route", "add", "default", "via", rsm.state.DefaultGateway, "dev", rsm.state.DefaultIface)
	} else {
		cmd = exec.Command("ip", "route", "add", "default", "via", rsm.state.DefaultGateway)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore default route: %v - %s", err, string(output))
	}

	// Don't restore individual routes - the system will recreate them automatically
	fmt.Println("Allowing system to recreate local routes automatically...")

	return nil
}

func (rsm *RoutingStateManager) restoreWindows() error {
	if rsm.state.DefaultGateway == "" {
		return fmt.Errorf("invalid backup state: missing default gateway")
	}

	// Remove existing default routes
	fmt.Println("Removing existing default routes...")
	exec.Command("route", "delete", "0.0.0.0").Run()

	// Restore default route
	fmt.Printf("Restoring default route via %s\n", rsm.state.DefaultGateway)
	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", rsm.state.DefaultGateway)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore default route: %v - %s", err, string(output))
	}

	return nil
}

// verifyRestoration checks if the routing state was properly restored
func (rsm *RoutingStateManager) verifyRestoration() error {
	// Test connectivity to a public DNS server
	var testIP = "8.8.8.8"

	// Verify default route exists
	switch runtime.GOOS {
	case "darwin":
		output, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return fmt.Errorf("no default route found: %v", err)
		}
		if !strings.Contains(string(output), rsm.state.DefaultGateway) {
			return fmt.Errorf("default gateway mismatch")
		}
	case "linux":
		output, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return fmt.Errorf("no default route found: %v", err)
		}
		if !strings.Contains(string(output), rsm.state.DefaultGateway) {
			return fmt.Errorf("default gateway mismatch")
		}
	case "windows":
		output, err := exec.Command("route", "print", "0.0.0.0").Output()
		if err != nil {
			return fmt.Errorf("no default route found: %v", err)
		}
		if !strings.Contains(string(output), rsm.state.DefaultGateway) {
			return fmt.Errorf("default gateway mismatch")
		}
	}

	// Test connectivity with ping
	var pingCmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		pingCmd = exec.Command("ping", "-n", "1", "-w", "3000", testIP)
	default:
		pingCmd = exec.Command("ping", "-c", "1", "-W", "3", testIP)
	}

	if err := pingCmd.Run(); err != nil {
		return fmt.Errorf("connectivity test failed - ping to %s failed: %v", testIP, err)
	}

	return nil
}

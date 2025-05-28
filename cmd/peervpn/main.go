package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danialdehvan/PeerVPN/pkg/config"
	"github.com/danialdehvan/PeerVPN/pkg/nat"
	"github.com/danialdehvan/PeerVPN/pkg/peers"
	"github.com/danialdehvan/PeerVPN/pkg/routing"
	"github.com/danialdehvan/PeerVPN/pkg/wireguard"
)

const (
	clientSubnet = "10.0.0.0/24"
)

var (
	// Platform-specific interface name
	interfaceName  = getDefaultInterfaceName()
	configDir      = getConfigDir()
	configFilePath = filepath.Join(configDir, "config.json")
	peerInfoPath   = filepath.Join(configDir, "peer_info.txt")
)

// getDefaultInterfaceName returns the default interface name based on the OS
func getDefaultInterfaceName() string {
	switch runtime.GOOS {
	case "darwin":
		// For macOS, try to find an available utun interface name
		// Start with utun12 and try higher numbers if occupied
		baseNum := 12
		maxTries := 10

		for i := 0; i < maxTries; i++ {
			ifName := fmt.Sprintf("utun%d", baseNum+i)
			// Check if this interface already exists
			_, err := exec.Command("ifconfig", ifName).CombinedOutput()
			if err != nil {
				// Interface doesn't exist, so it's available
				return ifName
			}
			// Try the next number
		}
		// If we couldn't find a free one, return a fallback
		return "utun20"
	case "windows":
		return "peervpn" // On Windows, can be any name
	default:
		return "peervpn0" // On Linux, can be any name
	}
}

func getConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory
		return ".peervpn"
	}
	return filepath.Join(homeDir, ".peervpn")
}

func main() {
	// Parse command-line flags
	var (
		isExitNode  bool
		showInfo    bool
		connectPeer string
		debugMode   bool
		connTimeout int
		retryCount  int
		diagnostics bool
		natTest     bool
		monitorNAT  bool
	)

	flag.BoolVar(&isExitNode, "exit", false, "Run as an exit node")
	flag.BoolVar(&showInfo, "info", false, "Show peer connection information")
	flag.StringVar(&connectPeer, "connect", "", "Connect to a peer (format: pubkey@endpoint)")
	flag.BoolVar(&debugMode, "debug", false, "Enable detailed connection debugging")
	flag.IntVar(&connTimeout, "timeout", 15, "Connection handshake timeout in seconds")
	flag.IntVar(&retryCount, "retry", 1, "Number of connection attempts before giving up")
	flag.BoolVar(&diagnostics, "diagnostics", false, "Run network diagnostics to troubleshoot connectivity issues")
	flag.BoolVar(&natTest, "nattest", false, "Test NAT type and P2P connectivity capabilities")
	flag.BoolVar(&monitorNAT, "monitor-nat", false, "Enable frequent NAT monitoring (logs public endpoint every 10 seconds)")
	flag.Parse()

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	// Verify WireGuard dependencies before proceeding
	fmt.Println("Verifying WireGuard dependencies...")
	if err := wireguard.VerifyDependencies(); err != nil {
		fmt.Printf("Dependency check failed: %v\n", err)
		fmt.Println("\nInstallation instructions:")
		switch runtime.GOOS {
		case "darwin":
			fmt.Println("  brew install wireguard-tools")
		case "linux":
			fmt.Println("  sudo apt install wireguard-tools  # Ubuntu/Debian")
			fmt.Println("  sudo yum install wireguard-tools  # RHEL/CentOS")
		case "windows":
			fmt.Println("  Download and install WireGuard from https://www.wireguard.com/install/")
		}
		os.Exit(1)
	}

	// Load or create configuration
	cfg, err := loadOrCreateConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Load or create peer info
	peerInfo, err := loadOrCreatePeerInfo(cfg)
	if err != nil {
		fmt.Printf("Error setting up peer information: %v\n", err)
		os.Exit(1)
	}

	// Create components
	wgManager, err := wireguard.NewWireGuardManager(interfaceName, cfg.WireguardPrivKey, cfg.WireguardPort, []string{cfg.WireguardAddress})
	if err != nil {
		fmt.Printf("Error creating WireGuard manager: %v\n", err)
		os.Exit(1)
	}

	routingManager := routing.NewRoutingManager(interfaceName, isExitNode)
	natDiscovery := nat.NewDiscoveryClient(cfg.StunServers)

	connectionManager := peers.NewConnectionManager(
		wgManager,
		routingManager,
		natDiscovery,
		peerInfo,
		interfaceName,
		clientSubnet,
	)

	// Handle diagnostics mode
	if diagnostics {
		fmt.Println("=== PeerVPN Network Diagnostics ===")
		runNetworkDiagnostics(connectionManager, natDiscovery)
		os.Exit(0)
	}

	// Handle NAT testing mode
	if natTest {
		fmt.Println("=== PeerVPN NAT Type Detection ===")
		runNATTypeDetection(cfg)
		os.Exit(0)
	}

	// Handle different modes
	if showInfo {
		// Just show peer information and exit
		fmt.Println("=== PeerVPN Connection Information ===")
		fmt.Println(connectionManager.GetConnectionInfo())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		endpoint, err := connectionManager.DiscoverEndpoint(ctx)
		if err != nil {
			fmt.Printf("Warning: Could not discover public endpoint: %v\n", err)
		} else {
			fmt.Printf("Current Public Endpoint: %s\n", endpoint)
		}

		os.Exit(0)
	}

	if isExitNode {
		// Set up as exit node
		fmt.Println("Setting up as an exit node...")
		if err := connectionManager.SetupExitNode(); err != nil {
			fmt.Printf("Error setting up exit node: %v\n", err)
			os.Exit(1)
		}

		// Save updated peer info
		if err := peers.WriteLocalPeerInfo(peerInfoPath, peerInfo); err != nil {
			fmt.Printf("Error saving peer info: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Exit node is ready. Share the following information with clients:")
		fmt.Println(connectionManager.GetConnectionInfo())

		// Display the connection string for easy copying
		connString := connectionManager.GetConnectionString()
		if connString != "" {
			fmt.Println("\n=== Easy Connect String (Copy & Paste) ===")
			fmt.Println(connString)
			fmt.Println("\nTo connect, run: sudo ./peervpn --connect=" + connString)
		}

		// Enable detailed connection debugging if requested
		if debugMode {
			fmt.Println("\nDebug mode enabled - detailed connection monitoring will be shown")
			connectionManager.EnableConnectionDebugging()
		}

		// Enable NAT monitoring if requested
		if monitorNAT {
			fmt.Println("\nNAT monitoring enabled - public endpoint will be logged every 10 seconds")
			fmt.Println("This helps verify that your exit node port remains accessible over time")
			ctx := context.Background()
			natDiscovery.StartNATMonitoring(ctx, 10*time.Second)
		}

		// Set up signal handling with cleanup protection
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		// Create cleanup function that ensures routing state is restored
		var cleanupInProgress bool
		var cleanupMutex sync.Mutex
		cleanup := func() {
			cleanupMutex.Lock()
			defer cleanupMutex.Unlock()

			if cleanupInProgress {
				return // Cleanup already in progress, avoid double execution
			}
			cleanupInProgress = true

			fmt.Println("\nShutting down and restoring network state...")
			fmt.Println("Please wait, do not interrupt (Ctrl+C again will be ignored)...")

			// Mask additional signals during cleanup to prevent interruption
			signal.Stop(sigCh)
			signal.Reset(syscall.SIGINT, syscall.SIGTERM)

			// Stop tracking before disconnecting
			connectionManager.StopConnectionTracking()

			// Clean up (this will restore routing state)
			if err := connectionManager.Disconnect(); err != nil {
				fmt.Printf("Error during cleanup: %v\n", err)

				// Emergency fallback: try direct routing restoration
				fmt.Println("Attempting emergency routing restoration...")
				if err := exec.Command("sudo", "./emergency_recovery.sh").Run(); err != nil {
					fmt.Printf("Emergency recovery script failed: %v\n", err)
					fmt.Println("Manual intervention may be required to restore network connectivity")
				}
			}

			fmt.Println("Network state restored, safe to exit.")
		}

		// Set up deferred cleanup to run on any exit
		defer cleanup()

		// Start tracking connections
		fmt.Println("\nWaiting for peer connections...")
		connectionManager.StartConnectionTracking(5 * time.Second)

		// Start a ticker to display peer stats every 10 seconds
		statsDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			defer close(statsDone)

			for {
				select {
				case <-ticker.C:
					connectionManager.DisplayPeerStats()
				case <-sigCh: // Will be triggered when sigCh receives a signal
					return
				}
			}
		}()

		// Signal handling loop with cleanup protection
		go func() {
			signalCount := 0
			for sig := range sigCh {
				signalCount++

				cleanupMutex.Lock()
				inProgress := cleanupInProgress
				cleanupMutex.Unlock()

				if inProgress {
					if signalCount == 1 {
						fmt.Printf("\nReceived %v, cleanup in progress...\n", sig)
						fmt.Println("Please wait for network restoration to complete.")
						fmt.Println("Forcing exit now may leave your network in a broken state!")
					} else {
						fmt.Printf("\nReceived %v again - cleanup still in progress, please wait...\n", sig)
					}
					continue
				}

				// First signal received, start graceful shutdown
				fmt.Printf("\nReceived %v, starting graceful shutdown...\n", sig)
				break
			}
		}()

		// Wait for first termination signal
		<-sigCh

		// Wait for stats goroutine to finish
		<-statsDone

		fmt.Println("Disconnected successfully.")
	} else if connectPeer != "" {
		// Connect to a peer
		fmt.Printf("Connecting to peer: %s\n", connectPeer)

		// Parse the connect string (format: pubkey@endpoint)
		parts := strings.Split(connectPeer, "@")
		if len(parts) != 2 {
			fmt.Println("Error: Invalid connection format. Use: --connect=pubkey@endpoint")
			os.Exit(1)
		}

		peerPublicKey := parts[0]
		peerEndpoint := parts[1]

		// Validate the endpoint
		validEndpoint, err := connectionManager.ValidatePeerEndpoint(peerEndpoint)
		if err != nil {
			fmt.Printf("Error: Invalid endpoint: %v\n", err)
			os.Exit(1)
		}

		// Use the provided timeout
		fmt.Printf("Connection timeout set to %d seconds\n", connTimeout)
		connectionManager.SetHandshakeTimeout(time.Duration(connTimeout) * time.Second)

		// Enable debug mode if requested
		if debugMode {
			fmt.Println("Debug mode enabled - detailed connection information will be shown")
			connectionManager.EnableConnectionDebugging()
		}

		// Enable NAT monitoring if requested
		if monitorNAT {
			fmt.Println("\nNAT monitoring enabled - will monitor your public endpoint during connection")
			ctx := context.Background()
			natDiscovery.StartNATMonitoring(ctx, 10*time.Second)
		}

		// Attempt connection with retries
		var connectErr error
		for attempt := 1; attempt <= retryCount; attempt++ {
			if attempt > 1 {
				fmt.Printf("\n=== Retry Attempt %d of %d ===\n", attempt, retryCount)
				// Give some time between retries
				time.Sleep(2 * time.Second)
			}

			// Connect to the peer
			connectErr = connectionManager.ConnectToPeer(peerPublicKey, validEndpoint)
			if connectErr == nil {
				break // Connection successful
			}

			fmt.Printf("Connection attempt %d failed: %v\n", attempt, connectErr)
		}

		if connectErr != nil {
			fmt.Printf("All connection attempts failed. Last error: %v\n", connectErr)
			os.Exit(1)
		}

		// Set up signal handling with cleanup protection
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		// Create cleanup function that ensures routing state is restored
		var cleanupInProgress bool
		var cleanupMutex sync.Mutex
		cleanup := func() {
			cleanupMutex.Lock()
			defer cleanupMutex.Unlock()

			if cleanupInProgress {
				return // Cleanup already in progress, avoid double execution
			}
			cleanupInProgress = true

			fmt.Println("\nShutting down and restoring network state...")
			fmt.Println("Please wait, do not interrupt (Ctrl+C again will be ignored)...")

			// Mask additional signals during cleanup to prevent interruption
			signal.Stop(sigCh)
			signal.Reset(syscall.SIGINT, syscall.SIGTERM)

			// Clean up (this will restore routing state)
			if err := connectionManager.Disconnect(); err != nil {
				fmt.Printf("Error during cleanup: %v\n", err)

				// Emergency fallback: try direct routing restoration
				fmt.Println("Attempting emergency routing restoration...")
				if err := exec.Command("sudo", "./emergency_recovery.sh").Run(); err != nil {
					fmt.Printf("Emergency recovery script failed: %v\n", err)
					fmt.Println("Manual intervention may be required to restore network connectivity")
				}
			}
		}

		// Set up deferred cleanup to run on any exit
		defer cleanup()

		// Signal handling loop with cleanup protection
		go func() {
			signalCount := 0
			for sig := range sigCh {
				signalCount++

				cleanupMutex.Lock()
				inProgress := cleanupInProgress
				cleanupMutex.Unlock()

				if inProgress {
					if signalCount == 1 {
						fmt.Printf("\nReceived %v, cleanup in progress...\n", sig)
						fmt.Println("Please wait for network restoration to complete.")
						fmt.Println("Forcing exit now may leave your network in a broken state!")
					} else {
						fmt.Printf("\nReceived %v again - cleanup still in progress, please wait...\n", sig)
					}
					continue
				}

				// First signal received, start graceful shutdown
				fmt.Printf("\nReceived %v, starting graceful shutdown...\n", sig)
				break
			}
		}()

		// Wait for termination signal
		<-sigCh

		fmt.Println("Disconnected successfully.")
	} else {
		// No mode specified
		fmt.Println("PeerVPN - WireGuard-based P2P VPN")
		fmt.Println("Use --exit to run as an exit node")
		fmt.Println("Use --connect=pubkey@endpoint to connect to a peer")
		fmt.Println("   Options:")
		fmt.Println("     --timeout=N      Set handshake timeout in seconds (default: 15)")
		fmt.Println("     --retry=N        Number of connection attempts (default: 1)")
		fmt.Println("     --debug          Enable detailed connection information")
		fmt.Println("     --monitor-nat    Log public endpoint every 10 seconds (test port persistence)")
		fmt.Println("Use --info to show your connection information")
		fmt.Println("Use --nattest to test your NAT type and P2P connectivity")
		fmt.Println("Use --diagnostics to run full network diagnostics")
		os.Exit(0)
	}
}

func loadOrCreateConfig() (*config.Config, error) {
	// Try to load existing config
	cfg, err := config.LoadFromFile(configFilePath)
	if err == nil {
		return cfg, nil
	}

	// Create a new config
	cfg = config.DefaultConfig()

	// Generate a WireGuard key pair if needed
	if cfg.WireguardPrivKey == "" {
		privKey, pubKey, err := wireguard.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate WireGuard keys: %v", err)
		}
		cfg.WireguardPrivKey = privKey
		cfg.WireguardPubKey = pubKey
	}

	// Save the config
	if err := cfg.SaveToFile(configFilePath); err != nil {
		return nil, fmt.Errorf("failed to save configuration: %v", err)
	}

	return cfg, nil
}

func loadOrCreatePeerInfo(cfg *config.Config) (*peers.PeerInfo, error) {
	// Try to load existing peer info
	peerInfo, err := peers.ReadLocalPeerInfo(peerInfoPath)
	if err == nil {
		return peerInfo, nil
	}

	// Create new peer info
	peerID, err := peers.GeneratePeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer ID: %v", err)
	}

	peerInfo = &peers.PeerInfo{
		PeerID:     peerID,
		PublicKey:  cfg.WireguardPubKey,
		IsExitNode: false,
	}

	// Save the peer info
	if err := peers.WriteLocalPeerInfo(peerInfoPath, peerInfo); err != nil {
		return nil, fmt.Errorf("failed to save peer info: %v", err)
	}

	return peerInfo, nil
}

// runNetworkDiagnostics performs various network connectivity tests
func runNetworkDiagnostics(cm *peers.ConnectionManager, natDiscovery *nat.DiscoveryClient) {
	fmt.Println("Running comprehensive network diagnostics...")

	// 1. Check OS and version
	fmt.Println("\n1. Operating System")
	fmt.Printf("OS: %s\n", runtime.GOOS)
	osVersionCmd := exec.Command("uname", "-a")
	output, _ := osVersionCmd.CombinedOutput()
	fmt.Printf("Version: %s", string(output))

	// 2. Check network interfaces
	fmt.Println("\n2. Network Interfaces")
	ifconfigCmd := exec.Command("ifconfig")
	output, _ = ifconfigCmd.CombinedOutput()
	fmt.Printf("%s\n", string(output))

	// 3. Check firewall status
	fmt.Println("\n3. Firewall Status")
	if runtime.GOOS == "darwin" {
		pfctlCmd := exec.Command("pfctl", "-s", "info")
		output, _ = pfctlCmd.CombinedOutput()
		fmt.Printf("PF Firewall: %s\n", string(output))

		// Check if our PeerVPN anchor exists
		pfAnchorCmd := exec.Command("pfctl", "-s", "Anchors")
		output, _ = pfAnchorCmd.CombinedOutput()
		fmt.Printf("PF Anchors: %s\n", string(output))
	} else if runtime.GOOS == "linux" {
		iptablesCmd := exec.Command("iptables", "-L")
		output, _ = iptablesCmd.CombinedOutput()
		fmt.Printf("iptables: %s\n", string(output))
	}

	// 4. Check routing table
	fmt.Println("\n4. Routing Table")
	var routeCmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		routeCmd = exec.Command("netstat", "-nr")
	} else {
		routeCmd = exec.Command("ip", "route", "show")
	}
	output, _ = routeCmd.CombinedOutput()
	fmt.Printf("%s\n", string(output))

	// 5. Check UDP connectivity
	fmt.Println("\n5. UDP Connectivity")
	// Try to bind to common WireGuard port
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 51820})
	if err != nil {
		fmt.Printf("Cannot bind to UDP port 51820: %v\n", err)
		fmt.Println("This may indicate another WireGuard service is running")
	} else {
		fmt.Println("Successfully bound to UDP port 51820")
		conn.Close()
	}

	// 6. Check STUN connectivity
	fmt.Println("\n6. STUN Connectivity")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint, err := natDiscovery.DiscoverPublicEndpoint(ctx)
	if err != nil {
		fmt.Printf("STUN discovery failed: %v\n", err)
	} else {
		fmt.Printf("Public endpoint according to STUN: %s\n", endpoint.String())
		fmt.Println("NAT discovery is working correctly")
	}

	// 7. Check DNS resolution
	fmt.Println("\n7. DNS Resolution")
	nsLookupCmd := exec.Command("nslookup", "google.com")
	output, err = nsLookupCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("DNS resolution failed: %v\n", err)
	} else {
		fmt.Printf("%s\n", string(output))
	}

	fmt.Println("\n=== Diagnostic Summary ===")
	fmt.Println("The diagnostics above can help identify network connectivity issues.")
	fmt.Println("If you're having trouble connecting to peers, look for:")
	fmt.Println("1. Firewall rules blocking UDP traffic")
	fmt.Println("2. Multiple WireGuard interfaces causing conflicts")
	fmt.Println("3. NAT type restrictions (symmetric NAT can cause issues)")
	fmt.Println("4. Routing table conflicts")

	fmt.Println("\nFor better connection success:")
	fmt.Println("- Try using --retry=3 --timeout=30 for difficult connections")
	fmt.Println("- Ensure UDP port 51820 (or your configured port) is forwarded if behind NAT")
	fmt.Println("- Disable any VPN services that might interfere with WireGuard")
}

// runNATTypeDetection performs NAT type detection and connectivity analysis
func runNATTypeDetection(cfg *config.Config) {
	fmt.Println("This will test your network's NAT type and P2P connectivity capabilities.")
	fmt.Println("Understanding your NAT type helps determine:")
	fmt.Println("• Whether you can act as an exit node")
	fmt.Println("• How easily others can connect to you")
	fmt.Println("• What connection issues you might encounter")
	fmt.Println("")

	// Create NAT type detector
	detector := nat.NewNATTypeDetector(cfg.StunServers)

	// Run detection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	natType, endpoints, err := detector.DetectNATType(ctx)
	if err != nil {
		fmt.Printf("❌ NAT detection failed: %v\n", err)
		return
	}

	// Display results
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("🌐 NAT Type: %s\n", natType.String())
	fmt.Printf("📊 P2P Compatibility: %s\n", natType.GetCompatibilityLevel())
	fmt.Println(strings.Repeat("=", 50))

	// Show discovered endpoints
	if len(endpoints) > 0 {
		fmt.Println("\n📍 Discovered External Endpoints:")
		for i, endpoint := range endpoints {
			fmt.Printf("   %d. %s\n", i+1, endpoint.String())
		}
	}

	// Show recommendations
	fmt.Println("\n💡 Recommendations:")
	recommendations := natType.GetRecommendations()
	for _, rec := range recommendations {
		fmt.Printf("   %s\n", rec)
	}

	// Provide specific guidance based on NAT type
	fmt.Println("\n📋 What This Means for PeerVPN:")

	switch natType {
	case nat.NATTypeOpen, nat.NATTypeFullCone:
		fmt.Println("✅ Excellent for PeerVPN!")
		fmt.Println("   • You can easily run as an exit node")
		fmt.Println("   • Others can connect to you reliably")
		fmt.Println("   • You can connect to most other peers")

	case nat.NATTypeRestrictedCone, nat.NATTypePortRestrictedCone:
		fmt.Println("⚠️  Good for PeerVPN with some limitations")
		fmt.Println("   • You can run as an exit node, but may need port forwarding")
		fmt.Println("   • You can connect to most peers")
		fmt.Println("   • Some peers behind strict NAT may have trouble connecting to you")

	case nat.NATTypeSymmetric:
		fmt.Println("❌ Poor for PeerVPN")
		fmt.Println("   • You should NOT run as an exit node (others can't reliably connect)")
		fmt.Println("   • You can only connect to peers with open/cone NAT")
		fmt.Println("   • Consider using a VPS or different network for better results")

	case nat.NATTypeBlocked:
		fmt.Println("🚫 Cannot use PeerVPN")
		fmt.Println("   • UDP traffic appears blocked")
		fmt.Println("   • Check firewall and router settings")
		fmt.Println("   • Try a different network")
	}

	// Additional network information
	fmt.Println("\n🔧 Network Configuration Help:")
	fmt.Println("If you want to improve your P2P connectivity:")
	fmt.Println("")
	fmt.Println("Router Settings:")
	fmt.Println("• Enable UPnP (Universal Plug and Play)")
	fmt.Println("• Forward UDP port 51820 to your computer's IP")
	fmt.Println("• Disable SIP ALG if available (can interfere with UDP)")
	fmt.Println("")
	fmt.Println("Firewall Settings:")
	fmt.Println("• Allow incoming UDP traffic on port 51820")
	fmt.Println("• Allow outgoing UDP traffic to any port")
	fmt.Println("")
	fmt.Println("If on corporate/school network:")
	fmt.Println("• Symmetric NAT is common on enterprise networks")
	fmt.Println("• Try using mobile hotspot or home network instead")
	fmt.Println("• Contact IT department about UDP port access")
}

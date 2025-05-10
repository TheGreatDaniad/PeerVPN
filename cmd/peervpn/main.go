package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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
	)

	flag.BoolVar(&isExitNode, "exit", false, "Run as an exit node")
	flag.BoolVar(&showInfo, "info", false, "Show peer connection information")
	flag.StringVar(&connectPeer, "connect", "", "Connect to a peer (format: pubkey@endpoint)")
	flag.BoolVar(&debugMode, "debug", false, "Enable detailed connection debugging")
	flag.Parse()

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
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

		// Set up signal handling
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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

		// Wait for termination signal
		<-sigCh
		fmt.Println("\nShutting down...")

		// Stop tracking before disconnecting
		connectionManager.StopConnectionTracking()

		// Clean up
		if err := connectionManager.Disconnect(); err != nil {
			fmt.Printf("Error during cleanup: %v\n", err)
			os.Exit(1)
		}

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

		// Connect to the peer
		if err := connectionManager.ConnectToPeer(peerPublicKey, validEndpoint); err != nil {
			fmt.Printf("Error connecting to peer: %v\n", err)
			os.Exit(1)
		}

		// Set up signal handling
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		// Wait for termination signal
		<-sigCh
		fmt.Println("\nShutting down...")

		// Clean up
		if err := connectionManager.Disconnect(); err != nil {
			fmt.Printf("Error during cleanup: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Disconnected successfully.")
	} else {
		// No mode specified
		fmt.Println("PeerVPN - WireGuard-based P2P VPN")
		fmt.Println("Use --exit to run as an exit node")
		fmt.Println("Use --connect=pubkey@endpoint to connect to a peer")
		fmt.Println("Use --info to show your connection information")
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

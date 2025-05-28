# PeerVPN

A peer-to-peer VPN solution using WireGuard tunnels with direct connections between peers.

## Features

- Direct peer-to-peer connections using WireGuard tunnels
- NAT traversal using STUN with automatic port mapping maintenance
- Cross-platform support (Linux, macOS, Windows)
- Manual peer connections with unique IDs
- Traffic routing through exit nodes
- No central server required for connections
- Proactive NAT keepalive to maintain connectivity during idle periods

## Installation

### Prerequisites

PeerVPN now includes bundled WireGuard binaries, but some platform-specific tools are still required:

#### Linux
- Required packages: `ip`, `sysctl`, `iptables`
```
sudo apt install iproute2 procps iptables
```

#### macOS
- WireGuard tools must be installed:
```
brew install wireguard-tools
```

#### Windows
- No additional prerequisites (WireGuard binary is bundled)

### Building from source

```
git clone https://github.com/danialdehvan/PeerVPN.git
cd PeerVPN
go build -o peervpn cmd/peervpn/main.go
```

## Usage

### Test your NAT type and P2P compatibility

```
./peervpn --nattest
```

This will analyze your network's NAT type and tell you:
- Whether you can run as an exit node
- How easily others can connect to you
- What P2P connection issues you might encounter
- Specific recommendations for your network setup

**NAT Types and P2P Compatibility:**
- **Open Internet (No NAT)**: Perfect for P2P, can act as exit node
- **Full Cone NAT**: Excellent for P2P, can act as exit node  
- **Restricted Cone NAT**: Good for P2P, may need port forwarding
- **Port-Restricted Cone NAT**: Fair for P2P, recommend port forwarding
- **Symmetric NAT**: Poor for P2P, should not act as exit node
- **Blocked/Firewalled**: Cannot establish P2P connections

### Show your connection information

```
sudo ./peervpn --info
```

This will show your Peer ID, WireGuard public key, and your current public endpoint. You can share this information with someone who wants to connect to your system.

### Running as an exit node

```
sudo ./peervpn --exit
```

This will:
1. Set up a WireGuard interface
2. Configure your system for IP forwarding
3. Discover your public endpoint using STUN
4. **Start NAT keepalive** to maintain port mapping during idle periods
5. Display connection information for clients

**Important:** The exit node automatically maintains its NAT port mapping even when no peers are connected. This means:
- Your port remains available and reachable for several minutes (or longer) after startup
- NAT mapping is refreshed every 60 seconds to prevent timeout
- Clients can connect successfully even if they attempt to connect minutes after you start the exit node

### Testing NAT port persistence

```
sudo ./peervpn --exit --monitor-nat
```

This enables frequent monitoring that logs your public endpoint every 10 seconds. Use this to:
- Verify that your port mapping remains consistent over time
- Test how long your NAT maintains the mapping during idle periods
- Troubleshoot NAT-related connectivity issues

You'll see output like:
```
[15:04:05] ✅ NAT port persistent: 203.0.113.45:51820 (unchanged)
[15:04:15] ✅ NAT port persistent: 203.0.113.45:51820 (unchanged)
[15:04:25] ⚠️  NAT port changed: 203.0.113.45:51820 -> 203.0.113.45:51821
```

You can also run the provided test script:
```
./test_nat_monitoring.sh
```

### Connecting to an exit node

```
sudo ./peervpn --connect=PUBKEY@ENDPOINT
```

Where:
- `PUBKEY` is the WireGuard public key of the exit node
- `ENDPOINT` is the public endpoint (IP:port) of the exit node

For example:
```
sudo ./peervpn --connect=QGCuHmJxKvB94NwXEZP4LVwQgLLKURwmfxbR9fyVeH0=@203.0.113.45:51820
```

## How it works

1. **NAT Traversal**: PeerVPN uses STUN to discover your public endpoint (IP:port) as seen from the internet.
2. **NAT Keepalive**: Exit nodes automatically maintain their NAT mapping by periodically refreshing it via STUN, ensuring reachability even during idle periods.
3. **Peer Discovery**: Connection information is exchanged manually between users.
4. **WireGuard Tunneling**: A secure WireGuard tunnel is established between peers.
5. **Routing Configuration**: Traffic is configured to route through the tunnel appropriately.

## NAT and Port Availability

### How PeerVPN ensures port availability:

1. **WireGuard Port Binding**: The UDP port remains bound as long as the exit node is running
2. **NAT Mapping Maintenance**: PeerVPN automatically refreshes the NAT mapping every 60 seconds
3. **Persistent Keepalive**: Once peers connect, WireGuard sends keepalive packets every 25 seconds

### Typical NAT timeout behavior:
- **Home routers**: 2-5 minutes for UDP mappings
- **Corporate NAT**: 1-3 minutes (varies widely)
- **Carrier-grade NAT**: 30 seconds to 2 minutes
- **With PeerVPN keepalive**: Mapping maintained indefinitely

This means your exit node remains reachable even if peers don't connect immediately after startup.

## Architecture

The system consists of the following components:

1. **Configuration Management**: Handles program settings and WireGuard key pairs
2. **NAT Traversal**: Discovers public endpoints using STUN with proactive keepalive
3. **WireGuard Integration**: Sets up and manages WireGuard tunnels
4. **Routing**: Configures network routes and IP forwarding
5. **Peer Management**: Handles peer IDs and connection information

## Security Considerations

- All traffic between peers is encrypted using WireGuard
- Exit nodes can see the unencrypted traffic they forward
- No central server stores connection information
- NAT traversal information is only stored temporarily in memory

## License

[MIT License](LICENSE) 
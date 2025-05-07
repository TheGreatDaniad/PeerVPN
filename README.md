# PeerVPN

A peer-to-peer VPN solution using WireGuard tunnels with direct connections between peers.

## Features

- Direct peer-to-peer connections using WireGuard tunnels
- NAT traversal using STUN
- Cross-platform support (Linux, macOS, Windows)
- Manual peer connections with unique IDs
- Traffic routing through exit nodes
- No central server required for connections

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
4. Display connection information for clients

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
2. **Peer Discovery**: Connection information is exchanged manually between users.
3. **WireGuard Tunneling**: A secure WireGuard tunnel is established between peers.
4. **Routing Configuration**: Traffic is configured to route through the tunnel appropriately.

## Architecture

The system consists of the following components:

1. **Configuration Management**: Handles program settings and WireGuard key pairs
2. **NAT Traversal**: Discovers public endpoints using STUN
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
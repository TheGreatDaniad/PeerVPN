#!/bin/bash
# Emergency network recovery script for PeerVPN on macOS
# Run this with sudo if you lose internet connectivity

echo "===== Emergency Network Recovery Tool ====="
echo "Attempting to restore your internet connection..."

# Kill any running WireGuard processes
echo "Stopping any WireGuard processes..."
pkill -f wireguard
pkill -f wg-quick
pkill -f "wireguard-go"

# Remove all utun interfaces that might be related to WireGuard
echo "Removing WireGuard interfaces..."
for i in {0..20}; do
  ifconfig utun$i destroy 2>/dev/null
done

# Flush the routing table
echo "Flushing routing tables..."
route -n flush
networksetup -setairportpower en0 off 2>/dev/null
networksetup -setairportpower en0 on 2>/dev/null

# Add back common default routes for your network
echo "Adding default routes..."
route -n add default 172.20.10.1  # Your primary gateway from logs
route -n add default 10.0.0.1     # Common gateway

# If using Wi-Fi, try resetting it
echo "Resetting Wi-Fi connection..."
networksetup -setairportpower en0 off
sleep 1
networksetup -setairportpower en0 on

# Test connectivity to common servers
echo "Testing connectivity..."
ping -c 1 -t 1 8.8.8.8
ping -c 1 -t 1 google.com

echo "===== Recovery Process Complete ====="
echo "If you're still experiencing issues, please restart your computer."
echo "To prevent this issue in the future, use: sudo ./peervpn --connect=... --no-route" 
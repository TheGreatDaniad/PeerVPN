#!/bin/bash

# Emergency Network Recovery Script for PeerVPN
# Use this if PeerVPN cleanup fails and your network is broken

echo "=== PeerVPN Emergency Network Recovery ==="
echo "This script attempts to restore basic network connectivity"
echo ""

# Function to detect the likely default gateway
detect_gateway() {
    # Try multiple methods to find the gateway
    
    # Method 1: Look for DHCP lease info (macOS)
    if [ -f "/var/db/dhcpd_leases" ]; then
        gateway=$(grep -E "router.*:" /var/db/dhcpd_leases 2>/dev/null | tail -1 | cut -d: -f2 | tr -d ' ')
        if [ -n "$gateway" ]; then
            echo "Found gateway from DHCP lease: $gateway"
            echo "$gateway"
            return 0
        fi
    fi
    
    # Method 2: Common residential router IPs
    common_gateways="192.168.1.1 192.168.0.1 192.168.2.1 192.168.1.254 192.168.0.254 192.168.2.254 10.0.0.1 10.0.1.1"
    
    for gw in $common_gateways; do
        if ping -c 1 -W 1 "$gw" >/dev/null 2>&1; then
            echo "Found responding gateway: $gw"
            echo "$gw"
            return 0
        fi
    done
    
    # Method 3: Try to extract from network interfaces
    for interface in en0 en1 eth0 wlan0; do
        if ifconfig "$interface" 2>/dev/null | grep -q "inet "; then
            ip=$(ifconfig "$interface" | grep "inet " | awk '{print $2}')
            # Assume gateway is .1 or .254 of the same network
            network=$(echo "$ip" | cut -d. -f1-3)
            for suffix in 1 254; do
                gw="$network.$suffix"
                if ping -c 1 -W 1 "$gw" >/dev/null 2>&1; then
                    echo "Found gateway by network inference: $gw"
                    echo "$gw"
                    return 0
                fi
            done
        fi
    done
    
    echo ""
    return 1
}

# Function to get main network interface
get_main_interface() {
    # Try common interface names
    for interface in en0 en1 eth0 wlan0; do
        if ifconfig "$interface" 2>/dev/null | grep -q "inet " && ifconfig "$interface" | grep -q "status: active"; then
            echo "$interface"
            return 0
        fi
    done
    echo "en0"  # fallback
}

echo "1. Checking current network state..."
if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Network appears to be working already"
    exit 0
fi

echo "❌ Network connectivity broken, attempting recovery..."
echo ""

echo "2. Detecting network configuration..."
gateway=$(detect_gateway)
interface=$(get_main_interface)

if [ -z "$gateway" ]; then
    echo "❌ Could not automatically detect gateway"
    echo "Please run one of these commands manually:"
    echo ""
    echo "# For typical home networks, try:"
    echo "sudo route -n add default 192.168.1.1"
    echo "sudo route -n add default 192.168.0.1" 
    echo "sudo route -n add default 192.168.2.1"
    echo ""
    echo "# To check your router's admin page for the correct gateway IP"
    exit 1
fi

echo "Detected gateway: $gateway"
echo "Primary interface: $interface"
echo ""

echo "3. Cleaning up existing routes..."
# Remove any existing default routes
sudo route -n flush >/dev/null 2>&1

echo "4. Restoring default route..."
sudo route -n add default "$gateway" 2>/dev/null

# Wait a moment
sleep 1

echo "5. Testing connectivity..."
if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ SUCCESS: Network connectivity restored!"
    echo "   Gateway: $gateway"
    echo "   Interface: $interface"
    echo ""
    echo "Your internet should now be working."
else
    echo "❌ FAILED: Could not restore connectivity"
    echo ""
    echo "Manual steps to try:"
    echo "1. Check your router's IP address (usually printed on the router)"
    echo "2. Run: sudo route -n add default [your_router_ip]"
    echo "3. Check if your WiFi/Ethernet cable is connected"
    echo "4. Restart your network interface:"
    echo "   sudo ifconfig $interface down && sudo ifconfig $interface up"
    echo "5. As a last resort, reboot your computer"
fi 
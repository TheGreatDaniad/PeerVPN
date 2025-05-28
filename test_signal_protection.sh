#!/bin/bash

# Test script to verify signal protection during cleanup
# This simulates rapid Ctrl+C presses to ensure routing is still restored

echo "=== PeerVPN Signal Protection Test ==="
echo ""

# Function to test internet connectivity
test_connectivity() {
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        echo "✅ Internet connectivity: OK"
        return 0
    else
        echo "❌ Internet connectivity: FAILED"
        return 1
    fi
}

# Function to get current default gateway
get_gateway() {
    route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}'
}

echo "1. Initial connectivity test:"
if ! test_connectivity; then
    echo "❌ Initial connectivity test failed - cannot proceed"
    exit 1
fi

INITIAL_GATEWAY=$(get_gateway)
echo "   Initial gateway: $INITIAL_GATEWAY"
echo ""

echo "2. Starting PeerVPN and simulating rapid Ctrl+C..."
echo "   This will test if multiple interrupts can break routing restoration"
echo ""

# Start PeerVPN in background
sudo ./peervpn --exit &
PEERVPN_PID=$!

echo "   PeerVPN started (PID: $PEERVPN_PID)"

# Wait a moment for PeerVPN to set up routing
sleep 3

echo "   Sending multiple SIGINT signals rapidly..."

# Send multiple rapid signals to simulate rapid Ctrl+C
for i in {1..5}; do
    echo "     Signal $i/5..."
    kill -INT $PEERVPN_PID 2>/dev/null
    sleep 0.2  # Very short delay between signals
done

echo "   Waiting for cleanup to complete..."

# Wait for the process to exit (with timeout)
for i in {1..15}; do
    if ! kill -0 $PEERVPN_PID 2>/dev/null; then
        echo "   PeerVPN process has exited"
        break
    fi
    sleep 1
    if [ $i -eq 15 ]; then
        echo "   Timeout: PeerVPN process still running, forcing kill"
        sudo kill -9 $PEERVPN_PID 2>/dev/null
    fi
done

echo ""

# Give system time to settle
sleep 2

echo "3. Post-interruption connectivity test:"
FINAL_GATEWAY=$(get_gateway)

if test_connectivity; then
    echo "   Final gateway: $FINAL_GATEWAY"
    echo ""
    
    if [ "$INITIAL_GATEWAY" = "$FINAL_GATEWAY" ]; then
        echo "🎉 SUCCESS: Signal protection worked!"
        echo "   ✅ Internet connectivity restored"
        echo "   ✅ Gateway properly restored ($FINAL_GATEWAY)"
        echo "   ✅ Multiple Ctrl+C signals handled correctly"
        exit 0
    else
        echo "⚠️  PARTIAL SUCCESS: Connectivity restored but gateway changed"
        echo "   ✅ Internet connectivity restored"
        echo "   ⚠️  Gateway changed: $INITIAL_GATEWAY → $FINAL_GATEWAY"
        echo "   (This might be acceptable if DHCP assigned a new gateway)"
        exit 0
    fi
else
    echo "   Final gateway: $FINAL_GATEWAY"
    echo ""
    echo "💥 FAILURE: Network connectivity not restored!"
    echo "   ❌ Internet access broken"
    echo "   ❌ Multiple Ctrl+C signals interrupted cleanup"
    echo ""
    echo "Manual recovery may be needed:"
    echo "   sudo route -n add default $INITIAL_GATEWAY"
    exit 1
fi 
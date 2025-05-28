#!/bin/bash

# Test script to verify routing restoration functionality
# This tests that PeerVPN properly restores network connectivity after exit

echo "=== PeerVPN Routing Restoration Test ==="
echo ""

# Function to test internet connectivity
test_connectivity() {
    echo "Testing internet connectivity..."
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        echo "✅ Internet connectivity: OK"
        return 0
    else
        echo "❌ Internet connectivity: FAILED"
        return 1
    fi
}

# Function to check default route
check_default_route() {
    echo "Checking default route..."
    if route -n get default >/dev/null 2>&1; then
        local gateway=$(route -n get default | grep 'gateway:' | awk '{print $2}')
        echo "✅ Default route: $gateway"
        return 0
    else
        echo "❌ Default route: NOT FOUND"
        return 1
    fi
}

# Function to display routing table summary
show_route_summary() {
    echo "Current routing summary:"
    echo "  Default route: $(route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}' || echo 'NOT FOUND')"
    echo "  Route count: $(netstat -rn -f inet | grep -v '^Routing' | grep -v '^Destination' | grep -v '^$' | wc -l | tr -d ' ')"
}

echo "1. Initial network state:"
show_route_summary
echo ""

echo "2. Testing initial connectivity:"
if ! test_connectivity; then
    echo "❌ Initial connectivity test failed - cannot proceed"
    exit 1
fi
echo ""

echo "3. Starting PeerVPN exit node for 10 seconds..."
echo "   (This will modify routing tables)"
echo ""

# Start PeerVPN in background and capture its PID
sudo timeout 10s ./peervpn --exit >/dev/null 2>&1 &
PEERVPN_PID=$!

# Wait for it to start up
sleep 3
echo "   PeerVPN is running (PID: $PEERVPN_PID)..."

# Wait for it to finish or timeout
wait $PEERVPN_PID 2>/dev/null
PEERVPN_EXIT_CODE=$?

echo ""
echo "4. PeerVPN has exited (code: $PEERVPN_EXIT_CODE)"
echo ""

# Give the system a moment to settle
sleep 2

echo "5. Post-exit network state:"
show_route_summary
echo ""

echo "6. Testing connectivity after restoration:"
if test_connectivity && check_default_route; then
    echo ""
    echo "🎉 SUCCESS: Network connectivity properly restored!"
    echo "   ✅ Internet access working"
    echo "   ✅ Default route present"
    echo "   ✅ No routing table corruption"
    exit 0
else
    echo ""
    echo "💥 FAILURE: Network connectivity not properly restored!"
    echo "   This indicates a problem with routing restoration."
    echo ""
    echo "Debug information:"
    echo "Current route table:"
    netstat -rn -f inet | head -20
    exit 1
fi 
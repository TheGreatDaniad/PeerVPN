#!/bin/bash

echo "==============================================="
echo "PeerVPN NAT Persistence Monitoring Test"
echo "==============================================="
echo ""
echo "This script demonstrates the NAT monitoring feature"
echo "which logs your public endpoint every 10 seconds"
echo "to verify port persistence over time."
echo ""
echo "What you'll see:"
echo "• Initial exit node setup"
echo "• Public endpoint discovery"
echo "• Continuous monitoring every 10 seconds"
echo "• ✅ Port persistent = same endpoint" 
echo "• ⚠️  Port changed = endpoint changed"
echo ""
echo "Press Ctrl+C to stop monitoring at any time"
echo ""
echo "Starting in 3 seconds..."
sleep 3

echo "Running: sudo ./peervpn --exit --monitor-nat"
echo ""
sudo ./peervpn --exit --monitor-nat 
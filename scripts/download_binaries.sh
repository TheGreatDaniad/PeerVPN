#!/bin/bash
set -e

# Create directories
mkdir -p bin/linux bin/darwin bin/windows

# Set version
WG_TOOLS_VERSION="1.0.20210914"
WIREGUARD_GO_VERSION="0.0.20230223"

# Download for Linux
echo "Downloading WireGuard tools for Linux..."
curl -sSL "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${WG_TOOLS_VERSION}.tar.xz" -o wireguard-tools.tar.xz
tar -xf wireguard-tools.tar.xz
cd wireguard-tools-${WG_TOOLS_VERSION}/src
make
cp wg ../../../bin/linux/
cd ../../
rm -rf wireguard-tools-${WG_TOOLS_VERSION} wireguard-tools.tar.xz

# Download wireguard-go for Linux
echo "Downloading wireguard-go for Linux..."
curl -sSL "https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-${WIREGUARD_GO_VERSION}.tar.xz" -o wireguard-go.tar.xz
tar -xf wireguard-go.tar.xz
cd wireguard-go-${WIREGUARD_GO_VERSION}
make
cp wireguard-go ../bin/linux/
cd ..
rm -rf wireguard-go-${WIREGUARD_GO_VERSION} wireguard-go.tar.xz

# Download for macOS
echo "Downloading WireGuard tools for macOS..."
curl -sSL "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${WG_TOOLS_VERSION}.tar.xz" -o wireguard-tools.tar.xz
tar -xf wireguard-tools.tar.xz
cd wireguard-tools-${WG_TOOLS_VERSION}/src
make
cp wg ../../bin/darwin/
cd ../../
rm -rf wireguard-tools-${WG_TOOLS_VERSION} wireguard-tools.tar.xz

# Download wireguard-go for macOS
echo "Downloading wireguard-go for macOS..."
curl -sSL "https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-${WIREGUARD_GO_VERSION}.tar.xz" -o wireguard-go.tar.xz
tar -xf wireguard-go.tar.xz
cd wireguard-go-${WIREGUARD_GO_VERSION}
make
cp wireguard-go ../bin/darwin/
cd ..
rm -rf wireguard-go-${WIREGUARD_GO_VERSION} wireguard-go.tar.xz

# Download for Windows
echo "Downloading WireGuard for Windows..."
# For Windows we'll need to download the installer and extract the needed components
curl -sSL "https://download.wireguard.com/windows-client/wireguard-installer.exe" -o bin/windows/wireguard.exe

echo "Binaries downloaded successfully!" 
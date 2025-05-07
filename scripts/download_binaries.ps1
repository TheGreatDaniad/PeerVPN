# Create directories
New-Item -ItemType Directory -Force -Path bin\windows

# Download WireGuard for Windows
Write-Host "Downloading WireGuard for Windows..."
Invoke-WebRequest -Uri "https://download.wireguard.com/windows-client/wireguard-installer.exe" -OutFile "bin\windows\wireguard.exe"

Write-Host "Windows binary downloaded successfully!" 
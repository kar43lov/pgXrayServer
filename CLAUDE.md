# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a pgXrayServer project that provides an interactive bash script for setting up Ubuntu systems as VPN routers using Xray with VLESS Reality protocol. The project consists of a single comprehensive setup script written in Russian.

## Repository Structure

The repository contains:
- `setup_final_bash.sh` - Main interactive setup script (932 lines)
- `README.md` - Basic project documentation
- Git repository initialized with main branch

## Script Architecture

The `setup_final_bash.sh` script is a comprehensive VPN router configuration tool with the following structure:

### Core Components
- **Interactive Menu System**: 7 different operation modes
- **Network Configuration**: Automated network interface detection and setup
- **VPN Integration**: Xray with VLESS Reality protocol configuration
- **System Services**: DHCP server, iptables firewall, SSH server management
- **GUI Management**: Enable/disable Ubuntu visual interface

### Key Functions
- `show_menu()` - Main interactive menu (lines 32-91)
- `check_root()` - Root privilege verification (lines 93-99)
- `check_vless_link()` - VLESS URL validation and input (lines 101-193)
- `cleanup_previous_install()` - System cleanup (lines 195-219)
- `setup_pppoe_interactive()` - Optional PPPoE connection setup (lines 221-269)
- `install_dependencies()` - Package installation (lines 271-278)
- `configure_network_interactive()` - Network interface setup (lines 280-379)
- `configure_system_core()` - Kernel parameters configuration (lines 381-391)
- `generate_xray_config()` - Xray configuration generation (lines 393-431)
- `setup_xray()` - Xray installation and configuration (lines 433-443)
- `setup_dhcp_interactive()` - Optional DHCP server setup (lines 445-466)
- `setup_firewall()` - iptables rules configuration (lines 468-484)
- `finalize()` - Service restart and final setup (lines 486-535)
- `cleanup_only()` - Standalone cleanup mode (lines 537-569)
- `update_xray_config()` - Update Xray config without reinstall (lines 571-635)
- `disable_gui()` - Disable Ubuntu GUI (lines 637-704)
- `enable_gui()` - Enable Ubuntu GUI (lines 706-769)
- `setup_ssh()` - SSH server configuration (lines 771-895)

### Operation Modes
1. Full installation (cleanup + install + configure)
2. Xray configuration update only
3. System cleanup only
4. Disable GUI
5. Enable GUI
6. SSH configuration
7. Exit

## Development Commands

This is a bash script project with no build system. To work with the script:

**Run the script** (requires root privileges):
```bash
sudo bash setup_final_bash.sh
```

**Test syntax**:
```bash
bash -n setup_final_bash.sh
```

## Security Considerations

⚠️ **SECURITY NOTICE**: This script requires root privileges and performs system-level modifications including:
- Network interface configuration
- Firewall rule modifications
- System service management
- User password modifications
- Package installation/removal

The script is designed for defensive VPN router setup purposes and should only be used on dedicated server systems.

## Configuration Requirements

The script requires:
- VLESS URL configuration (either in `vless_link.txt` file or manual input)
- Root/sudo access
- Ubuntu system with network interfaces
- Internet connectivity for package downloads

## Script Language

The script is written in Russian with Russian-language user interface and comments. All user prompts and error messages are in Russian.

## Xray Configuration Architecture

The script generates a comprehensive Xray configuration with the following components:

### VLESS URL Parsing
The script parses VLESS URLs to extract:
- `VLESS_ID` - User UUID
- `VLESS_HOST` - Server hostname
- `VLESS_PORT` - Server port
- `VLESS_PBK` - Public key (Reality protocol)
- `VLESS_FP` - Fingerprint
- `VLESS_SNI` - Server name indication
- `VLESS_SID` - Short ID
- `VLESS_SPX` - Spider X parameter (URL decoded)
- `VLESS_FLOW` - Flow control method

### Xray Inbounds
1. **Transparent Proxy** (port 12345): Dokodemo-door protocol for traffic redirection
2. **DNS Server** (port 53): Dokodemo-door for DNS queries to 1.1.1.1

### Xray Outbounds
1. **vless-reality**: Main VPN connection using VLESS with Reality protocol
2. **direct**: Direct connection without VPN
3. **block**: Blocks specified traffic
4. **dns-out**: DNS query handler

### Routing Rules (Order Matters)
1. DNS queries → direct connection
2. Block Windows NetBIOS ports (135, 137-139) from LAN
3. Block appcenter.ms domain
4. Direct route for specific IP (94.79.52.202:4004 UDP)
5. Direct route for Russian domains (.ru, .su, .рф, etc.) and Russian government sites
6. Direct route for VK, Yandex, Steam
7. Direct route for BitTorrent protocol
8. All other traffic → VPN (vless-reality)

## Network Architecture

### Default Network Configuration
- **LAN IP**: 192.168.100.1/24 (customizable)
- **DHCP Range**: 192.168.100.100-200 (if DHCP enabled)
- **DNS Server**: LAN IP (router itself)

### iptables Rules
The script creates PREROUTING NAT rules to redirect LAN traffic:
- DNS traffic (port 53 TCP/UDP) → redirect to port 53 (Xray DNS inbound)
- All other TCP/UDP traffic → redirect to port 12345 (Xray transparent proxy)
- POSTROUTING: Masquerade for WAN interface

### System Configuration
- **IPv4 forwarding**: Enabled (`net.ipv4.ip_forward=1`)
- **IPv6 forwarding**: Disabled (`net.ipv6.conf.all.forwarding=0`)
- **Netplan**: Used for persistent network configuration
- **Renderer**: Auto-detected (NetworkManager or networkd)

## External Dependencies

The script downloads and installs:
- **Xray**: From official XTLS repository (`install-release.sh`)
- **Geosite rules**: From SukkaW/v2ray-rules-dat (`geosite.dat`)
- **System packages**: `curl`, `unzip`, `isc-dhcp-server`, `iptables-persistent`, `net-tools`

## Service Management

Services managed by the script:
- `xray.service` - Main VPN proxy service
- `isc-dhcp-server.service` - DHCP server (optional)
- `ssh.service` - SSH server (optional configuration)
- Display managers: `gdm3`, `gdm`, `lightdm`, `sddm`, `xdm` (for GUI management)

## State Persistence

Configuration files created/modified:
- `/usr/local/etc/xray/config.json` - Xray configuration
- `/etc/netplan/*.yaml` - Network configuration
- `/etc/dhcp/dhcpd.conf` - DHCP server configuration
- `/etc/default/isc-dhcp-server` - DHCP interface binding
- `/etc/ssh/sshd_config` - SSH server configuration
- `/etc/sysctl.conf` - Kernel parameters
- Iptables rules saved via `netfilter-persistent`
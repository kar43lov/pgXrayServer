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
- `check_vless_link()` - VLESS URL validation and input (lines 101-193)
- `cleanup_previous_install()` - System cleanup (lines 195-219)
- `configure_network_interactive()` - Network interface setup (lines 280-379)
- `generate_xray_config()` - Xray configuration generation (lines 393-431)
- `setup_firewall()` - iptables rules configuration (lines 461-477)

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
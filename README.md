# Windows Privacy Blocker

## Overview

**Privacy Blocker** is a PowerShell script designed to enhance your privacy by blocking telemetry fields and IP addresses. The script performs the following actions:

1. Clears the existing contents of the Hosts file and appends it with both IPv4 and IPv6 entries to block the specified domains.
2. Blocks the specified IP addresses using Windows Firewall rules.

## Features

- Cleans and updates the hosts file to block specified domains.
- Supports both IPv4 (**0.0.0.0.0**) and IPv6 (**::1**) entries to block domains.
- Blocks specified IP addresses using Windows Firewall.
- Includes comments for each blocked entry for easy identification.

## Prerequisites

- Windows operating system.
- PowerShell with administrator privileges.

## Usage

1. Open PowerShell with administrator privileges.
2. Run the script using the following command:
```
irm "https://raw.githubusercontent.com/oqullcan/Privacy-Blocker/main/PrivacyBlocker.ps1" | iex
```
3. Enter.

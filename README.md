
# BERRY-privacy

This PowerShell script enhances privacy and security on Windows systems by disabling telemetry settings, blocking telemetry IPs via firewall, and modifying system settings to minimize data collection and transmission.

## Features

- **Telemetry Disabling:** Disables telemetry settings in Windows 10 and 11 through registry modifications.
- **Firewall Blocking:** Blocks telemetry IPs using Windows Firewall rules.
- **Hosts File Modification:** Adds telemetry domains to the hosts file to prevent data collection from specified domains.

## Usage

1. Open PowerShell with administrator privileges.
2. Run the script using the following command:
```
irm https://raw.githubusercontent.com/oqullcan/BERRY-privacy/main/BERRY-privacy.ps1 | iex
```
3. Enter.

## Disclaimer

- Use this script at your own risk. Understand the implications of disabling telemetry and modifying system settings before executing the script.
- Always review and verify the changes made by the script to ensure they align with your system's security and privacy requirements.

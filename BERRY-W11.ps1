# Function to log messages with timestamps and colors
function Write-Log {
    param (
        [string]$message,
        [string]$type = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($type) {
        "INFO" { Write-Host "$timestamp [$type] $message" -ForegroundColor Cyan }
        "ERROR" { Write-Host "$timestamp [$type] $message" -ForegroundColor Red }
        "SUCCESS" { Write-Host "$timestamp [$type] $message" -ForegroundColor Green }
        default { Write-Host "$timestamp [$type] $message" -ForegroundColor White }
    }
}

# Function to set registry values directly
function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )

    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
        Write-Log "Set $name to $value at $path." "SUCCESS"
    } catch {
        Write-Log "Failed to set $name at $path. Error: $_" "ERROR"
    }
}

# Function to add telemetry domains to the hosts file
function Add-DomainsToHostsFile {
    param (
        [string]$hostsFilePath,
        [string[]]$domains,
        [string]$comment = "x.com/oqullcn"
    )

    try {
        if (-not (Test-Path -Path $hostsFilePath -PathType Leaf)) {
            Write-Log "Creating a new hosts file at $hostsFilePath." "INFO"
            New-Item -Path $hostsFilePath -ItemType File -Force | Out-Null
            Write-Log "Successfully created the hosts file." "SUCCESS"
        }

        foreach ($domain in $domains) {
            $existingEntry = Get-Content -Path $hostsFilePath -ErrorAction SilentlyContinue | Where-Object { $_ -match "^0\.0\.0\.0\s+$domain" }
            if ($existingEntry) {
                Write-Log "Skipping, entry already exists for domain $domain." "INFO"
                continue
            }

            $newEntry = "0.0.0.0`t$domain $([char]35) $comment"
            Add-Content -Path $hostsFilePath -Value $newEntry -ErrorAction Stop
            Write-Log "Successfully added the entry for domain $domain." "SUCCESS"
        }
    } catch {
        Write-Log "Failed to add domains to hosts file. Error: $_" "ERROR"
    }
}

# Function to block telemetry IPs via Windows Firewall
function Block-TelemetryIPs {
    param (
        [string[]]$ips
    )

    try {
        $ruleName = "Block Telemetry IPs"
        Write-Log "Creating firewall rule '$ruleName' to block telemetry IPs." "INFO"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ips -ErrorAction Stop | Out-Null
        Write-Log "Successfully created firewall rule to block telemetry IPs." "SUCCESS"
    } catch {
        Write-Log "Failed to create firewall rule. Error: $_" "ERROR"
    }
}

# Function to disable telemetry settings in Windows registry
function Disable-Telemetry {
    try {
        $telemetrySettings = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feedback",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Telemetry",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync",
            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
        )

        foreach ($path in $telemetrySettings) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }

        # Telemetry settings
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -name "AllowTelemetry" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -name "DoNotShowFeedbackNotifications" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -name "NoLockScreenCamera" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -name "Disabled" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsConsumerFeatures" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsTips" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feedback" -name "DoNotShowFeedbackNotifications" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -name "NoCloudSync" -type "DWORD" -value 1

        # Additional settings
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -name "Disabled" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Telemetry" -name "DisableEnhancedTelemetry" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -name "AllowClipboardHistory" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -name "AllowCrossDeviceClipboard" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -name "EnableActivityFeed" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -name "PublishUserActivities" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -name "UploadUserActivities" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -name "DisableFileSyncNGSC" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search" -name "AllowCortana" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search" -name "ConnectedSearchUseWeb" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search" -name "AllowSearchToUseLocation" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -name "DisableSettingSync" -type "DWORD" -value 2
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -name "RestrictImplicitTextCollection" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -name "MDMEnrollmentURL" -type "STRING" -value ""
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall" -name "DisablePushToInstall" -type "DWORD" -value 1

        Write-Log "Telemetry settings disabled successfully." "SUCCESS"
    } catch {
        Write-Log "Failed to disable telemetry settings. Error: $_" "ERROR"
    }
}

# Main execution starts here

try {
    # Define the hosts file path
    $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

    # Define telemetry domains and IPs
    $domains = @(
    # ...
    )

    $ips = @(
    # ...
    )

    # Add domains to the hosts file
    Add-DomainsToHostsFile -hostsFilePath $hostsFilePath -domains $domains

    # Block telemetry IPs via firewall
    Block-TelemetryIPs -ips $ips

    # Disable telemetry settings in Windows
    Disable-Telemetry

    Write-Log "All tasks completed." "SUCCESS"
} catch {
    Write-Log "Script encountered an error. Error: $_" "ERROR"
}

# Path: DisableTelemetry.ps1

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

# Function to add telemetry domains to the hosts file
function Add-DomainsToHostsFile {
    param (
        [string]$hostsFilePath,
        [string[]]$domains,
        [string]$comment = "x.com/oqullcn"
    )

    $hostsFileEncoding = "UTF8"
    $blockingHostsEntries = @(
        @{ AddressType = "IPv4"; IPAddress = '0.0.0.0'; },
        @{ AddressType = "IPv6"; IPAddress = '::1'; }
    )

    try {
        if (-Not (Test-Path -Path $hostsFilePath -PathType Leaf)) {
            Write-Log "Creating a new hosts file at $hostsFilePath." "INFO"
            New-Item -Path $hostsFilePath -ItemType File -Force | Out-Null
            Write-Log "Successfully created the hosts file." "SUCCESS"
        }

        foreach ($domain in $domains) {
            foreach ($blockingEntry in $blockingHostsEntries) {
                Write-Log "Processing addition for $($blockingEntry.AddressType) entry for domain $domain." "INFO"
                try {
                    $hostsFileContents = Get-Content -Path $hostsFilePath -Raw -Encoding $hostsFileEncoding
                } catch {
                    Write-Log "Failed to read the hosts file. Error: $_" "ERROR"
                    continue
                }

                $hostsEntryLine = "$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"

                if ($hostsFileContents -contains $hostsEntryLine) {
                    Write-Log "Skipping, entry already exists for domain $domain." "INFO"
                    continue
                }

                try {
                    Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding
                    Write-Log "Successfully added the entry for domain $domain." "SUCCESS"
                } catch {
                    Write-Log "Failed to add the entry for domain $domain. Error: $_" "ERROR"
                    continue
                }
            }
        }
    } catch {
        Write-Log "Unexpected error in Add-DomainsToHostsFile. Error: $_" "ERROR"
        exit 1
    }
}

# Function to block telemetry IPs via Windows Firewall
function Block-TelemetryIPs {
    param (
        [string[]]$ips
    )

    try {
        Remove-NetFirewallRule -DisplayName "PrivacyBlocker" -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "PrivacyBlocker" -Direction Outbound -Action Block -RemoteAddress $ips | Out-Null
        Write-Log "Successfully created firewall rule to block telemetry IPs." "SUCCESS"
    } catch {
        Write-Log "Failed to create firewall rule. Error: $_" "ERROR"
    }
}

# Function to disable telemetry settings in Windows 10 and 11
function Disable-Telemetry {
    try {
        Write-Log "Disabling telemetry via registry settings." "INFO"
        $telemetrySettings = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feedback",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        )

        foreach ($path in $telemetrySettings) {
            if (-Not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }

        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -name "AllowTelemetry" -type "DWORD" -value 0
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -name "DoNotShowFeedbackNotifications" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -name "NoLockScreenCamera" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -name "Disabled" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsConsumerFeatures" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsTips" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feedback" -name "DoNotShowFeedbackNotifications" -type "DWORD" -value 1
        Set-RegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -name "NoCloudSync" -type "DWORD" -value 1

        Write-Log "Disabling DiagTrack service." "INFO"
        Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue | Out-Null
        Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction Stop

        Write-Log "Disabling dmwappushservice service." "INFO"
        Stop-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue | Out-Null
        Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction Stop

        Write-Log "Disabling Connected User Experiences and Telemetry (DiagTrack)." "INFO"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "Start" -Value 4 -ErrorAction Stop

        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushsvc") {
            Write-Log "Disabling dmwappushsvc." "INFO"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushsvc" -Name "Start" -Value 4 -ErrorAction Stop
        } else {
            Write-Log "dmwappushsvc service not found. Skipping." "INFO"
        }

        Write-Log "Telemetry settings disabled successfully." "SUCCESS"
    } catch {
        Write-Log "Failed to disable telemetry settings. Error: $_" "ERROR"
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
        if (-Not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
        Write-Log "Set $name to $value at $path." "SUCCESS"
    } catch {
        Write-Log "Failed to set $name at $path. Error: $_" "ERROR"
    }
}

# Device Guard
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -name "EnableVirtualizationBasedSecurity" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -name "RequirePlatformSecurityFeatures" -type "DWORD" -value 3
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -name "SecureLaunch" -type "DWORD" -value 1

# Internet Communication Management
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -name "CEIPEnable" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -name "Disabled" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Messenger\CustomerExperienceImprovement" -name "CEIPEnable" -type "DWORD" -value 0

# OS Policies
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\System" -name "AllowClipboardHistory" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\System" -name "AllowCrossDeviceClipboard" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\System" -name "EnableActivityFeed" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\System" -name "PublishUserActivities" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\System" -name "UploadUserActivities" -type "DWORD" -value 0

# User Profiles
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -name "Disabled" -type "DWORD" -value 1

# AutoPlay Policies
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoDriveTypeAutoRun" -type "DWORD" -value 255
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoAutorun" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoAutoplayforNonVolume" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoDriveAutorun" -type "DWORD" -value 67108863

# BitLocker Drive Encryption
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\FVE" -name "EncryptionMethodWithXtsFdv" -type "DWORD" -value 4
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\FVE" -name "UseAdvancedStartup" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\FVE" -name "UseEnhancedPIN" -type "DWORD" -value 1

# Cloud Content
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -name "DisableSoftLanding" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsConsumerFeatures" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -name "DisableWindowsTips" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -name "DisableCloudOptimizedContent" -type "DWORD" -value 1

# Credential User Interface
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -name "RequireTrustedPath" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -name "DisablePasswordReveal" -type "DWORD" -value 1

# Data Collection and Preview Builds
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -name "AllowTelemetry" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -name "LimitDiagnosticLogCollection" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -name "LimitDumpCollection" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -name "DisableDesktopAnalytics" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -name "DoNotShowFeedbackNotifications" -type "DWORD" -value 1

# File Explorer
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoFirstLogonAnimation" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -name "NoInstrumentation" -type "DWORD" -value 1

# MDM
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\MDM" -name "MDMEnrollmentURL" -type "STRING" -value ""

# OneDrive
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -name "DisableFileSyncNGSC" -type "DWORD" -value 1

# Push To Install
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\PushToInstall" -name "DisablePushToInstall" -type "DWORD" -value 1

# Search
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -name "AllowCortana" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -name "ConnectedSearchUseWeb" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -name "AllowSearchToUseLocation" -type "DWORD" -value 0

# Sync your settings
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -name "DisableSettingSync" -type "DWORD" -value 2

# Text input
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -name "RestrictImplicitTextCollection" -type "DWORD" -value 1

# Windows Error Reporting
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -name "Disabled" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -name "AutoApproveSubmission" -type "DWORD" -value 1
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -name "AutoApproveAlways" -type "DWORD" -value 0
Set-RegistryValue -path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -name "AutoApproveNoOverride" -type "DWORD" -value 0

# Function to disable diagnostic data processor
function Disable-DiagnosticDataProcessor {
    try {
        Write-Log "Disabling diagnostic data processor." "INFO"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManageProcessor" -Value 0 -Force -ErrorAction Stop
        Write-Log "Successfully disabled diagnostic data processor." "SUCCESS"
    } catch {
        Write-Log "Failed to disable diagnostic data processor. Error: $_" "ERROR"
    }
}

# Function to disable feedback and diagnostic services
function Disable-FeedbackDiagnosticServices {
    try {
        Write-Log "Disabling feedback and diagnostic services." "INFO"
        $services = @(
            "DiagTrack",
            "dmwappushservice",
            "PcaSvc",
            "diagnosticshub.standardcollector.service"
        )

        foreach ($service in $services) {
            Write-Log "Disabling $service service." "INFO"
            Stop-Service -Name $service -ErrorAction SilentlyContinue | Out-Null
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Log "Successfully disabled $service service." "SUCCESS"
        }
    } catch {
        Write-Log "Failed to disable feedback and diagnostic services. Error: $_" "ERROR"
    }
}

# Define the hosts file path
$hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

# Define telemetry domains and IPs
$domains = @(
    # Activity
    "activity.windows.com",
    "activity-consumer.trafficmanager.net",

    # Windows Crash Report
    "telemetry.microsoft.com",
    "outlookads.live.com"
)

$ips = @(
    "2.22.61.43",
    "2.22.61.66",
    "216.228.121.209"
)

# Add domains to the hosts file
Add-DomainsToHostsFile -hostsFilePath $hostsFilePath -domains $domains

# Block telemetry IPs via firewall
Block-TelemetryIPs -ips $ips

# Disable telemetry settings in Windows 10 and 11
Disable-Telemetry

# Disable diagnostic data processor
Disable-DiagnosticDataProcessor

# Disable feedback and diagnostic services
Disable-FeedbackDiagnosticServices

Write-Log "All tasks completed." "SUCCESS"

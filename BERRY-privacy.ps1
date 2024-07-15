# Path: BERRY-privacy.ps1

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
        Remove-NetFirewallRule -DisplayName "BERRY-privacy" -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "BERRY-privacy" -Direction Outbound -Action Block -RemoteAddress $ips | Out-Null
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

$dnsServers = @{
    IPv4Preferred = "9.9.9.9"
    IPv4Alternate = "149.112.112.112"
    IPv6Preferred = "2620:fe::fe"
    IPv6Alternate = "2620:fe::9"
}
$networkProfiles = Get-NetAdapter | Get-NetIPInterface -AddressFamily IPv4, IPv6 | Where-Object { $_.ConnectionState -eq 'Connected' }

foreach ($profile in $networkProfiles) {
    Set-DnsClientServerAddress -InterfaceAlias $profile.InterfaceAlias -ServerAddresses ($dnsServers.IPv4Preferred, $dnsServers.IPv4Alternate)
    Set-DnsClientServerAddress -InterfaceAlias $profile.InterfaceAlias -ServerAddresses ($dnsServers.IPv6Preferred, $dnsServers.IPv6Alternate)
}

# Define the hosts file path
$hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

# Define telemetry domains and IPs
$domains = @(

    # Dropbox
    "telemetry.dropbox.com",
    "telemetry.v.dropbox.com",

    # Windows Crash Report
    "oca.telemetry.microsoft.com",
    "oca.microsoft.com",
    "kmwatsonc.events.data.microsoft.com",

    # Windows Error Reporting
    "watson.telemetry.microsoft.com",
    "umwatsonc.events.data.microsoft.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
    "co4.telecommand.telemetry.microsoft.com",
    "cs11.wpc.v0cdn.net",
    "cs1137.wpc.gammacdn.net",
    "modern.watson.data.microsoft.com",

    # Telemetry and User Experience
    "functional.events.data.microsoft.com",
    "browser.events.data.msn.com",
    "self.events.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "v10c.events.data.microsoft.com",
    "us-v10c.events.data.microsoft.com",
    "eu-v10c.events.data.microsoft.com",
    "v10.vortex-win.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "www.telecommandsvc.microsoft.com",
    "umwatson.events.data.microsoft.com",
    "watsonc.events.data.microsoft.com",
    "eu-watsonc.events.data.microsoft.com",
    "v20.events.data.microsoft.com",

    # Remote Configuration Sync
    "settings-win.data.microsoft.com",
    "settings.data.microsoft.com",

    # Location Data Sharing
    "inference.location.live.net",
    "location-inference-westus.cloudapp.net",

    # Maps Data and Updates
    "maps.windows.com",
    "dev.virtualearth.net",
    "ecn.dev.virtualearth.net",
    "ecn-us.dev.virtualearth.net",
    "weathermapdata.blob.core.windows.net",
    "r.bing.com",
    "ssl.bing.com",
    "www.bing.com",

    # Block Spotlight Ads and Suggestions 
    "arc.msn.com",
    "ris.api.iris.microsoft.com",
    "api.msn.com",
    "assets.msn.com",
    "c.msn.com",
    "g.msn.com",
    "ntp.msn.com",
    "srtb.msn.com",
    "www.msn.com",
    "fd.api.iris.microsoft.com",
    "staticview.msn.com",
    "mucp.api.account.microsoft.com",
    "query.prod.cms.rt.microsoft.com",

    # Cortona and Live Tiles
    "business.bing.com", 
    "c.bing.com",
    "th.bing.com",
    "edgeassetservice.azureedge.net",
    "c-ring.msedge.net",
    "fp.msedge.net",
    "I-ring.msedge.net",
    "s-ring.msedge.net",
    "dual-s-ring.msedge.net",
    "creativecdn.com",
    "a-ring-fallback.msedge.net",
    "fp-afd-nocache-ccp.azureedge.net",
    "prod-azurecdn-akamai-iris.azureedge.net ",
    "widgetcdn.azureedge.net",
    "widgetservice.azurefd.net",
    "fp-vs.azureedge.net",
    "ln-ring.msedge.net",
    "t-ring.msedge.net",
    "t-ring-fdv2.msedge.net",
    "tse1.mm.bing.net",

    # Onenote
    "cdn.onenote.net",

    # Weather
    "tile-service.weather.microsoft.com",

    # Edge Experimentation
    "config.edge.skype.com",

    # Photos App Sync
    "evoke-windowsservices-tas.msedge.net"

)

$ips = @(
    "2.22.61.43",
    "2.22.61.66",
    "8.36.80.197",
    "8.36.80.224",
    "8.36.80.252",
    "8.36.113.118",
    "8.36.113.141",
    "8.36.80.230",
    "8.36.80.231",
    "8.36.113.126",
    "8.36.80.195",
    "8.36.80.217",
    "8.36.80.237",
    "8.36.80.246",
    "8.36.113.116",
    "8.36.113.139",
    "8.36.80.244",
    "13.68.31.193",
    "13.66.56.243",
    "13.68.82.8",
    "13.70.180.171",
    "13.73.26.107",
    "13.78.130.220",
    "13.78.232.226",
    "13.78.233.133",
    "13.88.28.53",
    "13.92.194.212",
    "20.44.86.43",
    "20.189.74.153",
    "23.99.49.121",
    "23.102.4.253",
    "23.102.21.4",
    "23.103.182.126",
    "23.218.212.69",
    "40.68.222.212",
    "40.69.153.67",
    "40.70.184.83",
    "40.70.220.248",
    "40.70.221.249",
    "40.77.228.47",
    "40.77.228.87",
    "40.77.228.92",
    "40.77.232.101",
    "40.79.85.125",
    "40.90.221.9",
    "40.115.3.210",
    "40.115.119.185",
    "40.119.211.203",
    "40.124.34.70",
    "51.140.40.236",
    "51.140.157.153",
    "51.143.111.7",
    "51.143.111.81",
    "52.114.6.46",
    "52.114.6.47",
    "52.114.7.36",
    "52.114.7.37",
    "52.114.7.38",
    "52.114.7.39",
    "52.114.32.5",
    "52.114.32.6",
    "52.114.32.7",
    "52.114.32.8",
    "52.114.32.24",
    "52.114.32.25",
    "52.114.36.1",
    "52.114.36.2",
    "52.114.36.3",
    "52.114.36.4",
    "52.114.74.43",
    "52.114.74.44",
    "52.114.74.45",
    "52.114.75.78",
    "52.114.75.79",
    "52.114.75.149",
    "52.114.75.150",
    "52.114.76.34",
    "52.114.76.35",
    "52.114.76.37",
    "52.114.77.33",
    "52.114.77.34",
    "52.114.77.137",
    "52.114.77.164",
    "52.114.88.19",
    "52.114.88.20",
    "52.114.88.21",
    "52.114.88.22",
    "52.114.88.28",
    "52.114.88.29",
    "52.114.128.7",
    "52.114.128.8",
    "52.114.128.9",
    "52.114.128.10",
    "52.114.128.43",
    "52.114.128.44",
    "52.114.128.58",
    "52.114.132.14",
    "52.114.132.20",
    "52.114.132.21",
    "52.114.132.22",
    "52.114.132.23",
    "52.114.132.73",
    "52.114.132.74",
    "52.114.158.50",
    "52.114.158.51",
    "52.114.158.52",
    "52.114.158.53",
    "52.114.158.91",
    "52.114.158.92",
    "52.114.158.102",
    "52.138.204.217",
    "52.138.216.83",
    "52.155.172.105",
    "52.157.234.37",
    "52.158.208.111",
    "52.164.241.205",
    "52.169.189.83",
    "52.170.83.19",
    "52.174.22.246",
    "52.178.147.240",
    "52.178.151.212",
    "52.178.178.16",
    "52.178.223.23",
    "52.183.114.173",
    "52.229.39.152",
    "52.230.85.180",
    "52.236.42.239",
    "52.236.43.202",
    "64.4.54.254",
    "65.39.117.230",
    "65.52.108.33",
    "65.55.108.23",
    "65.52.100.7",
    "65.52.100.9",
    "65.52.100.11",
    "65.52.100.91",
    "65.52.100.92",
    "65.52.100.93",
    "65.52.100.94",
    "65.52.161.64",
    "65.55.29.238",
    "65.55.44.51",
    "65.55.44.54",
    "65.55.44.108",
    "65.55.44.109",
    "65.55.83.120",
    "65.55.113.11",
    "65.55.113.12",
    "65.55.113.13",
    "65.55.176.90",
    "65.55.252.43",
    "65.55.252.63",
    "65.55.252.70",
    "65.55.252.71",
    "65.55.252.72",
    "65.55.252.93",
    "65.55.252.190",
    "65.55.252.202",
    "66.119.147.131",
    "104.26.8.156",
    "104.26.9.156",
    "104.41.207.73",
    "104.43.137.66",
    "104.43.139.21",
    "104.43.140.223",
    "104.43.228.53",
    "104.43.228.202",
    "104.43.237.169",
    "104.45.11.195",
    "104.45.214.112",
    "104.46.1.211",
    "104.46.38.64",
    "104.210.4.77",
    "104.210.40.87",
    "104.210.212.243",
    "104.214.35.244",
    "104.214.78.152",
    "131.253.6.87",
    "131.253.6.103",
    "131.253.40.37",
    "134.170.30.202",
    "134.170.30.203",
    "134.170.30.204",
    "134.170.30.221",
    "134.170.52.151",
    "134.170.235.16",
    "137.116.81.24",
    "157.56.74.250",
    "157.56.91.77",
    "157.56.106.184",
    "157.56.106.185",
    "157.56.106.189",
    "157.56.113.217",
    "157.56.121.89",
    "157.56.124.87",
    "157.56.149.250",
    "157.56.194.72",
    "157.56.194.73",
    "157.56.194.74",
    "168.61.24.141",
    "168.61.146.25",
    "168.61.149.17",
    "168.61.172.71",
    "168.62.187.13",
    "168.63.100.61",
    "168.63.108.233",
    "172.67.71.187",
    "184.86.53.99",
    "191.236.155.80",
    "191.237.218.239",
    "191.239.50.18",
    "191.239.50.77",
    "191.239.52.100",
    "191.239.54.52",
    "204.79.197.200",
    "207.68.166.254",
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

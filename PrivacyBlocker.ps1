# function to add telemetry domains to the hosts file
function Add-DomainsToHostsFile {
    param (
        [string]$hostsFilePath,
        [string[]]$domains,
        [string]$comment = "x.com/oqullcn"
    )

    # define the hosts file encoding
    $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8

    # define the blocking entries for both IPv4 and IPv6
    $blockingHostsEntries = @(
        @{ AddressType = "IPv4"; IPAddress = '0.0.0.0'; },
        @{ AddressType = "IPv6"; IPAddress = '::1'; }
    )

    try {
        $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop
    } catch {
        Write-Error "Failed to check hosts file existence. Error: $_"
        exit 1
    }

    if (-Not $isHostsFilePresent) {
        Write-Output "Creating a new hosts file at $hostsFilePath."
        try {
            New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null
            Write-Output "Successfully created the hosts file."
        } catch {
            Write-Error "Failed to create the hosts file. Error: $_"
            exit 1
        }
    }

    foreach ($domain in $domains) {
        foreach ($blockingEntry in $blockingHostsEntries) {
            Write-Output "Processing addition for $($blockingEntry.AddressType) entry for domain $domain."
            try {
                $hostsFileContents = Get-Content -Path $hostsFilePath -Raw -Encoding $hostsFileEncoding -ErrorAction Stop
            } catch {
                Write-Error "Failed to read the hosts file. Error: $_"
                continue
            }

            $hostsEntryLine = "$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"

            if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) {
                Write-Output "Skipping, entry already exists for domain $domain."
                continue
            }

            try {
                Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop
                Write-Output "Successfully added the entry for domain $domain."
            } catch {
                Write-Error "Failed to add the entry for domain $domain. Error: $_"
                continue
            }
        }
    }
}

# function to block telemetry IPs via Windows Firewall
function Block-TelemetryIPs {
    param (
        [string[]]$ips
    )

    # remove any existing rule with the same name to avoid duplicates
    Remove-NetFirewallRule -DisplayName "PrivacyBlocker" -ErrorAction SilentlyContinue

    # create a new firewall rule to block the provided IP addresses
    New-NetFirewallRule -DisplayName "PrivacyBlocker" -Direction Outbound -Action Block -RemoteAddress ([string[]]$ips)
}

# define the hosts file path
$hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

$domains = @(

    # Activity
    "activity.windows.com",
    "activity-consumer.trafficmanager.net",

    # Windows Crash Report
    "telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "blobcollector.events.data.trafficmanager.net",
    "onedsblobprdwus16.westus.cloudapp.azure.com",
    "oca.microsoft.com",
    "legacywatson.trafficmanager.net",
    "onedsblobprdcus07.centralus.cloudapp.azure.com",
    "kmwatsonc.events.data.microsoft.com",
    "onedsblobprdcus16.centralus.cloudapp.azure.com",

    # Windows Error Reporting
    "watson.microsoft.com",
    "legacywatson.trafficmanager.net",
    "onedsblobprdcus07.centralus.cloudapp.azure.com",
    "watson.telemetry.microsoft.com",
    "onedsblobprdeus17.eastus.cloudapp.azure.com",
    "umwatsonc.events.data.microsoft.com",
    "onedsblobprdeus15.eastus.cloudapp.azure.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "blob.dsm11prdstr10c.store.core.windows.net",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
    "blob.lvl01prdstr03a.store.core.windows.net",
    "co4.telecommand.telemetry.microsoft.com",
    "cs11.wpc.v0cdn.net",
    "cs1137.wpc.gammacdn.net",
    "wpc.gammacdn.net",
    "ns1.gammacdn.net",
    "modern.watson.data.microsoft.com",

    # Telemetry and User Experience
    "functional.events.data.microsoft.com",
    "global.asimov.events.data.trafficmanager.net",
    "onedscolprdcus14.centralus.cloudapp.azure.com",
    "browser.events.data.msn.com",
    "self.events.data.microsoft.com",
    "self-events-data.trafficmanager.net",
    "onedscolprdwus12.westus.cloudapp.azure.com",
    "v10.events.data.microsoft.com",
    "win-global-asimov-leafs-events-data.trafficmanager.net"
    "onedscolprdeus02.eastus.cloudapp.azure.com"
    "v10c.events.data.microsoft.com",
    "onedscolprdweu14.westeurope.cloudapp.azure.com",
    "us-v10c.events.data.microsoft.com",
    "us.events.data.trafficmanager.net",
    "onedscolprdeus21.eastus.cloudapp.azure.com",
    "eu-v10c.events.data.microsoft.com",
    "v10-win.vortex.data.trafficmanager.net",
    "onedscolprdcus20.centralus.cloudapp.azure.com",
    "eu.events.data.trafficmanager.net",
    "v10.vortex-win.data.microsoft.com",
    "onedscolprdweu12.westeurope.cloudapp.azure.com",
    "vortex-win.data.microsoft.com",
    "asimov-win.vortex.data.trafficmanager.net",
    "onedscolprdcus03.centralus.cloudapp.azure.com"
    "telecommand.telemetry.microsoft.com",
    "telecommand.azurewebsites.net",
    "waws-prod-usw3-011-3570.westus3.cloudapp.azure.com",
    "waws-prod-usw3-011.sip.azurewebsites.windows.net",
    "www.telecommandsvc.microsoft.com",
    "telecommand.azurewebsites.net",
    "watson.events.data.microsoft.com",
    "blobcollectorcommon.trafficmanager.net",
    "onedsblobprdwus15.westus.cloudapp.azure.com",
    "umwatson.events.data.microsoft.com",
    "onedsblobprdeus16.eastus.cloudapp.azure.com",
    "watsonc.events.data.microsoft.com",
    "eu-watsonc.events.data.microsoft.com",
    "eu.blobcollector.events.data.trafficmanager.net",
    "onedsblobprdweu08.westeurope.cloudapp.azure.com",
    "v20.events.data.microsoft.com",
    "onedscolprdwus19.westus.cloudapp.azure.com",

    # Spotlight Ads and Suggestions
    "arc.msn.com",
    "arc.trafficmanager.net",
    "iris-de-prod-azsc-v2-wus2.westus2.cloudapp.azure.com",
    "ris.api.iris.microsoft.com",
    "ris-prod.trafficmanager.net",
    "asf-ris-prod-scus-azsc.southcentralus.cloudapp.azure.com",
    "api.msn.com",
    "api-msn-com.a-0003.a-msedge.net",
    "a-0003.a-msedge.net",
    "assets.msn.com",
    "assets.msn.com.edgekey.net",
    "e28578.d.akamaiedge.net",
    "c.msn.com",
    "c-msn-com-nsatc.trafficmanager.net",
    "g.msn.com",
    "g-msn-com-nsatc.trafficmanager.net",
    "ntp.msn.com",
    "www-msn-com.a-0003.a-msedge.net",
    "srtb.msn.com",
    "www.msn.com",
    "fd.api.iris.microsoft.com",
    "staticview.msn.com",
    "mucp.api.account.microsoft.com",
    "query.prod.cms.rt.microsoft.com",

    # Remote Configuration Sync
    "settings-win.data.microsoft.com",
    "atm-settingsfe-prod-geo2.trafficmanager.net",
    "settings-prod-wus2-2.westus2.cloudapp.azure.com",
    "settings.data.microsoft.com",
    "settings-prod-ause-1.australiaeast.cloudapp.azure.com",

    # location Data Sharing
    "inference.location.live.net",
    "location-inference-westus.cloudapp.net",

    # Maps Data and Updates
    "maps.windows.com",
    "dev.virtualearth.net",
    "ecn.dev.virtualearth.net",
    "ecn-us.dev.virtualearth.net",
    "weathermapdata.blob.core.windows.net",

    # Edge
    "config.edge.skype.com",

    # Dropbox Telemetry
    "telemetry.dropbox.com",
    "telemetry.v.dropbox.com",

    # Cortana and Live Tiles
    "r.bing.com",
    "ssl.bing.com",
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
    "prod-azurecdn-akamai-iris.azureedge.net",
    "widgetcdn.azureedge.net",
    "widgetservice.azurefd.net",
    "fp-vs.azureedge.net",
    "ln-ring.msedge.net",
    "t-ring.msedge.net",
    "t-ring-fdv2.msedge.net",
    "tse1.mm.bing.net",

    # Google
    "id.google.com",
    "jnn-pa.googleapis.com",
    "pagead2.googlesyndication.com",
    "fundingchoicesmessages.google.com",
    "contributor.google.com",
    "www.googletagmanager.com",
    "securepubads.g.doubleclick.net",
    "pubads.g.doubleclick.net",
    "imasdk.googleapis.com",
    "tpc.googlesyndication.com",
    "www.google-analytics.com",

    # Firefox
    "incoming.telemetry.mozilla.org",
    "telemetry-incoming.r53-2.services.mozilla.com",
    "crash-stats.mozilla.com",
    "crash-reports.mozilla.com",
    "socorro-webapp.services.mozilla.com",
    "socorro-collector.services.mozilla.com",
    "contile.services.mozilla.com",
    "telemetry.mozilla.org",
    "events.mozilla.org",
    "detection.telemetry.mozilla.org",
    "services.mozilla.com",
    "snippets.mozilla.com",
    "snippets-prod.moz.works",
    "snippets-prod.frankfurt.moz.works",
    "beacon.mozilla.org",

    # Visual Studio and VSCode
    "vortex.data.microsoft.com",
    "dc.services.visualstudio.com",
    "visualstudio-devdiv-c2s.msedge.net",
    "az667904.vo.msecnd.net",
    "scus-breeziest-in.cloudapp.net",
    "nw-umwatson.events.data.microsoft.com",
    "mobile.events.data.microsoft.com",

    # Minecraft Servers | recently suffered a data leak.
    "craftrise.com",
    "craftrise.com.tr",

    # Extra
    "browser.pipe.aria.microsoft.com",
    "onedscolprdcus13.centralus.cloudapp.azure.com",
    "dmd.metaservices.microsoft.com",
    "devicemetadataservice.prod.trafficmanager.net",
    "vmss-prod-wus.westus.cloudapp.azure.com",
    "teams.events.data.microsoft.com",
    "teams-events-data.trafficmanager.net",
    "onedscolprdgwc00.germanywestcentral.cloudapp.azure.com",
    "browser.events.data.microsoft.com",
    "browser.events.data.trafficmanager.net",
    "onedscolprdwus00.westus.cloudapp.azure.com",
    "outlookads.live.com"

)

$ips = @(
    
# next update
    
)

# add domains to the hosts file
Add-DomainsToHostsFile -hostsFilePath $hostsFilePath -domains $domains

# block telemetry IPs via firewall
Block-TelemetryIPs -ips $ips

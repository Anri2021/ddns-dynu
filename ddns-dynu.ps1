[CmdletBinding()]
param (
    [Alias("c", "conf", "config")]
    [string]$SettingsFile
)

$ConfigFile = $SettingsFile

function Test-ValidIPAddress {
    param (
        [string]$Address,
        [System.Net.Sockets.AddressFamily]$AddressFamily
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $false
    }

    $parsedAddress = $null

    return (
        [System.Net.IPAddress]::TryParse(
            $Address.Trim(),
            [ref]$parsedAddress
        ) -and
        $parsedAddress.AddressFamily -eq $AddressFamily
    )
}

function Test-PreservedFields {
    param (
        [Parameter(Mandatory)]
        $Before,

        [Parameter(Mandatory)]
        $After,

        [Parameter(Mandatory)]
        [string[]]$Fields,

        [Parameter(Mandatory)]
        [string]$ObjectName
    )

    foreach ($field in $Fields) {
        $beforeValue = $Before.$field | ConvertTo-Json -Compress
        $afterValue  = $After.$field  | ConvertTo-Json -Compress

        if ($beforeValue -cne $afterValue) {
            Write-Error (
                "Dynu Safety Error: '$field' changed unexpectedly for " +
                "'$ObjectName'. Before: $beforeValue; After: $afterValue"
            )
        }
    }
}

while ($true) {
    $intervalSeconds = 300

    try {
        if (-not $ConfigFile) {
            $ConfigFile = Join-Path $PSScriptRoot "ddns-dynu.conf"
        }

        if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
            throw "Config file not found at: $ConfigFile"
        }

        $Config = Get-Content -LiteralPath $ConfigFile -Raw |
            ConvertFrom-Json -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace([string]$Config.ApiKey)) {
            throw "Dynu Config Error [Field: ApiKey]: Value is missing."
        }

        if ([string]::IsNullOrWhiteSpace([string]$Config.DnsId)) {
            throw "Dynu Config Error [Field: DnsId]: Value is missing."
        }

        if ([string]::IsNullOrWhiteSpace([string]$Config.BaseDomain)) {
            throw "Dynu Config Error [Field: BaseDomain]: Value is missing."
        }

        if ($null -ne $Config.IntervalSeconds) {
            $configuredInterval = 0

            if (
                -not [int]::TryParse(
                    [string]$Config.IntervalSeconds,
                    [ref]$configuredInterval
                ) -or
                $configuredInterval -lt 30
            ) {
                throw (
                    "Dynu Config Error [Field: IntervalSeconds]: " +
                    "Value must be an integer of at least 30 seconds."
                )
            }

            $intervalSeconds = $configuredInterval
        }

        $headers = @{
            "API-Key"     = [string]$Config.ApiKey
            "Accept"      = "application/json"
            "Content-Type" = "application/json"
        }

        $dnsId      = [string]$Config.DnsId
        $baseDomain = ([string]$Config.BaseDomain).Trim()
        $subdomains = @($Config.Subdomains)

        if ($subdomains.Count -eq 0) {
            throw "Dynu Config Error [Field: Subdomains]: No records configured."
        }

        # אימות סוגי הרשומות ומניעת רשומות כפולות בקובץ ההגדרות.
        $seenRecords = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        $plannedRecords = @(
            foreach ($record in $subdomains) {
                $type = ([string]$record.Type).Trim().ToUpperInvariant()
                $node = if ($null -eq $record.Node) {
                    ""
                }
                else {
                    ([string]$record.Node).Trim()
                }

                if ($type -notin @("A", "AAAA")) {
                    throw (
                        "Dynu Config Error [Field: Subdomains.Type]: " +
                        "Unsupported record type '$type'. Only A and AAAA are allowed."
                    )
                }

                $recordKey = "$node|$type"

                if (-not $seenRecords.Add($recordKey)) {
                    $duplicateName = if ([string]::IsNullOrWhiteSpace($node)) {
                        $baseDomain
                    }
                    else {
                        "$node.$baseDomain"
                    }

                    throw (
                        "Dynu Config Error [Field: Subdomains]: " +
                        "Duplicate record '$duplicateName' ($type)."
                    )
                }

                [PSCustomObject]@{
                    Node = $node
                    Type = $type
                }
            }
        )

        # שליפת מצב נוכחי מ-Dynu.
        try {
            $rootInfo = Invoke-RestMethod `
                -Method Get `
                -Uri "https://api.dynu.com/v2/dns/$dnsId" `
                -Headers $headers `
                -ErrorAction Stop

            $recordsResult = Invoke-RestMethod `
                -Method Get `
                -Uri "https://api.dynu.com/v2/dns/$dnsId/record" `
                -Headers $headers `
                -ErrorAction Stop

            $dynuRecords = @($recordsResult.dnsRecords)
        }
        catch {
            $statusCode = 0

            if ($null -ne $_.Exception.Response) {
                try {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                catch {
                    $statusCode = 0
                }
            }

            if ($statusCode -in @(401, 403)) {
                throw (
                    "Dynu Auth Error (HTTP $statusCode) [Field: ApiKey]: " +
                    "Invalid API key."
                )
            }

            if ($statusCode -in @(404, 501)) {
                throw (
                    "Dynu Config Error (HTTP $statusCode) [Field: DnsId]: " +
                    "Invalid DnsId '$dnsId'."
                )
            }

            throw "Dynu API Error: $($_.Exception.Message)"
        }

        $requiresIPv4 = $plannedRecords.Type -contains "A"
        $requiresIPv6 = $plannedRecords.Type -contains "AAAA"

        $ip4 = $null
        $ip6 = $null

        # איתור IPv4 ציבורי.
        if ($requiresIPv4) {
            $ip4 = Resolve-DnsName `
                -Name "myip.opendns.com" `
                -Server "208.67.222.222" `
                -Type A `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress } |
                Select-Object -ExpandProperty IPAddress -First 1

            if (-not $ip4) {
                try {
                    $ip4 = Invoke-RestMethod `
                        -Uri "https://api.ipify.org" `
                        -TimeoutSec 5 `
                        -ErrorAction Stop
                }
                catch {
                    Write-Warning (
                        "IPv4 discovery failed: $($_.Exception.Message)"
                    )
                }
            }

            if ($ip4) {
                $ip4 = ([string]$ip4).Trim()
            }

            if (
                -not (Test-ValidIPAddress `
                    -Address $ip4 `
                    -AddressFamily InterNetwork)
            ) {
                Write-Warning "No valid public IPv4 address was detected."
                $ip4 = $null
            }
        }

        # איתור כתובת IPv6 יציבה המבוססת EUI-64.
        if ($requiresIPv6) {
            try {
                $ifIndex = Get-NetRoute `
                    -DestinationPrefix "::/0" `
                    -AddressFamily IPv6 `
                    -ErrorAction Stop |
                    Sort-Object RouteMetric, InterfaceMetric |
                    Select-Object -ExpandProperty InterfaceIndex -First 1

                if ($null -eq $ifIndex) {
                    throw "No active IPv6 default route was found."
                }

                $adapter = Get-NetAdapter `
                    -InterfaceIndex $ifIndex `
                    -ErrorAction Stop

                $macParts = @(
                    $adapter.MacAddress -split "[:-]" |
                    Where-Object { $_ }
                )

                if ($macParts.Count -ne 6) {
                    throw (
                        "Adapter '$($adapter.Name)' does not expose a valid " +
                        "six-byte MAC address."
                    )
                }

                [byte[]]$macBytes = $macParts |
                    ForEach-Object {
                        [Convert]::ToByte($_, 16)
                    }

                $macBytes[0] = $macBytes[0] -bxor 0x02

                $eui64Suffix = (
                    "{0:x2}{1:x2}:{2:x2}ff:fe{3:x2}:{4:x2}{5:x2}" -f
                    $macBytes[0],
                    $macBytes[1],
                    $macBytes[2],
                    $macBytes[3],
                    $macBytes[4],
                    $macBytes[5]
                )

                $ip6 = Get-NetIPAddress `
                    -InterfaceIndex $ifIndex `
                    -AddressFamily IPv6 `
                    -AddressState Preferred `
                    -ErrorAction Stop |
                    Where-Object {
                        -not $_.SkipAsSource -and
                        $_.IPAddress -like "[23]*:$eui64Suffix"
                    } |
                    Select-Object -ExpandProperty IPAddress -First 1

                if (
                    -not (Test-ValidIPAddress `
                        -Address $ip6 `
                        -AddressFamily InterNetworkV6)
                ) {
                    Write-Warning (
                        "No preferred global EUI-64 IPv6 address was detected."
                    )

                    $ip6 = $null
                }
            }
            catch {
                Write-Warning "IPv6 discovery failed: $($_.Exception.Message)"
                $ip6 = $null
            }
        }

        $rootAConfigured = @(
            $plannedRecords |
            Where-Object {
                [string]::IsNullOrWhiteSpace($_.Node) -and
                $_.Type -eq "A"
            }
        ).Count -gt 0

        $rootAAAAConfigured = @(
            $plannedRecords |
            Where-Object {
                [string]::IsNullOrWhiteSpace($_.Node) -and
                $_.Type -eq "AAAA"
            }
        ).Count -gt 0

        # עדכון אטומי יחיד של כתובות ה-Root.
        $rootUpdateRequired = (
            $rootAConfigured -and
            $ip4 -and
            $rootInfo.ipv4Address -ne $ip4
        ) -or (
            $rootAAAAConfigured -and
            $ip6 -and
            $rootInfo.ipv6Address -ne $ip6
        )

        if ($rootUpdateRequired) {
            try {
                # קריאה חוזרת מיד לפני הכתיבה מצמצמת דריסת שינויים חיצוניים.
                $freshRoot = Invoke-RestMethod `
                    -Method Get `
                    -Uri "https://api.dynu.com/v2/dns/$dnsId" `
                    -Headers $headers `
                    -ErrorAction Stop

                $rootBody = [ordered]@{
                    name              = $freshRoot.name
                    group             = $freshRoot.group
                    ipv4Address       = $freshRoot.ipv4Address
                    ipv6Address       = $freshRoot.ipv6Address
                    ttl               = $freshRoot.ttl
                    ipv4              = $freshRoot.ipv4
                    ipv6              = $freshRoot.ipv6
                    ipv4WildcardAlias = $freshRoot.ipv4WildcardAlias
                    ipv6WildcardAlias = $freshRoot.ipv6WildcardAlias
                    allowZoneTransfer = $freshRoot.allowZoneTransfer
                    dnssec            = $freshRoot.dnssec
                }

                $changedRootTypes = [System.Collections.Generic.List[string]]::new()

                if (
                    $rootAConfigured -and
                    $ip4 -and
                    $freshRoot.ipv4Address -ne $ip4
                ) {
                    $rootBody.ipv4Address = $ip4
                    $changedRootTypes.Add("A")
                }

                if (
                    $rootAAAAConfigured -and
                    $ip6 -and
                    $freshRoot.ipv6Address -ne $ip6
                ) {
                    $rootBody.ipv6Address = $ip6
                    $changedRootTypes.Add("AAAA")
                }

                if ($changedRootTypes.Count -gt 0) {
                    Invoke-RestMethod `
                        -Method Post `
                        -Uri "https://api.dynu.com/v2/dns/$dnsId" `
                        -Headers $headers `
                        -Body ($rootBody | ConvertTo-Json -Depth 5 -Compress) `
                        -ErrorAction Stop |
                        Out-Null

                    # אימות שלא נדרסו הגדרות לאחר הכתיבה.
                    $verifiedRoot = Invoke-RestMethod `
                        -Method Get `
                        -Uri "https://api.dynu.com/v2/dns/$dnsId" `
                        -Headers $headers `
                        -ErrorAction Stop

                    Test-PreservedFields `
                        -Before $freshRoot `
                        -After $verifiedRoot `
                        -Fields @(
                            "group",
                            "ttl",
                            "ipv4",
                            "ipv6",
                            "ipv4WildcardAlias",
                            "ipv6WildcardAlias",
                            "allowZoneTransfer",
                            "dnssec"
                        ) `
                        -ObjectName $baseDomain

                    if (
                        $changedRootTypes.Contains("A") -and
                        $verifiedRoot.ipv4Address -ne $ip4
                    ) {
                        Write-Error (
                            "Dynu Verification Error: Root IPv4 was not " +
                            "updated to '$ip4'."
                        )
                    }

                    if (
                        $changedRootTypes.Contains("AAAA") -and
                        $verifiedRoot.ipv6Address -ne $ip6
                    ) {
                        Write-Error (
                            "Dynu Verification Error: Root IPv6 was not " +
                            "updated to '$ip6'."
                        )
                    }

                    Write-Host (
                        "Dynu DDNS: Updated $baseDomain " +
                        "($($changedRootTypes -join ', ')) via REST API"
                    ) -ForegroundColor Green

                    $rootInfo = $verifiedRoot
                }
            }
            catch {
                Write-Error (
                    "Dynu DDNS Error: Failed updating root domain " +
                    "'$baseDomain': $($_.Exception.Message)"
                )
            }
        }

        # עדכון רשומות המשנה.
        foreach ($record in $plannedRecords) {
            if ([string]::IsNullOrWhiteSpace($record.Node)) {
                continue
            }

            $targetIP = if ($record.Type -eq "A") {
                $ip4
            }
            else {
                $ip6
            }

            $fqdn = "$($record.Node).$baseDomain"

            if (-not $targetIP) {
                Write-Warning (
                    "Dynu DDNS: Skipping $fqdn ($($record.Type)); " +
                    "no valid target address is available."
                )

                continue
            }

            $listedRecord = $dynuRecords |
                Where-Object {
                    $_.nodeName -eq $record.Node -and
                    $_.recordType -eq $record.Type
                } |
                Select-Object -First 1

            if (-not $listedRecord) {
                Write-Warning (
                    "Dynu Config Warning: Subdomain '$fqdn' " +
                    "($($record.Type)) was not found in Dynu."
                )

                continue
            }

            $ipField = if ($record.Type -eq "A") {
                "ipv4Address"
            }
            else {
                "ipv6Address"
            }

            if ($listedRecord.$ipField -eq $targetIP) {
                continue
            }

            try {
                # קבלת המצב העדכני של הרשומה מיד לפני הכתיבה.
                $freshRecord = Invoke-RestMethod `
                    -Method Get `
                    -Uri (
                        "https://api.dynu.com/v2/dns/$dnsId/record/" +
                        $listedRecord.id
                    ) `
                    -Headers $headers `
                    -ErrorAction Stop

                if ($freshRecord.$ipField -eq $targetIP) {
                    continue
                }

                $recordBody = [ordered]@{
                    nodeName   = $freshRecord.nodeName
                    recordType = $freshRecord.recordType
                    ttl        = $freshRecord.ttl
                    state      = $freshRecord.state
                    group      = $freshRecord.group
                    $ipField   = $targetIP
                }

                Invoke-RestMethod `
                    -Method Post `
                    -Uri (
                        "https://api.dynu.com/v2/dns/$dnsId/record/" +
                        $freshRecord.id
                    ) `
                    -Headers $headers `
                    -Body ($recordBody | ConvertTo-Json -Depth 5 -Compress) `
                    -ErrorAction Stop |
                    Out-Null

                # אימות הכתובת וההגדרות שנדרשו להישמר.
                $verifiedRecord = Invoke-RestMethod `
                    -Method Get `
                    -Uri (
                        "https://api.dynu.com/v2/dns/$dnsId/record/" +
                        $freshRecord.id
                    ) `
                    -Headers $headers `
                    -ErrorAction Stop

                Test-PreservedFields `
                    -Before $freshRecord `
                    -After $verifiedRecord `
                    -Fields @("nodeName", "recordType", "ttl", "state", "group") `
                    -ObjectName $fqdn

                if ($verifiedRecord.$ipField -ne $targetIP) {
                    Write-Error (
                        "Dynu Verification Error: '$fqdn' " +
                        "($($record.Type)) was not updated to '$targetIP'."
                    )

                    continue
                }

                Write-Host (
                    "Dynu DDNS: Updated $fqdn " +
                    "($($record.Type)) -> $targetIP via REST API"
                ) -ForegroundColor Green
            }
            catch {
                Write-Error (
                    "Dynu DDNS Error: Failed updating '$fqdn' " +
                    "($($record.Type)): $($_.Exception.Message)"
                )
            }
        }
    }
    catch {
        Write-Error $_
    }

    Start-Sleep -Seconds $intervalSeconds
}

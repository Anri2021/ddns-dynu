[CmdletBinding()]
param (
	[Alias("c", "conf", "config")]
    [string]$SettingsFile
)

$ConfigFile = $SettingsFile

while ($true) {
	$intervalSeconds = 300

    try {
		if (-not $ConfigFile) {
    		$ConfigFile = Join-Path $PSScriptRoot "ddns-dynu.conf"
		}
		if (-not (Test-Path $ConfigFile)) {
			throw "Config file not found at: $ConfigFile"
		}
		$Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
		
		$headers    = @{ "API-Key" = $Config.ApiKey; "Content-Type" = "application/json" }
		$dnsId      = $Config.DnsId
		$baseDomain = $Config.BaseDomain
		$subdomains = $Config.Subdomains
		$intervalSeconds = $Config.IntervalSeconds

		# 1. שליפת נתוני הדומיין והרשומות (מאמת במכה אחת את ה-ApiKey וה-DnsId)
		$rootInfo = $null
		$dynuRecords = $null
		try {
			$rootInfo    = Invoke-RestMethod "https://api.dynu.com/v2/dns/$dnsId" -Headers $headers -ErrorAction Stop
			$apiResult   = Invoke-RestMethod "https://api.dynu.com/v2/dns/$dnsId/record" -Headers $headers -ErrorAction Stop
			$dynuRecords = @($apiResult.dnsRecords)
		}
		catch {
			$code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
			if ($code -in @(401, 403)) {
				throw "Dynu Auth Error (HTTP $code) [Field: ApiKey]: Invalid API Key. Check 'ApiKey' in config."
			}
			elseif ($code -in @(404, 501)) {
				throw "Dynu Config Error (HTTP $code) [Field: DnsId]: Invalid DnsId '$dnsId'. Check 'DnsId' in config."
			}
			else {
				Write-Warning "Dynu Network Issue: $($_.Exception.Message). Retrying in $intervalSeconds seconds..."
				Start-Sleep -Seconds $intervalSeconds
				continue
			}
		}
		
		# 2. רק אם ה-API אומת בהצלחה - תשאול מתאמי הרשת וכתובות ה-IP
		$ifIndex = (Get-NetRoute -DestinationPrefix '::/0' -AddressFamily IPv6 -ErrorAction SilentlyContinue | 
					Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -First 1)
		$macBytes = (Get-NetAdapter -InterfaceIndex $ifIndex).MacAddress -split '[:-]' | ForEach-Object { [Convert]::ToByte($_, 16) }
		$macBytes[0] = $macBytes[0] -bxor 0x02
		$eui64Suffix = "{0:x2}{1:x2}:{2:x2}ff:fe{3:x2}:{4:x2}{5:x2}" -f $macBytes[0], $macBytes[1], $macBytes[2], $macBytes[3], $macBytes[4], $macBytes[5]

		$ip6 = (Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv6 -AddressState Preferred -ErrorAction SilentlyContinue | 
				Where-Object { $_.IPAddress -like "[23]*:$eui64Suffix" } | 
				Select-Object -ExpandProperty IPAddress -First 1)

		$ip4 = (Resolve-DnsName myip.opendns.com -Server 208.67.222.222 -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -First 1)
		if (-not $ip4) { $ip4 = (Invoke-RestMethod "https://api.ipify.org" -TimeoutSec 3 -ErrorAction SilentlyContinue) }

		
		foreach ($rec in $subdomains) {
			$ipField  = if ($rec.Type -eq 'A') { 'ipv4Address' } else { 'ipv6Address' }
			$targetIP = if ($rec.Type -eq 'A') { $ip4 } else { $ip6 }
			if (-not $targetIP) { continue }

			$isRoot = [string]::IsNullOrWhiteSpace($rec.Node)
			$fqdn   = if ($isRoot) { $baseDomain } else { "$($rec.Node).$baseDomain" }

			# הכנת כתובת היעד והגוף (הפרדה מינימלית בלבד)
			if ($isRoot) {
				$currentValue = $rootInfo.$ipField
				$targetUri    = "https://api.dynu.com/v2/dns/$dnsId"
				$body         = @{ name = $baseDomain; $ipField = $targetIP }
			} else {
				$live = $dynuRecords | Where-Object { $_.nodeName -eq $rec.Node -and $_.recordType -eq $rec.Type } | Select-Object -First 1
				if (-not $live) {
					Write-Warning "Dynu Config Warning: Subdomain '$fqdn' ($($rec.Type)) was not found in Dynu DNS records."
					continue
				}
				$currentValue = $live.$ipField
				$targetUri    = "https://api.dynu.com/v2/dns/$dnsId/record/$($live.id)"
				$body         = @{
					nodeName   = $rec.Node
					recordType = $rec.Type
					ttl        = 120
					state      = $true
					$ipField   = $targetIP
				}
				if (-not [string]::IsNullOrWhiteSpace($live.group)) { $body["group"] = $live.group }
			}

			# ביצוע, הגנה מכישלון בודד ודיווח מרוכז
			if ($currentValue -ne $targetIP) {
				try {
					Invoke-RestMethod -Method Post -Uri $targetUri -Headers $headers -Body ($body | ConvertTo-Json) -ErrorAction Stop
					Write-Host "Dynu DDNS: Updated $fqdn ($($rec.Type)) -> $targetIP via REST API" -ForegroundColor Green
				}
				catch {
					Write-Error "Dynu DDNS Error: Failed updating $fqdn ($($rec.Type)): $($_.Exception.Message)"
				}
			}
		}
	}
    catch {
        Write-Error $_
    }

    # השהיה של 5 דקות בין בדיקה לבדיקה:
    Start-Sleep -Seconds $intervalSeconds
}


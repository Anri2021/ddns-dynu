while ($true) {
    try {
		$ConfigFile = Join-Path $PSScriptRoot "ddns.conf"
		if (-not (Test-Path $ConfigFile)) {
			throw "Config file not found at: $ConfigFile"
		}
		$Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
		
		$headers    = @{ "API-Key" = $Config.ApiKey; "Content-Type" = "application/json" }
		$username = $Config.Username
		$password = $Config.Password
		$dnsId      = $Config.DnsId
		$baseDomain = $Config.BaseDomain
		$subdomains = $Config.Subdomains
		$intervalSeconds = $Config.IntervalSeconds
		
		
		$ifIndex = (Get-NetRoute -DestinationPrefix '::/0' -AddressFamily IPv6 -ErrorAction SilentlyContinue | 
					Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -First 1)
		# חישוב סיומת ה-64 ביט הקבועה (EUI-64) ישירות מכתובת ה-MAC של הכרטיס
		$macBytes = (Get-NetAdapter -InterfaceIndex $ifIndex).MacAddress -split '[:-]' | ForEach-Object { [Convert]::ToByte($_, 16) }
		$macBytes[0] = $macBytes[0] -bxor 0x02
		$eui64Suffix = "{0:x2}{1:x2}:{2:x2}ff:fe{3:x2}:{4:x2}{5:x2}" -f $macBytes[0], $macBytes[1], $macBytes[2], $macBytes[3], $macBytes[4], $macBytes[5]
		
		# שליפת כתובת ה-GUA של סלקום: מתחילה ב-2 ומסתיימת בסיומת החומרה המדויקת שלך
		$ip6 = (Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv6 -AddressState Preferred -ErrorAction SilentlyContinue | 
				Where-Object { $_.IPAddress -like "[23]*:$eui64Suffix" } | 
				Select-Object -ExpandProperty IPAddress -First 1)
		
		$ip4 = (Resolve-DnsName myip.opendns.com -Server 208.67.222.222 -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -First 1)
		if (-not $ip4) { $ip4 = (Invoke-RestMethod "https://api.ipify.org" -TimeoutSec 3 -ErrorAction SilentlyContinue) }

		
		$dynuRecords = @((Invoke-RestMethod "https://api.dynu.com/v2/dns/$DnsId/record" -Headers $headers).dnsRecords)
		
		foreach ($rec in $subdomains) {
			# שיוך אוטומטי של כתובת היעד לפי סוג הרשומה
			$targetIP = if ($rec.Type -eq 'A') { $ip4 } else { $ip6 }
			if (-not $targetIP) { continue }
		
			$fqdn = if ([string]::IsNullOrWhiteSpace($rec.Node)) { $BaseDomain } else { "$($rec.Node).$BaseDomain" }
		
			if ([string]::IsNullOrWhiteSpace($rec.Node)) {
				# עדכון דומיין שורש דרך ממשק ה-DDNS הרגיל
				$currentValue = (Resolve-DnsName $fqdn -Server ns1.dynu.com -Type $rec.Type -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -First 1)
				if ($currentValue -ne $targetIP) {
					$param = if ($rec.Type -eq 'A') { "myip" } else { "myipv6" }
					Invoke-RestMethod "https://api.dynu.com/nic/update?hostname=$fqdn&$param=$targetIP&username=$username&password=$([System.Uri]::EscapeDataString($password))"
				}
			} else {
				# זיהוי דינמי של ה-ID מתוך הרשומות שנטענו לזיכרון
				$live = $dynuRecords | Where-Object { $_.nodeName -eq $rec.Node -and $_.recordType -eq $rec.Type } | Select-Object -First 1
		
				if ($live) {
					$currentValue = if ($rec.Type -eq 'A') { $live.ipv4Address } else { $live.ipv6Address }
		
					if ($currentValue -ne $targetIP) {
						$body = @{ 
							nodeName   = $rec.Node
							recordType = $rec.Type
							ttl        = 120
							state      = $true 
						}
						if (-not [string]::IsNullOrWhiteSpace($live.group)) { $body["group"] = $live.group }
						if ($rec.Type -eq 'A') { $body["ipv4Address"] = $targetIP } else { $body["ipv6Address"] = $targetIP }
		
						Invoke-RestMethod -Method Post -Uri "https://api.dynu.com/v2/dns/$DnsId/record/$($live.id)" -Headers $headers -Body ($body | ConvertTo-Json)
					}
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


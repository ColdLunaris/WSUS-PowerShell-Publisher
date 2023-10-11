[void][reflection.assembly]::LoadWithPartialName(“Microsoft.UpdateServices.Administration”)

# Get digest
Write-Host "Creating digest for update file" -f Green
$filePath = "C:\Users\administrator.LUNARIS\Desktop\Spyder_64bit_full.exe"
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$sha1HashBytes = $sha1.ComputeHash($fileBytes)
$sha256HashBytes = $sha256.ComputeHash($fileBytes)
$sha1Base64 = [System.Convert]::ToBase64String($sha1HashBytes)
$sha256Base64 = [System.Convert]::ToBase64String($sha256HashBytes)

# Create Software Distribution Package and populate information from EXE file
Write-Host "Creating `"Software Distribution Package`"-definition" -f Green
$sdp = New-Object Microsoft.UpdateServices.Administration.SoftwareDistributionPackage
$sdp.PopulatePackageFromExe($filePath)
$sdp.InstallableItems[0].Arguments = "/S"

# Add source file information
Write-Host "Populating source file information" -f Green
$sdp.InstallableItems[0].OriginalSourceFile.FileName = $filePath.Split('\')[-1]
$sdp.InstallableItems[0].OriginalSourceFile.Digest = $sha1Base64
$sdp.InstallableItems[0].OriginalSourceFile.AdditionalDigest = $sha256Base64
$sdp.InstallableItems[0].OriginalSourceFile.Size = Get-Item -Path $filePath | Select-Object -ExpandProperty Length
$sdp.InstallableItems[0].OriginalSourceFile.OriginUri = "https://github.com/spyder-ide/spyder/releases/download/v5.4.5/Spyder_64bit_full.exe"

# Add return codes for successful install reboot required
Write-Host "Adding reboot codes" -f Green
$rc1 = New-Object Microsoft.UpdateServices.Administration.ReturnCode
$rc2 = New-Object Microsoft.UpdateServices.Administration.ReturnCode
$rc1.IsRebootRequired = $true
$rc2.IsRebootRequired = $true
$rc1.ReturnCodeValue = 1641
$rc2.ReturnCodeValue = 3010
$sdp.InstallableItems[0].ReturnCodes.Add($rc1)
$sdp.InstallableItems[0].ReturnCodes.Add($rc2)

# Create detection rules
Write-Host "Creating detection rules" -f Green
$sdp.InstallableItems[0].IsInstallableApplicabilityRule = @'
<bar:RegKeyExists Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spyder" />
'@
$sdp.InstallableItems[0].IsInstalledApplicabilityRule = @'
<bar:RegSzToVersion Key="HKEY_LOCAL_MACHINE" Subkey="SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spyder" Value="DisplayVersion" Comparison="EqualTo" Data="5.4.5.0" />
'@

# Superseed old updates
$sdp.SupersededPackages.Add('b1f0b37c-dcc7-4204-a535-5c1e199896c6')

# Add general information
Write-Host "Adding general information" -f Green
$sdp.Title = "Spyder 5.4.5"
$sdp.Description = "This update contains bug fixes and security updates"
$sdp.VendorName = "Lunaris"
$sdp.DefaultLanguage = "en"
$sdp.SupportUrl = "https://github.com/spyder-ide/spyder/releases/tag/v5.4.5"
$sdp.PackageUpdateType = "Software"
$sdp.PackageType = "Update"
$sdp.SecurityRating = "Moderate"
$sdp.PackageUpdateClassification = "SecurityUpdates"

# Publish package
Write-Host "Saving SDP XML" -f Green
$sdpFilePath = "C:\Users\administrator.LUNARIS\Desktop\$($sdp.Title) $($sdp.PackageId.ToString()).xml"
$sdp.Save($sdpFilePath)
$sourcePath = $filePath.Substring(0, $filePath.LastIndexOf('\'))

Write-Host "Creating connection to WSUS in preparation for publishing" -f Green
[Microsoft.UpdateServices.Administration.IUpdateServer]$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer("LUNSCCM01", $true, 8531)
[Microsoft.UpdateServices.Administration.IPublisher]$publisher = $wsus.GetPublisher($sdpFilePath)

Write-Host "Publishing update. This will take a while..." -f Green
$timer = [System.Diagnostics.Stopwatch]::New()
$timer.Start()
$publisher.PublishPackage($sourcePath, $null)
$timer.Stop()
Write-Host "Update published. It took $($timer.Elapsed.Minutes) minutes and $($timer.Elapsed.Seconds) seconds to finish publishing" -f Green
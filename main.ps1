[void][reflection.assembly]::LoadWithPartialName(“Microsoft.UpdateServices.Administration”)

# Get digest
Write-Host "Creating digest for update file" -f Green
$filePath = "C:\Users\administrator.LUNARIS\Desktop\Spyder IDE\Spyder_64bit_full.exe"
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
$sdp.SupersededPackages.Add('a973c77b-5898-4b0e-b5de-c1239e55fbdc')
$sdp.SupersededPackages.Add('355b38b7-bddc-4e14-96ff-9cbe117d868a')
$sdp.SupersededPackages.Add('989cc724-dbf8-4baa-83a6-918508ff84cb')
$sdp.SupersededPackages.Add('b33e00d1-8855-4b3c-965c-ef84229a9b69')
$sdp.SupersededPackages.Add('9e8ec786-d477-4afb-abc9-7029baae9950')
$sdp.SupersededPackages.Add('71a6557e-aa15-4e1f-b5d6-a5a522d7f343')
$sdp.SupersededPackages.Add('64e45086-11fd-4aaf-abe8-1b05d673255f')
$sdp.SupersededPackages.Add('04408308-1550-4748-a702-df6bccbab06e')

# Add general information
Write-Host "Adding general information" -f Green
$sdp.Title = "Spyder IDE 5.4.5"
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
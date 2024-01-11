###########################
# VARIABLES TO BE DEFINED #
###########################

# WSUS settings
$wsusServer = "LUNSCCM01"
$wsusPort = 8531
$wsusSSL = $true

# Package info
$applicationName = "Spyder IDE"
$applicationVersion = "5.5.0"
$description = "This update contains bug fixes and security updates"
$vendorName = "Lunaris"
$productName = "SCUP Updates"
$defaultLanguage = "en"
$additionalInformation = "https://github.com/spyder-ide/spyder/blob/master/changelogs/Spyder-5.md#version-550-2023-11-08"
$supportUrl = "https://www.spyder-ide.org/"

# Installation info
$filePath = "C:\Script\Executables\Spyder IDE\Deploy-Application.exe"
$installParameters = "Install NonInteractive"
$originUri = "https://github.com/spyder-ide/spyder/releases/download/v5.5.0/Spyder_64bit_full.exe"
$sdpPath = "C:\Script\SDP" # Folder where SDP-file will be saved

# Applicability info
$applicabilityRegistryKey = "HKEY_LOCAL_MACHINE"
$applicabilityRegistrySubKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$applicabilityNameValue = "DisplayName"
$applicabilityNameComparison = "Contains"
$applicabilityNameData = $applicationName.Split(" ")[0]
$applicabilityVersionValue = "DisplayVersion"
$applicabilityVersionComparison = "LessThan"
$applicabilityVersionData = "$applicationVersion.0"

# Detection info
$detectionRegistryKey = "HKEY_LOCAL_MACHINE"
$detectionRegistrySubKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$detectionNameValue = "DisplayName"
$detectionNameComparison = "Contains"
$detectionNameData = $applicationName.Split(" ")[0]
$detectionVersionValue = "DisplayVersion"
$detectionVersionComparison = "GreaterThanOrEqualTo"
$detectionVersionData = "$applicationVersion.0"

###############
# MAIN SCRIPT #
###############
try {
    Write-Host "Connecting to $wsusServer"
    [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
    [Microsoft.UpdateServices.Administration.IUpdateServer]$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($wsusServer, $wsusSSL, $wsusPort)
}
catch {
    Write-Error "Could not connect to $wsusServer`r`n$($_.Exception.Message)"
    throw
}

# Create Software Distribution Package and populate information from EXE file
Write-Host "Creating `"Software Distribution Package`"-definition"
$sdp = [Microsoft.UpdateServices.Administration.SoftwareDistributionPackage]::New()
$sdp.PopulatePackageFromExe($filePath)
$sdp.InstallableItems[0].Arguments = $installParameters

# Add general information
Write-Host "Adding general information"
$sdp.Title = "$applicationName $applicationVersion"
$sdp.Description = $description
$sdp.VendorName = $vendorName
$sdp.ProductNames.Add($productName) | Out-Null
$sdp.DefaultLanguage = $defaultLanguage
$sdp.AdditionalInformationUrls.Add($additionalInformation)
$sdp.SupportUrl = $supportUrl
$sdp.PackageUpdateType = "Software"
$sdp.PackageType = "Update"
$sdp.SecurityRating = "Moderate"
$sdp.PackageUpdateClassification = "SecurityUpdates"

# Get digests
Write-Host "Creating SHA1 and SHA256 digests for source file"
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$sha1 = [System.Security.Cryptography.SHA1CryptoServiceProvider]::New()
$sha1HashBytes = $sha1.ComputeHash($fileBytes)
$sha1Base64 = [System.Convert]::ToBase64String($sha1HashBytes)
$sha256 = [System.Security.Cryptography.SHA256CryptoServiceProvider]::New()
$sha256HashBytes = $sha256.ComputeHash($fileBytes)
$sha256Base64 = [System.Convert]::ToBase64String($sha256HashBytes)

# Add source file information
Write-Host "Populating installable source file information"
$sdp.InstallableItems[0].OriginalSourceFile.FileName = $filePath.Split('\')[-1]
$sdp.InstallableItems[0].OriginalSourceFile.Digest = $sha1Base64
$sdp.InstallableItems[0].OriginalSourceFile.AdditionalDigest = $sha256Base64
$sdp.InstallableItems[0].OriginalSourceFile.Size = Get-Item -Path $filePath | Select-Object -ExpandProperty Length
$sdp.InstallableItems[0].OriginalSourceFile.OriginUri = $originUri

# Add return codes for successful install reboot required
$rc1 = [Microsoft.UpdateServices.Administration.ReturnCode]::New()
$rc2 = [Microsoft.UpdateServices.Administration.ReturnCode]::New()
$rc1.IsRebootRequired = $true
$rc2.IsRebootRequired = $true
$rc1.ReturnCodeValue = 1641
$rc2.ReturnCodeValue = 3010
$sdp.InstallableItems[0].ReturnCodes.Add($rc1)
$sdp.InstallableItems[0].ReturnCodes.Add($rc2)

#region Creation of Applicability rule in XML
# Set up XML Writer. Omit duplicate namespaces
$stringWriter = [System.IO.StringWriter]::New()
$xmlSettings = [System.Xml.XmlWriterSettings]::New()
$xmlSettings.Indent = $true
$xmlSettings.OmitXmlDeclaration = $true
$xmlSettings.NamespaceHandling = [System.Xml.NamespaceHandling]::OmitDuplicates
$xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $xmlSettings)

# Write upper And element
$xmlWriter.WriteStartElement("lar", "And", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/LogicalApplicabilityRules.xsd")

# Write condition for Windows 10 or higher
$xmlWriter.WriteStartElement("bar", "WindowsVersion", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Comparison", "GreaterThanOrEqualTo")
$xmlWriter.WriteAttributeString("MajorVersion", "10")
$xmlWriter.WriteAttributeString("MinorVersion", "0")
$xmlWriter.WriteEndElement()

# Write registry loop element
$xmlWriter.WriteStartElement("bar", "RegKeyLoop", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", $applicabilityRegistryKey)
$xmlWriter.WriteAttributeString("Subkey", $applicabilityRegistrySubKey)
$xmlWriter.WriteAttributeString("TrueIf", "Any")

# Write And element to combine the following registry conditions
$xmlWriter.WriteStartElement("lar", "And", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/LogicalApplicabilityRules.xsd")

# Write registry loop conditions
$xmlWriter.WriteStartElement("bar", "RegSzToVersion", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", $applicabilityVersionValue)
$xmlWriter.WriteAttributeString("Comparison", $applicabilityVersionComparison)
$xmlWriter.WriteAttributeString("Data", $applicabilityVersionData)
$xmlWriter.WriteEndElement()

$xmlWriter.WriteStartElement("bar", "RegSz", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", $applicabilityNameValue)
$xmlWriter.WriteAttributeString("Comparison", $applicabilityNameComparison)
$xmlWriter.WriteAttributeString("Data", $applicabilityNameData)
$xmlWriter.WriteEndElement()

# End And element for registry conditions
$xmlWriter.WriteEndElement()

# End registry loop
$xmlWriter.WriteEndElement()

# End upper And
$xmlWriter.WriteEndElement()

# Write changes to stringWriter
$xmlWriter.Flush()
$xmlWriter.Close()

$isInstallable = $stringWriter.ToString() -replace " xmlns.*", ">" -replace "`"0`">", "`"0`" />"
#endregion

#region Creation of Installed rule in XML
# Set up XML Writer. Omit duplicate namespaces
$stringWriter = [System.IO.StringWriter]::New()
$xmlSettings = [System.Xml.XmlWriterSettings]::New()
$xmlSettings.Indent = $true
$xmlSettings.OmitXmlDeclaration = $true
$xmlSettings.NamespaceHandling = [System.Xml.NamespaceHandling]::OmitDuplicates
$xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $xmlSettings)

# Write registry loop element
$xmlWriter.WriteStartElement("bar", "RegKeyLoop", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", $detectionRegistryKey)
$xmlWriter.WriteAttributeString("Subkey", $detectionRegistrySubKey)
$xmlWriter.WriteAttributeString("TrueIf", "Any")

# Write And element to combine the following registry conditions
$xmlWriter.WriteStartElement("lar", "And", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/LogicalApplicabilityRules.xsd")

# Write registry loop conditions
$xmlWriter.WriteStartElement("bar", "RegSzToVersion", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", $detectionVersionValue)
$xmlWriter.WriteAttributeString("Comparison", $detectionVersionComparison)
$xmlWriter.WriteAttributeString("Data", $detectionVersionData)
$xmlWriter.WriteEndElement()

$xmlWriter.WriteStartElement("bar", "RegSz", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", $detectionNameValue)
$xmlWriter.WriteAttributeString("Comparison", $detectionNameComparison)
$xmlWriter.WriteAttributeString("Data", $detectionNameData)
$xmlWriter.WriteEndElement()

# End And element for registry conditions
$xmlWriter.WriteEndElement()

# End registry loop
$xmlWriter.WriteEndElement()


# Write changes to stringWriter
$xmlWriter.Flush()
$xmlWriter.Close()

$isInstalled = $stringWriter.ToString() -replace " xmlns.*", ">"
#endregion

# Apply XML rules
$sdp.InstallableItems[0].IsInstallableApplicabilityRule = $isInstallable
$sdp.InstallableItems[0].IsInstalledApplicabilityRule = $isInstalled

# Superseed old updates
Write-Host "Checking for old updates. If any are found they will be superseded"
$updates = $wsus.SearchUpdates("Spyder IDE")
if ($updates.Count -ge 1) {
    $updates | ForEach-Object {
        $sdp.SupersededPackages.Add($($_.id.UpdateId.Guid))
    }
}

# Save SoftwareDistributionPackage and prepare for publishing
Write-Host "Saving SDP XML"
$sdpFilePath = "$sdpPath\$($sdp.Title) $($sdp.PackageId.ToString()).xml"
try {
    $sdp.Save($sdpFilePath)
    Write-Host "SDP saved to `"$sdpFilePath`""
}
catch {
    Write-Error "Could not save SDP with the following error message:`r`n$($_.Exception.Message)"
    throw
}
$sourcePath = $filePath.Substring(0, $filePath.LastIndexOf('\'))

Write-Host "Loading SDP into publisher interface"
[Microsoft.UpdateServices.Administration.IPublisher]$publisher = $wsus.GetPublisher($sdpFilePath)

# Create separate runspace to allow for monitoring publisher progress via ProgressHandler event handler
$runspace = [runspacefactory]::CreateRunspace($Host)
$runspace.Open()

# Add publisher and sdp to runspace
$runspace.SessionStateProxy.PSVariable.Set([psvariable]::New('publisher', $publisher))

# Scriptblock that reads the event handler and prints progress
$powershell = [powershell]::Create().AddScript({
    $objectEvent = @{
        InputObject      = $publisher
        EventName        = 'ProgressHandler'
        SourceIdentifier = 'PublisherProgressChanged'
        Action           = {
            # Percentage is calculated per job
            $percentage = [math]::Round($($eventArgs.CurrentProgress / $eventArgs.UpperProgressBound * 100))
            $string = "{0}% - {1}: `"{2}`"" -f $percentage, $eventArgs.ProgressStep, $EventArgs.ProgressInfo

            # Console buffer width is found to keep progress on the same line
            Write-Host -NoNewline ("`r{0,-$([console]::BufferWidth)}" -f $string)

            # Write newline when moving to next step of publishing
            if ($percentage -eq 100) {
                Write-Host
            }
        }
    }
    Register-ObjectEvent @objectEvent
})

# Start runspace
$powershell.Runspace = $runspace
$powershell.BeginInvoke() | Out-Null

# Publish package to WSUS
Write-Host "Publishing update. Depending on the size of the file(s), this might take a while..."
$timer = [System.Diagnostics.Stopwatch]::New()
$timer.Start()
$publisher.PublishPackage($sourcePath, $null)
Start-Sleep -Milliseconds 100 # Allow runspace to finish printing
$timer.Stop()
Write-Host "Update published successfully in $($timer.Elapsed.Minutes) minutes and $($timer.Elapsed.Seconds) seconds"
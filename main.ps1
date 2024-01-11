[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

try {
    Write-Host "Establishing connection to WSUS"
    [Microsoft.UpdateServices.Administration.IUpdateServer]$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer("LUNSCCM01", $true, 8531)
}
catch {
    Write-Error "Could not establish connection to WSUS"
    throw
}

# Get digests
Write-Host "Creating digest for update file"
$filePath = "C:\Script\Executables\Spyder IDE\Deploy-Application.exe"
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$sha1 = [System.Security.Cryptography.SHA1CryptoServiceProvider]::New()
$sha1HashBytes = $sha1.ComputeHash($fileBytes)
$sha1Base64 = [System.Convert]::ToBase64String($sha1HashBytes)
$sha256 = [System.Security.Cryptography.SHA256CryptoServiceProvider]::New()
$sha256HashBytes = $sha256.ComputeHash($fileBytes)
$sha256Base64 = [System.Convert]::ToBase64String($sha256HashBytes)

# Create Software Distribution Package and populate information from EXE file
Write-Host "Creating `"Software Distribution Package`"-definition"
$sdp = [Microsoft.UpdateServices.Administration.SoftwareDistributionPackage]::New()
$sdp.PopulatePackageFromExe($filePath)
$sdp.InstallableItems[0].Arguments = "Install NonInteractive"

# Add source file information
Write-Host "Populating source file information"
$sdp.InstallableItems[0].OriginalSourceFile.FileName = $filePath.Split('\')[-1]
$sdp.InstallableItems[0].OriginalSourceFile.Digest = $sha1Base64
$sdp.InstallableItems[0].OriginalSourceFile.AdditionalDigest = $sha256Base64
$sdp.InstallableItems[0].OriginalSourceFile.Size = Get-Item -Path $filePath | Select-Object -ExpandProperty Length
$sdp.InstallableItems[0].OriginalSourceFile.OriginUri = "https://github.com/spyder-ide/spyder/releases/download/v5.5.0/Spyder_64bit_full.exe"

# Add return codes for successful install reboot required
Write-Host "Adding reboot codes"
$rc1 = [Microsoft.UpdateServices.Administration.ReturnCode]::New()
$rc2 = [Microsoft.UpdateServices.Administration.ReturnCode]::New()
$rc1.IsRebootRequired = $true
$rc2.IsRebootRequired = $true
$rc1.ReturnCodeValue = 1641
$rc2.ReturnCodeValue = 3010
$sdp.InstallableItems[0].ReturnCodes.Add($rc1)
$sdp.InstallableItems[0].ReturnCodes.Add($rc2)

#region Creation of Applicability rule in XML
Write-Host "Setting up XML for IsInstallable"

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
$xmlWriter.WriteAttributeString("Key", "HKEY_LOCAL_MACHINE")
$xmlWriter.WriteAttributeString("Subkey", "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
$xmlWriter.WriteAttributeString("TrueIf", "Any")

# Write And element to combine the following registry conditions
$xmlWriter.WriteStartElement("lar", "And", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/LogicalApplicabilityRules.xsd")

# Write registry loop conditions
$xmlWriter.WriteStartElement("bar", "RegSzToVersion", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", "DisplayVersion")
$xmlWriter.WriteAttributeString("Comparison", "LessThan")
$xmlWriter.WriteAttributeString("Data", "5.5.0.0")
$xmlWriter.WriteEndElement()

$xmlWriter.WriteStartElement("bar", "RegSz", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", "DisplayName")
$xmlWriter.WriteAttributeString("Comparison", "Contains")
$xmlWriter.WriteAttributeString("Data", "Spyder")
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
Write-Host "Setting up XML for IsInstalled"

# Set up XML Writer. Omit duplicate namespaces
$stringWriter = [System.IO.StringWriter]::New()
$xmlSettings = [System.Xml.XmlWriterSettings]::New()
$xmlSettings.Indent = $true
$xmlSettings.OmitXmlDeclaration = $true
$xmlSettings.NamespaceHandling = [System.Xml.NamespaceHandling]::OmitDuplicates
$xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $xmlSettings)

# Write registry loop element
$xmlWriter.WriteStartElement("bar", "RegKeyLoop", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOCAL_MACHINE")
$xmlWriter.WriteAttributeString("Subkey", "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
$xmlWriter.WriteAttributeString("TrueIf", "Any")

# Write And element to combine the following registry conditions
$xmlWriter.WriteStartElement("lar", "And", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/LogicalApplicabilityRules.xsd")

# Write registry loop conditions
$xmlWriter.WriteStartElement("bar", "RegSzToVersion", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", "DisplayVersion")
$xmlWriter.WriteAttributeString("Comparison", "GreaterThanOrEqualTo")
$xmlWriter.WriteAttributeString("Data", "5.5.0.0")
$xmlWriter.WriteEndElement()

$xmlWriter.WriteStartElement("bar", "RegSz", "https://schemas.microsoft.com/wsus/2005/04/CorporatePublishing/BaseApplicabilityRules.xsd")
$xmlWriter.WriteAttributeString("Key", "HKEY_LOOP_TARGET")
$xmlWriter.WriteAttributeString("Subkey", "\")
$xmlWriter.WriteAttributeString("Value", "DisplayName")
$xmlWriter.WriteAttributeString("Comparison", "Contains")
$xmlWriter.WriteAttributeString("Data", "Spyder")
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

# Add general information
Write-Host "Adding general information"
$sdp.Title = "Spyder IDE 5.5.0"
$sdp.Description = "This update contains bug fixes and security updates"
$sdp.VendorName = "Lunaris"
$sdp.ProductNames.Add("SCUP Updates") | Out-Null
$sdp.DefaultLanguage = "en"
$sdp.AdditionalInformationUrls.Add("https://github.com/spyder-ide/spyder/blob/master/changelogs/Spyder-5.md#version-550-2023-11-08")
$sdp.SupportUrl = "https://www.spyder-ide.org/"
$sdp.PackageUpdateType = "Software"
$sdp.PackageType = "Update"
$sdp.SecurityRating = "Moderate"
$sdp.PackageUpdateClassification = "SecurityUpdates"

# Save SoftwareDistributionPackage and prepare for publishing
Write-Host "Saving SDP XML"
$sdpFilePath = "C:\Script\SDP\$($sdp.Title) $($sdp.PackageId.ToString()).xml"
$sdp.Save($sdpFilePath)
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
            $string = "{0}: `"{1}`" - {2}%" -f $eventArgs.ProgressStep, $EventArgs.ProgressInfo, $percentage

            # Console buffer width is found to keep progress on the same line
            Write-Host -NoNewline ("`r{0,-$([console]::BufferWidth)}" -f $string)
        }
    }
    Register-ObjectEvent @objectEvent
})

# Start runspace
$powershell.Runspace = $runspace
$task = $powershell.BeginInvoke()

Write-Host "Publishing update. Depending on the size of the file(s), this might take a while..."
$timer = [System.Diagnostics.Stopwatch]::New()
$timer.Start()
$publisher.PublishPackage($sourcePath, $null)
Start-Sleep -Seconds 1
$timer.Stop()
Write-Host "`r`nUpdate published. It took $($timer.Elapsed.Minutes) minutes and $($timer.Elapsed.Seconds) seconds to finish publishing"
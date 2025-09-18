<#
.SYNOPSIS
    DXBuilder - Create a streamlined, debloated Windows 11 image.

.DESCRIPTION
    This script automates the creation of a minimal, privacy-focused Windows 11 installation.
    Conceptually inspired by "tiny11", but fully rewritten, enhanced, and branded by DeXon.
    Uses only Microsoft-native tools (DISM, etc.). External binaries are minimized (only oscdimg.exe if needed).

.PARAMETER ISO
    Drive letter of the mounted Windows ISO (e.g., E).

.PARAMETER SCRATCH
    Drive letter for temporary workspace (e.g., D).

.PARAMETER InteractiveApps
    If specified, shows an interactive menu to select which apps to remove.

.EXAMPLE
    .\DXBuilder.ps1 -ISO E -SCRATCH D
    .\DXBuilder.ps1 -InteractiveApps

.NOTES
    Author: DeXon
    Date: 2025-07-09
    Version: 1.0
    Inspired by: ntdevlabs/tiny11 (concept only)

#---------[ Parameters ]---------#
param (
    [ValidatePattern('^[c-zC-Z]$')][string]$ISO,
    [ValidatePattern('^[c-zC-Z]$')][string]$SCRATCH,
    [switch]$InteractiveApps
)

#---------[ Initialization & Validation ]---------#
if (-not $SCRATCH) {
    $ScratchDisk = $PSScriptRoot -replace '[\\]+$', ''
} else {
    $ScratchDisk = $SCRATCH + ":"
}

# Ensure log directory exists
$LogPath = "$PSScriptRoot\DXBuilder_$(Get-Date -f yyyyMMdd_HHmmss).log"
Start-Transcript -Path $LogPath -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = "DXBuilder - Windows 11 Streamliner"
Clear-Host
Write-Output "Welcome to DXBuilder! (Concept: tiny11 | Author: DeXon) - Release: 2025-07-09"

#---------[ Functions ]---------#

function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )
    try {
        & 'reg' 'add' $path '/v' $name '/t' $type '/d' $value '/f' | Out-Null
        Write-Output "Set registry value: $path\$name"
    } catch {
        Write-Warning "Error setting registry value: $_"
    }
}

function Remove-RegistryValue {
    param (
        [string]$path
    )
    try {
        & 'reg' 'delete' $path '/f' | Out-Null
        Write-Output "Removed registry value: $path"
    } catch {
        Write-Warning "Error removing registry value: $_"
    }
}

function Invoke-Cleanup {
    param([switch]$ExitWithError)

    Write-Output "Performing Cleanup..."

    # Unmount images if mounted
    if (Test-Path "$ScratchDisk\scratchdir\Windows") {
        Write-Output "Dismounting Windows image..."
        Dismount-WindowsImage -Path "$ScratchDisk\scratchdir" -Discard -ErrorAction SilentlyContinue | Out-Null
    }

    # Unload registry hives
    @('HKLM\zCOMPONENTS', 'HKLM\zDEFAULT', 'HKLM\zNTUSER', 'HKLM\zSOFTWARE', 'HKLM\zSYSTEM') | ForEach-Object {
        if ($_ -ne $null) {
            reg unload $_ 2>&1 | Out-Null
        }
    }

    # Remove temporary folders
    @("$ScratchDisk\DXBuilder_Dir", "$ScratchDisk\scratchdir") | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $_) {
                Write-Warning "Could not remove: $_"
            }
        }
    }

    # Eject ISO if specified
    if ($DriveLetter -and (Get-Volume -DriveLetter $DriveLetter[0] -ErrorAction SilentlyContinue)) {
        Get-Volume -DriveLetter $DriveLetter[0] | Get-DiskImage | Dismount-DiskImage -ErrorAction SilentlyContinue | Out-Null
        Write-Output "ISO drive $DriveLetter ejected."
    }

    # Remove downloaded files (only if downloaded by script)
    if ($downloadedAutounattend) {
        Remove-Item -Path "$PSScriptRoot\autounattend.xml" -Force -ErrorAction SilentlyContinue
    }
    if ($downloadedOscdimg) {
        Remove-Item -Path "$PSScriptRoot\oscdimg.exe" -Force -ErrorAction SilentlyContinue
    }

    Stop-Transcript -ErrorAction SilentlyContinue

    if ($ExitWithError) {
        Write-Error "Script terminated due to an error."
        exit 1
    }
}

function Show-AppSelectionMenu {
    $packagePrefixesDefault = @(
        'AppUp.IntelManagementandSecurityStatus',
        'Clipchamp.Clipchamp',
        'DolbyLaboratories.DolbyAccess',
        'DolbyLaboratories.DolbyDigitalPlusDecoderOEM',
        'Microsoft.BingNews',
        'Microsoft.BingSearch',
        'Microsoft.BingWeather',
        'Microsoft.Copilot',
        'Microsoft.Windows.CrossDevice',
        'Microsoft.GamingApp',
        'Microsoft.GetHelp',
        'Microsoft.Getstarted',
        'Microsoft.Microsoft3DViewer',
        'Microsoft.MicrosoftOfficeHub',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.MicrosoftStickyNotes',
        'Microsoft.MixedReality.Portal',
        'Microsoft.MSPaint',
        'Microsoft.Office.OneNote',
        'Microsoft.OfficePushNotificationUtility',
        'Microsoft.OutlookForWindows',
        'Microsoft.Paint',
        'Microsoft.People',
        'Microsoft.PowerAutomateDesktop',
        'Microsoft.SkypeApp',
        'Microsoft.StartExperiencesApp',
        'Microsoft.Todos',
        'Microsoft.Wallet',
        'Microsoft.Windows.DevHome',
        'Microsoft.Windows.Copilot',
        'Microsoft.Windows.Teams',
        'Microsoft.WindowsAlarms',
        'Microsoft.WindowsCamera',
        'microsoft.windowscommunicationsapps',
        'Microsoft.WindowsFeedbackHub',
        'Microsoft.WindowsMaps',
        'Microsoft.WindowsSoundRecorder',
        'Microsoft.WindowsTerminal',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.YourPhone',
        'Microsoft.ZuneMusic',
        'Microsoft.ZuneVideo',
        'MicrosoftCorporationII.MicrosoftFamily',
        'MicrosoftCorporationII.QuickAssist',
        'MSTeams',
        'MicrosoftTeams',
        'Microsoft.549981C3F5F10'
    )

    $selectedPackages = @()
    Write-Host "`n--- Select Apps to REMOVE ---" -ForegroundColor Yellow
    for ($i = 0; $i -lt $packagePrefixesDefault.Count; $i++) {
        Write-Host "$($i+1). $($packagePrefixesDefault[$i])"
    }
    Write-Host "0. Select ALL (default)" -ForegroundColor Green
    Write-Host "`nPress Enter to confirm selection.`n"

    $input = Read-Host "Enter numbers separated by commas (e.g., 1,3,5) or 0 for all"
    if ([string]::IsNullOrWhiteSpace($input) -or $input -eq "0") {
        return $packagePrefixesDefault
    }

    $indices = $input -split ',' | ForEach-Object { $_.Trim() -as [int] }
    foreach ($idx in $indices) {
        if ($idx -ge 1 -and $idx -le $packagePrefixesDefault.Count) {
            $selectedPackages += $packagePrefixesDefault[$idx - 1]
        }
    }

    return $selectedPackages
}

#---------[ Execution ]---------#

# Check Execution Policy
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Output "PowerShell Execution Policy is Restricted. Change to RemoteSigned? (yes/no)"
    $response = Read-Host
    if ($response -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    } else {
        Write-Error "Script cannot run without changing Execution Policy."
        exit 1
    }
}

# Check Admin Rights
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "Restarting as Administrator..."
    Start-Process PowerShell -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Download or verify autounattend.xml (CORRECTED VERSION)
$autounattendPath = "$PSScriptRoot\autounattend.xml"
$downloadedAutounattend = $false

if (-not (Test-Path $autounattendPath)) {
    Write-Output "Downloading corrected autounattend.xml..."
    $correctedXml = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
            </OOBE>
            <ConfigureChatAutoInstall>false</ConfigureChatAutoInstall>
        </component>
    </settings>
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DynamicUpdate>
                <WillShowUI>OnError</WillShowUI>
            </DynamicUpdate>
            <ImageInstall>
                <OSImage>
                    <Compact>true</Compact>
                    <WillShowUI>OnError</WillShowUI>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/INDEX</Key>
                            <Value>1</Value>
                        </MetaData>
                    </InstallFrom>
                </OSImage>
            </ImageInstall>
            <UserData>
                <ProductKey>
                    <Key/>
                </ProductKey>
            </UserData>
        </component>
    </settings>
</unattend>
'@
    $correctedXml | Out-File $autounattendPath -Encoding UTF8
    $downloadedAutounattend = $true
    Write-Output "Corrected autounattend.xml saved locally."
}

# Validate Scratch Disk
if (-not (Test-Path $ScratchDisk)) {
    Write-Error "Scratch disk $ScratchDisk not found or inaccessible."
    Invoke-Cleanup -ExitWithError
}

# Get ISO Drive Letter
do {
    if (-not $ISO) {
        $DriveLetterInput = Read-Host "Enter drive letter for mounted Windows 11 ISO"
    } else {
        $DriveLetterInput = $ISO
    }
    if ($DriveLetterInput -match '^[c-zC-Z]$') {
        $DriveLetter = $DriveLetterInput + ":"
        if (Test-Path "$DriveLetter\") {
            Write-Output "Drive letter set to $DriveLetter"
            break
        } else {
            Write-Warning "Drive $DriveLetter is not accessible. Please check if ISO is mounted."
        }
    } else {
        Write-Warning "Invalid drive letter. Enter a letter between C and Z."
    }
} while ($true)

# Check for installation files
if (-not (Test-Path "$DriveLetter\sources\boot.wim") -or (-not (Test-Path "$DriveLetter\sources\install.wim") -and -not (Test-Path "$DriveLetter\sources\install.esd"))) {
    Write-Error "Cannot find Windows installation files (boot.wim + install.wim/install.esd) on $DriveLetter."
    Invoke-Cleanup -ExitWithError
}

# Prepare workspace (¡CAMBIADO! Usa DXBuilder_Dir)
New-Item -ItemType Directory -Force -Path "$ScratchDisk\DXBuilder_Dir\sources" | Out-Null

# Handle install.esd
if ((Test-Path "$DriveLetter\sources\install.esd") -and (-not (Test-Path "$DriveLetter\sources\install.wim"))) {
    Write-Output "Found install.esd, converting to install.wim..."
    Get-WindowsImage -ImagePath "$DriveLetter\sources\install.esd" | Format-Table ImageIndex, ImageName
    $index = Read-Host "Enter image index to convert"
    Write-Progress -Activity "Converting ESD to WIM" -Status "This may take 20-40 minutes. Please wait..."
    Export-WindowsImage -SourceImagePath "$DriveLetter\sources\install.esd" -SourceIndex $index -DestinationImagePath "$ScratchDisk\DXBuilder_Dir\sources\install.wim" -CompressionType Maximum -CheckIntegrity
    Write-Progress -Activity "Converting ESD to WIM" -Completed
}

# Copy ISO contents (¡CAMBIADO!)
Write-Output "Copying Windows image files..."
Copy-Item -Path "$DriveLetter\*" -Destination "$ScratchDisk\DXBuilder_Dir" -Recurse -Force
if (Test-Path "$ScratchDisk\DXBuilder_Dir\sources\install.esd") {
    Set-ItemProperty -Path "$ScratchDisk\DXBuilder_Dir\sources\install.esd" -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    Remove-Item "$ScratchDisk\DXBuilder_Dir\sources\install.esd" -Force -ErrorAction SilentlyContinue
}

# Get Image Index
Write-Output "Getting image information:"
Get-WindowsImage -ImagePath "$ScratchDisk\DXBuilder_Dir\sources\install.wim" | Format-Table ImageIndex, ImageName, ImageDescription
$index = Read-Host "Enter image index to modify"

# Mount Image
Write-Output "Mounting Windows image (Index $index). This may take a few minutes..."
$wimFilePath = "$ScratchDisk\DXBuilder_Dir\sources\install.wim"

try {
    # Take ownership if needed
    & takeown /F $wimFilePath 2>&1 | Out-Null
    & icacls $wimFilePath /grant "$(([System.Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([System.Security.Principal.NTAccount]).Value):(F)" 2>&1 | Out-Null

    New-Item -ItemType Directory -Force -Path "$ScratchDisk\scratchdir" | Out-Null
    Mount-WindowsImage -ImagePath $wimFilePath -Index $index -Path "$ScratchDisk\scratchdir" -ErrorAction Stop
} catch {
    Write-Error "Failed to mount image: $_"
    Invoke-Cleanup -ExitWithError
}

# Get Architecture and Language
$imageInfo = dism /English /Get-WimInfo /wimFile:$wimFilePath /index:$index
$architecture = ($imageInfo | Select-String 'Architecture : (.*)').Matches.Groups[1].Value
if ($architecture -eq 'x64') { $architecture = 'amd64' }
Write-Output "Architecture: $architecture"

$hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
if ($architecture -ne $hostArchitecture -and -not ($hostArchitecture -eq 'AMD64' -and $architecture -eq 'x86')) {
    Write-Warning "Image architecture ($architecture) does not match host ($hostArchitecture). Proceed with caution."
}

# Load Registry Hives
Write-Output "Loading registry hives..."
@(
    @{ Hive = 'HKLM\zCOMPONENTS'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\COMPONENTS" },
    @{ Hive = 'HKLM\zDEFAULT'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\DEFAULT" },
    @{ Hive = 'HKLM\zNTUSER'; Path = "$ScratchDisk\scratchdir\Users\Default\ntuser.dat" },
    @{ Hive = 'HKLM\zSOFTWARE'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE" },
    @{ Hive = 'HKLM\zSYSTEM'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\SYSTEM" }
) | ForEach-Object {
    if (Test-Path $_.Path) {
        reg load $_.Hive $_.Path 2>&1 | Out-Null
    } else {
        Write-Warning "Registry hive not found: $($_.Path)"
    }
}

# Get Provisioned Packages
Write-Output "Retrieving list of provisioned apps..."
$packages = dism /English /image:"$ScratchDisk\scratchdir" /Get-ProvisionedAppxPackages | Where-Object { $_ -match 'PackageName : (.*)' } | ForEach-Object { $matches[1] }

# Determine packages to remove
$packagesToRemove = @()
if ($InteractiveApps) {
    $packagePrefixes = Show-AppSelectionMenu
} else {
    $packagePrefixes = @(
        'AppUp.IntelManagementandSecurityStatus',
        'Clipchamp.Clipchamp',
        'DolbyLaboratories.DolbyAccess',
        'DolbyLaboratories.DolbyDigitalPlusDecoderOEM',
        'Microsoft.BingNews',
        'Microsoft.BingSearch',
        'Microsoft.BingWeather',
        'Microsoft.Copilot',
        'Microsoft.Windows.CrossDevice',
        'Microsoft.GamingApp',
        'Microsoft.GetHelp',
        'Microsoft.Getstarted',
        'Microsoft.Microsoft3DViewer',
        'Microsoft.MicrosoftOfficeHub',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.MicrosoftStickyNotes',
        'Microsoft.MixedReality.Portal',
        'Microsoft.MSPaint',
        'Microsoft.Office.OneNote',
        'Microsoft.OfficePushNotificationUtility',
        'Microsoft.OutlookForWindows',
        'Microsoft.Paint',
        'Microsoft.People',
        'Microsoft.PowerAutomateDesktop',
        'Microsoft.SkypeApp',
        'Microsoft.StartExperiencesApp',
        'Microsoft.Todos',
        'Microsoft.Wallet',
        'Microsoft.Windows.DevHome',
        'Microsoft.Windows.Copilot',
        'Microsoft.Windows.Teams',
        'Microsoft.WindowsAlarms',
        'Microsoft.WindowsCamera',
        'microsoft.windowscommunicationsapps',
        'Microsoft.WindowsFeedbackHub',
        'Microsoft.WindowsMaps',
        'Microsoft.WindowsSoundRecorder',
        'Microsoft.WindowsTerminal',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxApp',
        'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.YourPhone',
        'Microsoft.ZuneMusic',
        'Microsoft.ZuneVideo',
        'MicrosoftCorporationII.MicrosoftFamily',
        'MicrosoftCorporationII.QuickAssist',
        'MSTeams',
        'MicrosoftTeams',
        'Microsoft.549981C3F5F10'
    )
}

$packagesToRemove = $packages | Where-Object {
    $pkg = $_
    $packagePrefixes | Where-Object { $pkg -like "*$_*" }
}

# Remove Apps
foreach ($package in $packagesToRemove) {
    Write-Output "Removing: $package"
    dism /English /image:"$ScratchDisk\scratchdir" /Remove-ProvisionedAppxPackage /PackageName:$package | Out-Null
}

# Remove Edge & OneDrive (Hardcoded, as per request)
Write-Output "Removing Edge..."
Remove-Item -Path "$ScratchDisk\scratchdir\Program Files (x86)\Microsoft\Edge*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ScratchDisk\scratchdir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Removing OneDrive..."
Remove-Item -Path "$ScratchDisk\scratchdir\Windows\System32\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue

# Apply Registry Tweaks
Write-Output "Applying registry tweaks..."

# Bypass Hardware Checks
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'

# Disabling Sponsored Apps
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'OemPreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'ContentDeliveryAllowed' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' 'ConfigureStartPins' 'REG_SZ' '{"pinnedList": [{}]}'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'FeatureManagementEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEverEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContentEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'

# Enabling Local Accounts on OOBE
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'

# Disabling Reserved Storage
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'

# Disabling BitLocker Device Encryption
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'

# Disabling Chat icon
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'

# Removing Edge related registries
Remove-RegistryValue "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
Remove-RegistryValue "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"

# Disabling OneDrive folder backup
Set-RegistryValue "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "REG_DWORD" "1"

# Disabling Telemetry
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' 'Start' 'REG_DWORD' '4'

# Prevents installation of DevHome and Outlook
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'

# Disabling Copilot
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 'REG_DWORD' '1'

# Prevents installation of Teams
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'

# Prevent installation of New Outlook
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'

# Deleting scheduled task definition files
Write-Host "Deleting scheduled task definition files..."
$tasksPath = "$ScratchDisk\scratchdir\Windows\System32\Tasks"
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" -Force -ErrorAction SilentlyContinue
Write-Host "Task files have been deleted."

# Copy Autounattend to Sysprep
Copy-Item -Path $autounattendPath -Destination "$ScratchDisk\scratchdir\Windows\System32\Sysprep\autounattend.xml" -Force

# Unload Registry
Write-Output "Unloading registry hives..."
@('HKLM\zCOMPONENTS', 'HKLM\zDEFAULT', 'HKLM\zNTUSER', 'HKLM\zSOFTWARE', 'HKLM\zSYSTEM') | ForEach-Object {
    reg unload $_ 2>&1 | Out-Null
}

# Cleanup Image
Write-Progress -Activity "Cleaning up image" -Status "Running DISM /Cleanup-Image /StartComponentCleanup /ResetBase. This may take 10-30 minutes."
dism.exe /Image:"$ScratchDisk\scratchdir" /Cleanup-Image /StartComponentCleanup /ResetBase
Write-Progress -Activity "Cleaning up image" -Completed

# Dismount and Export
Write-Output "Saving and exporting image..."
Dismount-WindowsImage -Path "$ScratchDisk\scratchdir" -Save

Write-Progress -Activity "Exporting compressed image" -Status "Creating install.wim with recovery compression..."
Dism.exe /Export-Image /SourceImageFile:"$ScratchDisk\DXBuilder_Dir\sources\install.wim" /SourceIndex:$index /DestinationImageFile:"$ScratchDisk\DXBuilder_Dir\sources\install2.wim" /Compress:recovery
Remove-Item -Path "$ScratchDisk\DXBuilder_Dir\sources\install.wim" -Force
Rename-Item -Path "$ScratchDisk\DXBuilder_Dir\sources\install2.wim" -NewName "install.wim"
Write-Progress -Activity "Exporting compressed image" -Completed

# Process boot.wim
Write-Output "Processing boot.wim..."
$bootWimPath = "$ScratchDisk\DXBuilder_Dir\sources\boot.wim"
& takeown /F $bootWimPath 2>&1 | Out-Null
& icacls $bootWimPath /grant "$(([System.Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([System.Security.Principal.NTAccount]).Value):(F)" 2>&1 | Out-Null

Mount-WindowsImage -ImagePath $bootWimPath -Index 2 -Path "$ScratchDisk\scratchdir"

# Load Registry for boot.wim
Write-Output "Loading registry hives for boot image..."
@(
    @{ Hive = 'HKLM\zCOMPONENTS'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\COMPONENTS" },
    @{ Hive = 'HKLM\zDEFAULT'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\DEFAULT" },
    @{ Hive = 'HKLM\zNTUSER'; Path = "$ScratchDisk\scratchdir\Users\Default\ntuser.dat" },
    @{ Hive = 'HKLM\zSOFTWARE'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE" },
    @{ Hive = 'HKLM\zSYSTEM'; Path = "$ScratchDisk\scratchdir\Windows\System32\config\SYSTEM" }
) | ForEach-Object {
    if (Test-Path $_.Path) {
        reg load $_.Hive $_.Path 2>&1 | Out-Null
    }
}

# Apply same bypasses to boot.wim
Write-Output "Applying hardware bypasses to boot image..."
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'

# Unload and Dismount boot.wim
@('HKLM\zCOMPONENTS', 'HKLM\zDEFAULT', 'HKLM\zNTUSER', 'HKLM\zSOFTWARE', 'HKLM\zSYSTEM') | ForEach-Object {
    reg unload $_ 2>&1 | Out-Null
}
Dismount-WindowsImage -Path "$ScratchDisk\scratchdir" -Save

# Create ISO
Write-Output "Copying autounattend.xml to ISO root..."
Copy-Item -Path $autounattendPath -Destination "$ScratchDisk\DXBuilder_Dir\autounattend.xml" -Force

Write-Output "Locating or downloading oscdimg.exe..."
$downloadedOscdimg = $false
$OSCDIMG = $null

$ADKPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostArchitecture\Oscdimg\oscdimg.exe"
if (Test-Path $ADKPath) {
    $OSCDIMG = $ADKPath
    Write-Output "Using oscdimg.exe from ADK: $OSCDIMG"
} else {
    $localOscdimg = "$PSScriptRoot\oscdimg.exe"
    if (-not (Test-Path $localOscdimg)) {
        $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"
        Write-Output "Downloading oscdimg.exe from Microsoft..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $localOscdimg -ErrorAction Stop
            $downloadedOscdimg = $true
        } catch {
            Write-Error "Failed to download oscdimg.exe: $_"
            Invoke-Cleanup -ExitWithError
        }
    }
    $OSCDIMG = $localOscdimg
    Write-Output "Using local oscdimg.exe: $OSCDIMG"

    # Validate it's executable
    if (-not (& $OSCDIMG '/?' 2>&1 | Select-String "usage")) {
        Write-Error "Downloaded oscdimg.exe is invalid or corrupted."
        Invoke-Cleanup -ExitWithError
    }
}

Write-Output "Creating bootable ISO..."
$isoPath = "$PSScriptRoot\DXBuilder.iso"
& $OSCDIMG -m -o -u2 -udfver102 -boot2#p0,e,b"$ScratchDisk\DXBuilder_Dir\boot\etfsboot.com"#pEF,e,b"$ScratchDisk\DXBuilder_Dir\efi\microsoft\boot\efisys.bin" "$ScratchDisk\DXBuilder_Dir" $isoPath

if (-not (Test-Path $isoPath)) {
    Write-Error "ISO creation failed."
    Invoke-Cleanup -ExitWithError
} else {
    Write-Output "✅ ISO created successfully: $isoPath"
    Write-Output "`n--- SHA256 Checksum ---"
    Get-FileHash -Path $isoPath -Algorithm SHA256 | Format-List
}

# Final Cleanup
Invoke-Cleanup

Write-Output "`n🎉 DXBuilder: Windows 11 image creation completed successfully!`n"
Write-Output "Created with DXBuilder - Inspired by tiny11, crafted by DeXon."
Read-Host "Press Enter to exit"

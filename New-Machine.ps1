﻿$ErrorActionPreference = 'Stop'

'Setting up Execution Policy'
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

'Adding Chocolatey'
$null = Get-PackageProvider -Name Chocolatey

'Trusting Chocolatey'
$null = Set-PackageSource -Name Chocolatey -Trusted

'Installing software from Chocolatey'
$ChocolateySoftwareToInstall = @(
    #'7zip.install'
    'brave'
    'conemu'
    'fiddler4'
    'firefox'
    'git.install'
    'git-credential-manager-for-windows'
    'google-chrome-x64'
    'hexchat'
    'itunes'
    'Keepass.install'
    'lastpass'
    'nmap'
    'notepadplusplus.install'
    'openinvscode'
    'putty.install'
    'rdcman'
    'snagit'
    'sql-server-management-studio'
    'vcredist-all'
    'visualstudiocode'
    'visualstudiocode-insiders'
    'VLC'
    'vscode-powershell'
    'WinMerge'
    'wireshark'
)

Foreach ($Software in $ChocolateySoftwareToInstall) {
    if ($null -eq (Get-Package -Name $Software -ErrorAction SilentlyContinue)) {
        'Installing Package - {0}' -f $Software
        $null = Install-Package -Name $Software -ProviderName chocolatey
    }
    else {
        $InstalledVersion = (Get-Package -Name $Software)[0].version
        $LatestVersion = (Find-Package -Name $Software)[0].version

        if ($InstalledVersion -lt $LatestVersion) {
            'Updating Package - {0}' -f $Software
            $null = Install-Package -Name $Software -ProviderName chocolatey
        }
    }
}

'Set PS Gallery to trusted'
$null = Set-PackageSource -Name PSGallery -Trusted

'Installing modules for PS gallery'
$ModulesToInstall = @(
    'AzureRM'
    'Azure'
    'AuditPolicyDSC'
    'cAzureStorage'
    'cChoco'
    'cWSMan'
    'GPRegistryPolicy'
    'HybridWorkerToolkit'
    'PackageManagement'
    'PackageManagementProviderResource'
    'Pester'
    'Plaster'
    'Posh-Docker'
    'Posh-Git'
    'Posh-SSH'
    'PowerShellGet'
    'PSReadline'
    'PSScriptAnalyzer'
    'SecurityPolicyDSC'
    'WindowsDefender'
    'xActiveDirectory'
    'xAdcsDeployment'
    'xCertificate'
    'xComputerManagement'
    'xDFS'
    'xDnsServer'
    'xDSCResourceDesigner'
    'xNetworking'
    'xPendingReboot'
    'xPSDesiredStateConfiguration'
    'xRemoteDesktopAdmin'
    'xStorage'
    'xTimeZone'
    'xWebAdministration'
    'xWindowsUpdate'
)

Foreach ($Module in $ModulesToInstall) {
    'Processing Module - {0}' -f $Module
    if ($null -eq (Get-Module -Name $Module -ListAvailable)) {
        'Installing PowerShell Module - {0}' -f $Module
        $null = Install-Module -Name $Module -Force
    }
    else {
        $InstalledVersion = (Get-Module -Name $Module -ListAvailable)[0].version
        $LatestVersion = (Find-Module -Name $Module)[0].version

        if ($InstalledVersion -lt $LatestVersion) {
            if ($null -eq (Get-Package -Name $Module -ErrorAction SilentlyContinue)) {
                'Force Installing PowerShell Module - {0}' -f $Module
                $null = Install-Module -Name $Module -Force
            }
            else {
                'Updating PowerShell Module - {0}' -f $Module
                $null = Update-Module -Name $Module -Force
            }
        }
    }
}

'Installing .Net 3.5'
Enable-WindowsOptionalFeature -FeatureName NetFx3 -Online

'Enable Developer Mode'
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Value 1
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Value 1

'Installing Bash on Windows'
#Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux'

'Enable CTL+ALT+DEL at logon'
$null = New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -PropertyType DWORD -Value 0 -Force

'Setting UAC to FULL'
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2

'Set explorer to open to "This PC"'
$null = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -PropertyType DWORD -Value 1 -Force

'Show file extensions'
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -PropertyType DWORD -Value 0 -Force

'Set PowerShell for Win+X'
$null = Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'DontUsePowerShellOnWinX' -Value 0

'Make Git ask who I am before I commit'
& "$env:ProgramW6432\git\bin\git.exe" config --global user.useconfigonly true

'Setting git push behaviour to squelch the 2.0 upgrade message'
if ($null -eq (& "$env:ProgramW6432\git\bin\git.exe" config push.default)) {
    'Setting git push behaviour to squelch the 2.0 upgrade message'
    & "$env:ProgramW6432\git\bin\git.exe" config --global push.default simple
}

'Setting git aliases'
& "$env:ProgramW6432\git\bin\git.exe" config --global alias.st 'status'
& "$env:ProgramW6432\git\bin\git.exe" config --global alias.co 'checkout'
& "$env:ProgramW6432\git\bin\git.exe" config --global alias.df 'diff'
& "$env:ProgramW6432\git\bin\git.exe" config --global alias.lg "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset' --abbrev-commit --date=relative"

'Enabling Office smileys'
if (Test-Path -Path 'HKCU:\Software\Microsoft\Office\16.0') {
    if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback')) {
        $null = New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -ItemType Directory
    }
    $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -Name Enabled -Value 1
}
else {
    Write-Warning -Message "Couldn't find a compatible install of Office"
}

'Block Advertising in IE'

if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety')) {
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety' -ItemType Directory
}
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE')) {
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -ItemType Directory
}
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\')) {
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\' -ItemType Directory
}
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'FilteringMode' -PropertyType DWORD -Value 0 -Force
if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}')) {
    $null = New-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}' -ItemType Directory
}
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Enabled' -PropertyType DWORD -Value 1 -Force
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Name' -PropertyType String -Value 'EasyList' -Force
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Path' -PropertyType String -Value '%AppDataDir%\Local\Microsoft\Internet Explorer\Tracking Protection\{7C998372-3B89-46E6-9546-1945C711CD0C}.tpl' -Force
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Url' -PropertyType String -Value 'http://easylist-msie.adblockplus.org/easylist.tpl' -Force

'Install Microsoft Junk E-Mail Reporting Add-in'
$MicrosoftDownloadsURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=18275'
$DownloadPage = Invoke-WebRequest -UseBasicParsing -Uri $MicrosoftDownloadsURL
$DownloadLink = ($DownloadPage.Links.Where{$_.outerHTML -match 'Click here' -and $_.href -match 'Junk Reporting Add-in for Office 2007' -and $_.href -match '32-bit'}).href[0]
$null = Invoke-WebRequest -UseBasicParsing -Uri $DownloadLink -OutFile "$env:temp\junkreporter-installer.msi"
Start-Process -FilePath "$env:temp\junkreporter-installer.msi" -ArgumentList '/quiet /qn /norestart' -Wait

'Date and time formatting'
$null = Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name sShortDate -Value yyyy-MM-dd
$null = Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name sShortTime -Value HH:mm

'Update PowerShell Help'
Update-Help -ErrorAction SilentlyContinue

'Install RSAT for Windows 10/Server 2016'
$MicrosoftDownloadsURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=45520'
$DownloadPage = Invoke-WebRequest -UseBasicParsing -Uri $MicrosoftDownloadsURL
$DownloadLink = ($DownloadPage.Links.Where{$_.outerHTML -match 'Click here' -and $_.href -match 'x64.msu'}).href[0]
$null = Invoke-WebRequest -UseBasicParsing -Uri $DownloadLink -OutFile "$env:temp\rsat.msu"
Start-Process -FilePath "$env:temp\rsat.msu" -ArgumentList '/quiet /norestart' -Wait

<#
    TODO: Features to add:
    'Block Macros in Word, Excel and Publisher'
#>

<#
git config --global core.editor "code --wait"
git config --global user.name "Matt Hilton"

if (-not (Test-Path -Path HKCU:\Software\Microsoft\OneDrive))
{throw "Couldn't find a compatible install of OneDrive"}
$OneDriveRoot = (Get-Item -Path HKCU:\Software\Microsoft\OneDrive).GetValue('UserFolder')
if (-not (Test-Path $OneDriveRoot))
{throw "Couldn't find the OneDrive root"}

$SshKeyPath = Join-Path -Path $OneDriveRoot -ChildPath Configuration\SSHProfiles\GitHub\GitPrivate.ppk
if (-not (Test-Path $SshKeyPath))
{throw "Couldn't find SSH key at $SshKeyPath"}

$sshHomePath = Join-Path $ENV:UserProfile '.ssh'
if (-not (Test-Path $sshHomePath))
{ mkdir $sshHomePath }
Copy-Item $SshKeyPath $sshHomePath

'Setting plink.exe as GIT_SSH'
$PuttyDirectory = 'C:\Program Files (x86)\PuTTY'
$PlinkPath = Join-Path -Path $PuttyDirectory -ChildPath plink.exe
[Environment]::SetEnvironmentVariable('GIT_SSH', $PlinkPath, [EnvironmentVariableTarget]::User)
$env:GIT_SSH = $PlinkPath

"Storing GitHub's SSH key"
$SshHostKeysPath = 'HKCU:\SOFTWARE\SimonTatham\PuTTY\SshHostKeys'
if (-not (Test-Path $SshHostKeysPath)) { New-Item $SshHostKeysPath -ItemType Directory -Force }
Set-ItemProperty -Path $SshHostKeysPath -Name 'rsa2@22:github.com' -Value '0x23,0xab603b8511a67679bdb540db3bd2034b004ae936d06be3d760f08fcbaadb4eb4edc3b3c791c70aae9a74c95869e4774421c2abea92e554305f38b5fd414b3208e574c337e320936518462c7652c98b31e16e7da6523bd200742a6444d83fcd5e1732d03673c7b7811555487b55f0c4494f3829ece60f94255a95cb9af537d7fc8c7fe49ef318474ef2920992052265b0a06ea66d4a167fd9f3a48a1a4a307ec1eaaa5149a969a6ac5d56a5ef627e517d81fb644f5b745c4f478ecd082a9492f744aad326f76c8c4dc9100bc6ab79461d2657cb6f06dec92e6b64a6562ff0e32084ea06ce0ea9d35a583bfb00bad38c9d19703c549892e5aa78dc95e250514069'




        $SshKeyPath = Join-Path -Path $OneDriveRoot -ChildPath Configuration\SSHProfiles\GitHub\GitPrivate.ppk
        if (-not (Test-Path $SshKeyPath))
        {
        throw "Couldn't find SSH key at $SshKeyPath"
        }

        $sshHomePath = Join-Path $ENV:UserProfile '.ssh'
        if (-not (Test-Path $sshHomePath))
        {
        mkdir $sshHomePath
        }
        Copy-Item $SshKeyPath $sshHomePath

        'Setting plink.exe as GIT_SSH'
        $PuttyDirectory = 'C:\Program Files (x86)\PuTTY'
        $PlinkPath = Join-Path -Path $PuttyDirectory -ChildPath plink.exe
        [Environment]::SetEnvironmentVariable('GIT_SSH', $PlinkPath, [EnvironmentVariableTarget]::User)
        $env:GIT_SSH = $PlinkPath

        "Storing GitHub's SSH key"
        $SshHostKeysPath = 'HKCU:\SOFTWARE\SimonTatham\PuTTY\SshHostKeys'
        if (-not (Test-Path $SshHostKeysPath))
        {
        New-Item $SshHostKeysPath -ItemType Directory -Force
        }
        Set-ItemProperty -Path $SshHostKeysPath -Name 'rsa2@22:github.com' -Value '0x23,0xab603b8511a67679bdb540db3bd2034b004ae936d06be3d760f08fcbaadb4eb4edc3b3c791c70aae9a74c95869e4774421c2abea92e554305f38b5fd414b3208e574c337e320936518462c7652c98b31e16e7da6523bd200742a6444d83fcd5e1732d03673c7b7811555487b55f0c4494f3829ece60f94255a95cb9af537d7fc8c7fe49ef318474ef2920992052265b0a06ea66d4a167fd9f3a48a1a4a307ec1eaaa5149a969a6ac5d56a5ef627e517d81fb644f5b745c4f478ecd082a9492f744aad326f76c8c4dc9100bc6ab79461d2657cb6f06dec92e6b64a6562ff0e32084ea06ce0ea9d35a583bfb00bad38c9d19703c549892e5aa78dc95e250514069'
#>


'REBOOT!'

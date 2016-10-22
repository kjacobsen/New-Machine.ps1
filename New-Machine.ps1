$ErrorActionPreference = 'Stop'

'Setting up Execution Policy'
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

'Adding Chocolatey'
$null = Get-PackageProvider -Name Chocolatey

'Trusting Chocolatey'
$null = Set-PackageSource -Name Chocolatey -Trusted

'Installing software from Chocolatey'
$ChocolateySoftwareToInstall = @(
    'vcredist2005'
    'vcredist2008'
    'vcredist2010'
    'vcredist2012'
    'vcredist2013'
    'vcredist2015'
    '7zip.install'
    'adobereader'
    'tunnelier'
    'CrashPlan'
    #'emet'
    'fiddler4'
    'git.install'
    #'glasswire'
    'google-chrome-x64'
    'hexchat'
    'Keepass.install'
    'git-credential-manager-for-windows'
    'visualstudiocode'
    'vscode-powershell'
    #'visualstudiocode-insiders'
    'openinvscode'
    'nmap'
    'notepadplusplus.install'
    'putty.install'
    'rdmfree'
    'slack'
    #'spotify'
    'WinMerge'
    'wireshark'
    'conemu'
    'VLC'
    'WinSCP.install'
    'openssh'
    'vmwareworkstation'
)

Foreach ($Software in $ChocolateySoftwareToInstall)
{
    "Installing $Software"
    $null = Install-Package -Name $Software -ProviderName chocolatey
}

'Set PS Gallery to trusted'
$null = Set-PackageSource -Name PSGallery -Trusted

'Installing modules for PS gallery'
$ModulesToInstall = @(
    #'Azure'
    #'AzureRM'
    'Posh-Git'
    'cChoco'
    'cWSMan'
    'HybridWorkerToolkit'
    'Pester'
    'Posh-SSH'
    'PSScriptAnalyzer'
    'xActiveDirectory'
    'xAdcsDeployment'
    'xCertificate'
    'xComputerManagement'
    'xDnsServer'
    'xDSCResourceDesigner'
    'xNetworking'
    'xPSDesiredStateConfiguration'
    'xStorage'
    'xRemoteDesktopAdmin'
    'xWebAdministration'
    'PSReadline'
    'PowerShellGet'
    'PackageManagement'
)

Foreach ($Module in $ModulesToInstall)
{
    "Installing $Module"
    #$null = Install-Module -Name $Module -Force
}

'Install PowerShell ISE Steroids into current user'
Install-Module -Name 'ISESteroids' -Scope CurrentUser

'Forcing up to new version of PowerShellGet'
Import-Module PowerShellGet -Force -MinimumVersion 1.1.1.0

'Installing Office Pro Plus'
#$null = Install-Module -Name 'OfficeProvider' -Force
$Null = import-packageprovider 'OfficeProvider'
$null = Get-PackageProvider -Name 'OfficeProvider' -ForceBootstrap
$null = Install-Package -Name 'Office Installer' -ProviderName OfficeProvider -Bitness 32 -Channel FirstReleaseCurrent

'Installing .Net 3.5'
Enable-WindowsOptionalFeature –Online –FeatureName 'NetFx3' –All

'Enable Developer Mode'
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Value 1
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Value 1

'Installing Bash on Windows'
Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux'

'Enable CTL+ALT+DEL at logon'
$null = New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -PropertyType DWORD -Value 0 -Force

'Setting UAC to FULL'
$null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 3

'Set explorer to open to "This PC"'
$null = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -PropertyType DWORD -Value 1 -Force

'Show file extensions'
$null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -PropertyType DWORD -Value 0 -Force

'Set PowerShell for Win+X'
$null = Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'DontUsePowerShellOnWinX' -Value 0

'Make Git ask who I am before I commit'
git config --global user.useconfigonly true

'Setting git push behaviour to squelch the 2.0 upgrade message'
if ((& git.exe config push.default) -eq $null)
{
    'Setting git push behaviour to squelch the 2.0 upgrade message'
    git.exe config --global push.default simple
}

'Setting git aliases'
git.exe config --global alias.st 'status'
git.exe config --global alias.co 'checkout'
git.exe config --global alias.df 'diff'
git.exe config --global alias.lg "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset' --abbrev-commit --date=relative"

'Enabling Office smileys'
if (Test-Path HKCU:\Software\Microsoft\Office\16.0) 
{
    if (-not (Test-Path -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback'))
    {
        $null = New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -ItemType Directory
    }
    $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -Name Enabled -Value 1
}
else
{
    Write-Warning "Couldn't find a compatible install of Office"
}

'Block Advertising in IE'
$null = New-ItemProperty -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'FilteringMode' -PropertyType DWORD -Value 0 -Force

if (-not (Test-Path -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}'))
{
    $null = New-Item -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}' -ItemType Directory
}
$null = New-ItemProperty -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Enabled' -PropertyType DWORD -Value 1 -Force
$null = New-ItemProperty -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Name' -PropertyType SZ -Value 'EasyList' -Force
$null = New-ItemProperty -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Path' -PropertyType SZ -Value '%AppDataDir%\Local\Microsoft\Internet Explorer\Tracking Protection\{7C998372-3B89-46E6-9546-1945C711CD0C}.tpl' -Force
$null = New-ItemProperty -Path 'HKCU:\\Software\Microsoft\Internet Explorer\Safety\PrivacIE' -Name 'Url' -PropertyType SZ -Value 'http://easylist-msie.adblockplus.org/easylist.tpl' -Force

'Harden Adobe PDF configuration'
$null = New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'iProtectedView' -PropertyType DWORD -Value 1 -Force

'Install Microsoft Junk E-Mail Reporting Add-in'
$MicrosoftDownloadsURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=18275'
$DownloadPage = Invoke-WebRequest -UseBasicParsing -Uri $MicrosoftDownloadsURL
$DownloadLink = ($DownloadPage.Links | Where-Object -FilterScript {$_.outerHTML -match 'Click here' -and $_.href -match 'Junk Reporting Add-in for Office 2007' -and $_.href -match '32-bit'}).href[0]
$Null = Invoke-WebRequest -UseBasicParsing -Uri $DownloadLink -OutFile "$env:temp\installer.msi"
start-process "$env:temp\installer.msi" -ArgumentList "/quiet /qn /norestart" -Wait

'==================='
'Ensure Nuget is up to date'

'Block Macros in Word, Excel and Publisher'

'Date and time formatting'

'Installing ISE Steriods License (if found)'

'GitHub SSH key configuration'

'Copy hexchat configuration'

'=============='
<#
if (-not (Test-Path -Path HKCU:\Software\Microsoft\OneDrive))
{
    throw "Couldn't find a compatible install of OneDrive"
}

$OneDriveRoot = (Get-Item -Path HKCU:\Software\Microsoft\OneDrive).GetValue('UserFolder')
if (-not (Test-Path $OneDriveRoot))
{
    throw "Couldn't find the OneDrive root"
}

$SshKeyPath = Join-Path -Path $OneDriveRoot -ChildPath SSHProfiles\GitHub\GitPrivate.ppk
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

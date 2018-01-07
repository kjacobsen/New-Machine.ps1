[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop';

$IsAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    throw 'You need to run this script elevated'
}

Write-Progress -Activity 'Setting execution policy'
Set-ExecutionPolicy RemoteSigned


Write-Progress -Activity 'Ensuring ChocolateyGet is available'
$null = Find-PackageProvider ChocolateyGet
$null = Install-PackageProvider ChocolateyGet
$null = Import-PackageProvider ChocolateyGet

Write-Progress -Activity "Ensuring Chocolatey is trusted"
if (-not ((Get-PackageSource -Name 'chocolatey').IsTrusted)) {
    $null = Set-PackageSource -Name 'chocolatey' -Trusted
}


$ChocolateySoftwareToInstall = @(
    'vcredist-all'
    'brave'
    'conemu'
    'git.install'
    'google-chrome-x64'
    'hexchat'
    'itunes'
    'lastpass'
    'google-chrome-x64'
    'visualstudiocode'
    'vscode-powershell'
    'openinvscode'
    'rdcman'
    'snagit'
    'sql-server-management-studio'
    'wireshark'
    'glasswire'
    'gpg4win'
)

Foreach ($Software in $ChocolateySoftwareToInstall) {
    if ($null -eq (Get-Package -Name $Software -ErrorAction SilentlyContinue)) {
        Write-Progress -Activity ('Installing Package - {0}' -f $Software)
        $null = Install-Package -Name $Software -ProviderName chocolatey
    }
    else {
        $InstalledVersion = (Get-Package -Name $Software).version
        $LatestVersion = (Find-Package -Name $Software).version

        if ($InstalledVersion -lt $LatestVersion) {
            Write-Progress -Activity ('Updating Package - {0}' -f $Software)
            $null = Install-Package -Name $Software -ProviderName chocolatey
        }
    }
}

Write-Progress -Activity 'Ensuring PowerShell Gallery is trusted'
if (-not ((Get-PackageSource -Name 'PSGallery').IsTrusted)) {
    $null = Set-PackageSource -Name 'PSGallery' -Trusted
}

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
    if ($null -eq (Get-Module -Name $Module -ListAvailable)) {
        Write-Progress -Activity ('Installing PowerShell Module - {0}' -f $Module)
        $null = Install-Module -Name $Module -Force
    }
    else {
        $InstalledVersion = (Get-Module -Name $Module -ListAvailable)[0].version
        $LatestVersion = (Find-Module -Name $Module)[0].version

        if ($InstalledVersion -lt $LatestVersion) {
            if ($null -eq (Get-Package -Name $Module -ErrorAction SilentlyContinue)) {
                Write-Progress -Activity ('Force Installing PowerShell Module - {0}' -f $Module)
                $null = Install-Module -Name $Module -Force
            }
            else {
                Write-Progress -Activity ('Updating PowerShell Module - {0}' -f $Module)
                $null = Update-Module -Name $Module -Force
            }
        }
    }
}

Write-Progress -Activity 'Enabling Office smileys'
if (Test-Path 'HKCU:\Software\Microsoft\Office\16.0') {
    if (-not (Test-Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback')) {
        $null = New-Item 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -ItemType Directory
    }

    if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback').Enabled -ne 1) {
        $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Feedback' -Name 'Enabled' -Value 1
    }
} else {
    Write-Warning "Couldn't find a compatible install of Office"
}

Write-Progress -Activity 'Disabling Outlook notifications'
if (Test-Path -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences') {
    if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences').ChangePointer -ne 0) {
        $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences' -Name 'ChangePointer' -Value 0
    }

    if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences').NewmailDesktopAlerts -ne 0) {
        $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences' -Name 'NewmailDesktopAlerts' -Value 0
    }

    if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences').PlaySound -ne 0) {
        $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences' -Name 'PlaySound' -Value 0
    }

    if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences').ShowEnvelope -ne 0) {
        $null = Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences' -Name 'ShowEnvelope' -Value 0
    }
}
else {
    Write-Warning "Couldn't find a compatible install of Outlook, or Outlook has never been started"
}

Write-Progress 'Hiding desktop icons'
if ((Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\').HideIcons -ne 1) {
    $null = Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'HideIcons' -Value 1
    $null = Get-Process 'explorer' | Stop-Process
}

Write-Progress "Enabling PowerShell on Win+X"
if ((Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\').DontUsePowerShellOnWinX -ne 0) {
    $null = Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'DontUsePowerShellOnWinX' -Value 0
    $null = Get-Process 'explorer' | Stop-Process
}

Write-Progress -Activity 'Enable CTL+ALT+DEL at logon'
if ((Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').DisableCAD -ne 0) {
    $null = Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Value 0
}

Write-Progress -Activity 'Setting UAC to FULL'
if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin -ne 2) {
    $null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
}

Write-Progress -Activity 'Set explorer to open to "This PC"'
if ((Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced').LaunchTo -ne 1) {
    $null = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -PropertyType DWORD -Value 1
    $null = Get-Process explorer | Stop-Process
}

Write-Progress -Activity 'Show file extensions'
if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced').HideFileExt -ne 0) {
    $null = New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -PropertyType DWORD -Value 0
    $null = Get-Process explorer | Stop-Process
}

Write-Progress -Activity 'Forcing .Net 4 to use TLS 1.2 by default'
if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319').SchUseStrongCrypto -ne 1) {
    $null = New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWORD -Value 1
}
if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319').SchUseStrongCrypto -ne 1) {
    $null = New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWORD -Value 1
}

<#
Write-Progress -Activity 'Hardening TLS (Server) Configuration'
# Disable insecure Ciphers - We use some weird registry calls here due to the / in the cipher names
$InsecureCiphers = 'DES 56/56', 'NULL', 'RC2 128/128', 'RC2 40/128', 'RC2 56/128', 'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128'
foreach ($Cipher in $InsecureCiphers)
{
    if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher")) {
        $CipherKey = (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($Cipher)
        $CipherKey.close()
    }

    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher").Enabled -ne 0) {
        $CipherKey = (Get-Item -Path 'HKLM:\').OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher", $true)
        $CipherKey.SetValue('Enabled', 0, 'DWord')
        $CipherKey.close()
    }
}

# Enable secure Ciphers
$SecureCiphers = 'AES 128/128', 'AES 256/256', 'Triple DES 168/168'
foreach ($Cipher in $SecureCiphers)
{
    if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher")) {
        $CipherKey = (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($Cipher)
        $CipherKey.close()
    }

    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher").Enabled -ne 1) {
        $CipherKey = (Get-Item -Path 'HKLM:\').OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher", $true)
        $CipherKey.SetValue('Enabled', 1, 'DWord')
        $CipherKey.close()
    }
}

# Disable MD5
if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')) {
    $null = New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -ItemType Directory
}
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5').Enabled -ne 0) {
    $null = New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Name 'Enabled' -Value 0
}

# Enable SHA
if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA')) {
    $null = New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -ItemType Directory
}
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA').Enabled -ne 1) {
    $null = New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -Name 'Enabled' -Value 1
}

# Enable Diffie-Hellman / PKCS
$KeyExchangeAlgorithms = 'Diffie-Hellman', 'PKCS'
foreach ($KeyExchangeAlgorithm in $KeyExchangeAlgorithms)
{
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KeyExchangeAlgorithm")) {
        $null = New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KeyExchangeAlgorithm" -ItemType Directory
    }
    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KeyExchangeAlgorithm").Enabled -ne 1) {
        $null = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KeyExchangeAlgorithm" -Name 'Enabled' -Value 1
    }
}

# Update Cipher Suite Order
$cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
)
$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)

if (-not (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions -eq $cipherSuitesAsString) {
    $null = New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value $cipherSuitesAsString -PropertyType String
}


# Disable PCT 1.0 / SSL 3.0 / SSL 2.0 / TLS 1.0 / TLS 1.1
$sslVersions = 'PCT 1.0', 'SSL 3.0', 'SSL 2.0', 'TLS 1.0', 'TLS 1.1'
foreach ($sslVersion in $sslVersions)
{
    if (-not (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion")) {
        $null = New-Item "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion" -ItemType Directory
    }

    if (-not (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server")) {
        $null = New-Item "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -ItemType Directory
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server").Enabled -ne 0) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -Name 'Enabled' -Value 0
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server").DisabledByDefault -ne 1) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -Name 'DisabledByDefault' -Value 1
    }
}

# Add TLS 1.2
$tlsVersion = 'TLS 1.2'
foreach ($x in $tlsVersion)
{
    if (-not (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion")) {
        $null = New-Item "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion" -ItemType Directory
    }

    if (-not (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server")) {
        $null = New-Item "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -ItemType Directory
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server").Enabled -ne 1) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -Name 'Enabled' -Value 1
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server").DisabledByDefault -ne 0) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Server" -Name 'DisabledByDefault' -Value 0
    }

    if (-not (Test-Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client")) {
        $null = New-Item "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client" -ItemType Directory
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client").Enabled -ne 1) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client" -Name 'Enabled' -Value 1
    }

    if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client").DisabledByDefault -ne 0) {
        $null = New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sslVersion\Client" -Name 'DisabledByDefault' -Value 0
    }
}
#>

Write-Progress -Activity 'Installing .Net 3.5'
$null = Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -NoRestart

Write-Progress -Activity 'Installing Subsystem for Linux'
$null = Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -NoRestart

Write-Progress -Activity 'Removing SMB1'
$null = Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart

Write-Progress -Activity 'Install Microsoft Junk E-Mail Reporting Add-in'
if ($null -eq (Get-Package -Name 'Microsoft Junk E-mail Reporting Add-in' -ErrorAction SilentlyContinue)) {
    $MicrosoftDownloadsURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=18275'
    $DownloadPage = Invoke-WebRequest -UseBasicParsing -Uri $MicrosoftDownloadsURL
    $DownloadLink = ($DownloadPage.Links.Where{$_.outerHTML -match 'Click here' -and $_.href -match 'Junk Reporting Add-in for Office 2007' -and $_.href -match '32-bit'}).href[0]
    $null = Invoke-WebRequest -UseBasicParsing -Uri $DownloadLink -OutFile "$env:temp\junkreporter-installer.msi"
    Start-Process -FilePath "$env:temp\junkreporter-installer.msi" -ArgumentList '/quiet /qn /norestart' -Wait
}

Write-Progress -Activity 'Install RSAT for Windows 10/Server 2016'
if ($null -eq (Get-Package -Name 'Update for Windows (KB2693643)' -ErrorAction SilentlyContinue)) {
    $MicrosoftDownloadsURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=45520'
    $DownloadPage = Invoke-WebRequest -UseBasicParsing -Uri $MicrosoftDownloadsURL
    $DownloadLink = ($DownloadPage.Links.Where{$_.outerHTML -match 'Click here' -and $_.href -match 'x64.msu'}).href[0]
    $null = Invoke-WebRequest -UseBasicParsing -Uri $DownloadLink -OutFile "$env:temp\rsat.msu"
    Start-Process -FilePath "$env:temp\rsat.msu" -ArgumentList '/quiet /norestart' -Wait
}

Write-Progress -Activity 'Setting Date and time formatting'
if ((Get-ItemProperty -Path 'HKCU:\Control Panel\International').sShortDate -ne 'yyy y-MM-dd') {
    $null = Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sShortDate' -Value 'yyyy-MM-dd'
}

if ((Get-ItemProperty -Path 'HKCU:\Control Panel\International').sShortTime -ne 'HH:mm'){
    $null = Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sShortTime' -Value 'HH:mm'
}

Write-Progress -Activity 'Updating PowerShell Help'
Update-Help -ErrorAction SilentlyContinue

<#
    TODO: Features to add:
    'Block Macros in Word, Excel and Publisher'
#>

<#

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

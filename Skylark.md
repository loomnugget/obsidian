```
nmap 192.168.240.220-227 192.168.240.250
```

.250
```
nmap 192.168.240.250
nmap -sT -A -p 5040,49664 192.168.240.250
sudo nmap -O 192.168.240.250 --osscan-guess
sudo nmap -sU --open -p 161 192.168.240.250

# only ports open (no snmp): 135,139,445,3389,5040,49664-49670
```

.220 - (Skylark Partner Portal)
```
nmap 192.168.240.220

# ports open: 80,135,139,445,5900(vnc),5985,47001(winrm),49664-49670
nmap -sT -A -p 80,5900,47001 192.168.240.220

# enumerate vnc, cannot connect
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 192.168.240.220
hydra -s 5900 -P /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt -t 16 192.168.240.220 vnc
vncviewer 192.168.240.220::5901

# enumerate smb - we need a password to do anything
enum4linux 192.168.240.220
nmap -v -p 139,445 --script smb-os-discovery 192.168.240.220
smbclient -L 192.168.240.220
smbmap -H 192.168.240.220

# enumerate webserver
# cracking using the 10million will take way too long, smaller lists have no effect
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/seclists/Passwords/probable-v2-top1575.txt -s 80 -f 192.168.240.220 http-get /
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.240.220 
```

.221 (austin02.SKYLARK.com)
```
nmap 192.168.240.221
nmap -sT -A -p 80,443 192.168.240.221
nmap -p 1000-60000 192.168.240.221
# port 3387, 5504 open

# enumerate port 10000 (i don't think it's actually ndmp, but another rdp port)
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 192.168.240.221

# enumerate smb - we need a password to do anything
enum4linux 192.168.240.221
nmap -v -p 139,445 --script smb-os-discovery 192.168.240.221
smbclient -L 192.168.240.221
smbmap -H 192.168.240.221

# enumerate webserver
nikto -host 192.168.240.221 -port 80
whatweb http://192.168.240.221:80
gobuster dir -u http://192.168.240.221:80 -w /usr/share/wordlists/dirb/common.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --url http://192.168.240.221 --dont-scan /aspnet_client,/Aspnet_client,/Aspnet_Client,/aspnet_Client,/ASPNET_CLIENT
```

.222
```
nmap 192.168.213.222
sudo nmap -sU --open -p 161 192.168.213.222

# ports 135,139,445,2994(veritas-vis2),5985(wsman),47001(winrm),49664-49670

# enumerate smb - we need a password to do anything
enum4linux 192.168.213.222
nmap -v -p 139,445 --script smb-os-discovery 192.168.213.222
smbclient -L 192.168.213.222
smbmap -H 192.168.213.222
```

.223
```
nmap 192.168.213.223
sudo nmap -sU --open -p 161 192.168.213.223

# 80,443 show up, but are closed, 161 open

```
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

.220
```
nmap 192.168.240.220

# ports open: 80,135,139,445,5900(vnc),5985,47001(winrm),49664-49670
nmap -sT -A -p 80,5900,47001 192.168.240.220

# enumerate vnc, cannot connect
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 192.168.240.220
hydra -s 5900 -P /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt -t 16 192.168.240.220 vnc

# enumerate smb


```
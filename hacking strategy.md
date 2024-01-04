### study guides
- TJnull study guide: https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html#section-17-port-redirection-and-pivoting
- Awesome cheat sheet: https://www.linkedin.com/pulse/muhammad-nomans-oscp-journey-comprehensive-review-110-noman-khalid-9ksgf/
- OSCP general cheat sheet (ok): https://github.com/akenofu/OSCP-Cheat-Sheet
- OSCP cheat sheet: https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP_Notes.md#port-21-ftp
- Generic study guide: https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-main.md
- ippsec videos: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
- Report template: https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP-exam-report-template_whoisflynn_v3.2.md?ref_type=heads
- Cheatsheet (includes important file locations): https://github.com/saisathvik1/OSCP-Cheatsheet

### helpful scripts/tools
- Invoke-PowerShellTcp.ps1: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
- sharphound.ps1: https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
- ligolo: https://github.com/nicocha30/ligolo-ng/releases
- rubeus: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
- powerview.ps1: https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1
- enum4linux: https://www.kali.org/tools/enum4linux/
- onetwopunch: https://github.com/superkojiman/onetwopunch
### enumeration
- SNMP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
- SNMP RCE: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce
- Awesome port list: https://github.com/dashagriiva/OSCP-Prep-1/blob/master/ServicesPortsList.txt - also this guy has other cheat sheets
- pentesting SNMP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp#modifying-snmp-values
### password cracking
- Cracking VNC: https://www.hackingarticles.in/password-crackingvnc/
- hashcat modes: https://hashcat.net/wiki/doku.php?id=hashcat
### wordlists
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt
- Rockyou (link downloads): https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
- Fasttrack: https://raw.githubusercontent.com/drtychai/wordlists/master/fasttrack.txt
### shells
- reverse shell cheatsheet: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- reverse shells cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- powershell shells: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/windows#powershell-shells
### pivoting
- Ligolo (includes double pivot) https://4pfsec.com/ligolo
- Pass the hash: https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/
- crackmapexec cheat sheet: https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/
- Port forwarding cheat sheet: https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-port-fowarding.md
### linux privesc
- Socket command injection: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/socket-command-injection
- linux privesc cheat sheet: https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html
- GTFOBins: https://gtfobins.github.io/
### windows privesc
- Best cheat sheet: https://sushant747.gitbooks.io/total-oscp-guide/content/cmd.html
- Windows privesc: https://github.com/evets007/OSCP-Prep-cheatsheet/blob/master/windows-privesc.md
-  Windows privesc cheat sheet: https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/
 - windows privesc cheat sheet: https://github.com/evets007/OSCP-Prep-cheatsheet/blob/master/windows-privesc.md
 - windows privesc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
 - potatoes: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer
 - DLL hijacking: https://notchxor.github.io/oscp-notes/4-win-privesc/6-dll-hijacking/
- Abuse kerberos using impacket: https://www.hackingarticles.in/abusing-kerberos-using-impacket/
- crackmapexec: https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/
- impacket: https://tools.thehacker.recipes/impacket
### active directory
- active directory cheat sheet: https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md

### Keep in mind
- do very thorough enumeration
- repeat enumeration steps after increasing privs
- check all directories and unusual services
- check for activedirectory info

### Initial enumeration
- scan common ports on machines in the external network, `-p-` for all ports, also scan UDP
```bash
nmap 192.168.248.225
sudo nmap -sU --open -p 161 192.168.248.225
sudo nmap -p- -Pn 192.168.248.225 -sS -T 5 --verbose
nmap -sT -A -p 80,8090 192.168.248.225
```
- fingerprint webservices
	- make note of http titles as well, could help identify cms/plugins etc
```
nikto -host 192.168.248.225 -port 8090
sudo nmap -sV -p 8090 --script "vuln" 192.168.248.225
```
- run whatweb for CMS identification
```bash
whatweb 192.168.248.225:8090
```
- use gobuster/feroxbuster to find directories/paths for web services
	- also check for files like pdfs
	- use exiftool to gain more info and pdftotext 
	- do more fuzzing if necessary
```
gobuster dir -u http://192.168.248.225:8090 -w /usr/share/wordlists/dirb/big.txt
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.248.225:8090
exiftool -a -u info.pdf
```
- look for initial foothold
	- find inputs for sql injection/command injection
	- find file uploads
	- find file params for LFI RFI
	- with fingerprinting/cms info find CVEs for those technologies or CMS vulnerabilities (plugins etc)
	- check smb, smtp, snmp, ftp
- searchsploit AND google for services, pprts and exploits
- LFI, RFI and directory traversal are all separate things, and are tested separately
- check for SMB hash attack via url params

### Windows privesc
- check if access to internal network
- run winpeas for initial overview of system
- look for Se privs
	- if impersonate, try to use printSpoofer or one of the potatos
- check user groups and privs
- look for other users and other groups
- look for hidden files that may contain passwords
- look for odd running programs 
	- do they have write access? (use icacls)
	- do they have ddls?
		- if so use procmon to check for missing ddls
	- can they be started/stopped
	- can use powerup to verify we can replace programs
	- unquoted service paths
- look for scheduled tasks
- check powershell history for secrets
- check for presence of keepass and .kdbx files
- identify if there are any internal web services - always check default admin creds
- note there may be AV protection blocking our scripts

### Linux privesc
- check for access to internal network
- determine the OS, arch, version for exploits and make sure you know how the distro works for example freeBSD
- run linpeas for initial overview
	- check exploits in output
	- check sudo version exploits
- look for writable files and directories, especially group and pw related and webservers
- look for user's sudo perms
- look at interesting programs and their config files (unusual SUID)
- look for internal webservers - always check default admin creds
- look for setuid binaries and capabilities
	- see if there are exploits on gtfo bins
- check for apparmor
- run pspy
- check log files for creds/interesting files
- check for dirty pipe
- check sudo version for exploit
- test su and sudo -l
- check for tar wildcard exploit

### Pivoting
- use found credentials
	- spray with crackmapexec smb
	- use crowbar to test RDP access
- if creds are a match, gain shell
	- if port 5986/5985 - winrm, evil-winrm
	- if only port 445 crackmapexec smb -X to run a shell
	- if crowbar success, use RDP
	- impacket psexec etc
- check all open ports and services including smtp, ftp, smb, webservers, rdp, ssh
- double check high ports
- if we have mail server creds we may be able to phish

### Active Directory 
- user powerview to gain more info on domain users
- determine if service accounts (iis_service) have higher privs
- look at domain shares
- look at user acls

### Post exploition
- determine if domain joined, if so run bloodhound to gather data as soon as possible
	-  this can determine if we can do kerb or aspreproasting on certain users
	- determine who are the domain users
	- determine shortest path to domain controller
	- see who has active sessions
- mimikatz to gain NTLM hashes
- look for hidden kdbx, passwords in files when you are higher priv
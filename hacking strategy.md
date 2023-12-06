### study guides
- TJnull study guide: https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html#section-17-port-redirection-and-pivoting
- crackmapexec: https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/
- impacket: https://tools.thehacker.recipes/impacket
- windows privesc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- potatos: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer
- powershell shells: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/windows#powershell-shells
- OSCP cheat sheet: https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP_Notes.md#port-21-ftp
- windows privesc cheat sheet: https://github.com/evets007/OSCP-Prep-cheatsheet/blob/master/windows-privesc.md

### helpful scripts/tools
- Invoke-PowerShellTcp.ps1: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
- sharphound.ps1: https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
- ligolo: https://github.com/nicocha30/ligolo-ng/releases
- rubeus: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
- powerview.ps1: https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1
- enum4linux: https://www.kali.org/tools/enum4linux/

### Keep in mind
- do very thorough enumeration
- repeat enumeration steps after increasing privs
- check all directories and unusual services
- check for activedirectory info

### Initial enumeration
- scan common ports on machines in the external network
- if nothing actionable found, try high ports
- udp ports
- fingerprint webservices
	- make note of http titles as well, could help identify cms/plugins etc
- run whatweb for CMS identification
- use gobuster to find directories/paths for web services
	- also check for files like pdfs
	- use exiftool to gain more info and pdftotext 
- do more fuzzing if necessary
- look for initial foothold
	- find inputs for sql injection/command injection
	- find file uploads
	- find file params for LFI RFI
	- with fingerprinting/cms info find CVEs for those technologies or CMS vulnerabilities (plugins etc)
	- check smb, smtp, snmp, ftp
- searchsploit AND google for services, pprts and exploits

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
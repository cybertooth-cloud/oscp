# OSCP
OSCP references, commands, resources

Repo to reference important scripts, commands, resources, and links for reference during study for the OSCP.

This repo is structured in the same manner as the OffSec PEN-200 course and will include content from them as well as valuable external resources.

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

- Using nmap: ```nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254``` >>> ```cat smb.txt```
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

- 


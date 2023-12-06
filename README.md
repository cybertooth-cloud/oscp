# oscp
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

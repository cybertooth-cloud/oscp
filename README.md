# oscp
OSCP references, commands, resources

Repo to reference important scripts, commands, resources, and links for reference during study for the OSCP.

This repo is structured in the same manner as the OffSec PEN-200 course and will include content from them as well as valuable external resources.

# **Passive Information Gathering**

## **Links**

1. SSL Server Test analyzes a server's SSL/TLS configuration and compares it against current best practices. It will also identify some SSL/TLS related vulnerabilities, such as Poodle6 or Heartbleed. >> https://www.ssllabs.com/ssltest/
2. Netcraft is an internet service company, based in England, offering a free web portal that performs various information gathering functions such as discovering which technologies are running on a given website and finding which other hosts share the same IP netblock. >>https://searchdns.netcraft.com/
3. Shodan is a search engine that crawls devices connected to the internet, including the servers that run websites, but also devices like routers and IoT devices. >> https://www.shodan.io/
4. Security Headers will analyze HTTP response headers and provide basic analysis of the target site's security posture. We can use this to get an idea of an organization's coding and security practices based on the results. >> https://securityheaders.com/

## **Commands/Scripts**

### WhoIs Enumeration

- Basic whois: 'whois <domain URL> -h <whois host IP>'
- Reverse whois: 'whois <NS IP> -h <whois host IP>'

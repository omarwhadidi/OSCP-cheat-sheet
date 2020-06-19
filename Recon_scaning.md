<h1 align="center">INFO GATHERING (OSINT) </h1>

<h2 align="center">Info Gathering (passive Reconnaissance/ Footprinting) </h2>

</P align="center">"Gather info about the target without being connected to him" </P>

-   **Domain & registration info**

    -   **Whois**

        -   Who.is

        -   Whois.domaintools.com

        -   Whois.com

    -   **News.netcraft.com**

    -   **Lookup.icann.org**

-   **Google Dorks**

    -   site:microsoft.com intitle:\"index of\"

    -   site:microsoft.com inurl:phpinfo

    -   site:microsoft.com intext:password

    -   site:microsoft.com filetype:pdf

    -   site:microsoft.com "specific word"

-   **Search Engine websites**

-   **Social Networking Sites**

-   **Archive search & History of the website**

    -   Archive.org

-   **People Search**

    -   Pipl.com

    -   Anywho.com

    -   Truecaller.com

    -   Peekyou.com

    -   Zoominfo.com

    -   Peoplelookup.com

    -   123people.com

    -   Wink.com

    -   Peoplesmart.com

    -   Whitepages.com

-   **Target location info gathering**

    -   Maps.google.com

    -   Google.com/earth

-   **Download websites (mirror)**

    -   HTTRACK

    -   Wget \[website\]

    -   Surfoffline.com

    -   Calluna-software.com

-   **Exploit search**

    -   www.exploit-db.com      -\> (google hacking database)

    -   www.securityfocus.com

    -   packetstormsecurity.com

-   **IOT (devices) search websites**

    -   Shodan.io

    -   Censys.com

-   **Email Info Gathering**

    -   **TheHarvester      -\>** gather subdomains, emails, ip's , employee names , ....

        -   theHarvester -d \[website\] -l 500 -b {all, baidu,bing,google,linkedin, twitter,virustotal,netcraft,yahoo}

    -   **Metasploit**

        -   Use auxiliary/gather/search\_email\_collector

    -   **SimplyEmail**

        -   git clone https://github.com/killswitch-GUI/SimplyEmail.git 

        -   ./SimplyEmail.py -all -e TARGET-DOMAIN

-   **Metadata info Gathering**

    -   **Metagoofil**      -\> download files and metadata about the website

        -   metagoofil -d \[domain\] -t {doc,pdf,xls,ppt,odp,ods,docx,xslx,pptx} -l 200 -n 5 -o \[out\] -f results.html

    -   **exiftool 	    -\>** show metada on files

        -   apt install exiftool

        -   exiftool \[file\]

-   **technology used in Websites Info Gathering**

    -   **whatweb**

        -   whatweb --v \[website\]

    -   **Dmitry**

        -   dmitry -winsep [\[website\]](http://example.com)

        -   dmitry -winsepo result.txt [\[website\]](http://example.com)

    -   **Wappalyzer addon**

-   **Firewall Info Gathering**

    -   **Wafwoof**

        -   Wafwoof --L -\> list all waf supported by wafwoof

        -   Wafwoof -a \[website\]

    -   **Nmap**

        -   nmap -p 80,443 \--script=http-waf-detect \[website\]

-   **Maltego** 	-\> Gui tool that gather domain owner info , Emails , domains , \...

-   **Recon-ng**

    -   **commands**

        -   help

        -   marketplace search \[module name\]

        -   marketplace install all    -\>install all the modules on my pc   

        -   marketplace install \[module name\]

        -   marketplace info \[module name\]

        -   modules search  - \> list all modules

        -   modules load \[module name\]   -\> same as use module 

            -   Ex  : modules load recon/profiles-profiles/profiler

        -   info   -\> list module info and options

        -   options set \[option\] \[value\]

        -   run

        -   show \[double tab\]  -\>to show all we can show

        -   show profiles  	 -\> show all profiles resulted from scan

-   **Dns Info Gathering**

    -   **Dns records**

        -   A Records: An address record that allows a computer name to be translated to an IP address. Each computer has to have this record for its IP address to be located via DNS.

        -   AAAA Records: same as A record but ipv6

        -   SOA Records: Indicates the server that has authority for the domain.

        -   MX Records: List of a host's or domain's mail exchanger server(s).

        -   NS Records: List of a host's or domain's name server(s).

        -   PTR Records: Lists a host's domain name, host identified by its IP address.(reverse lookup)

        -   SRV Records: Service location record.

        -   HINFO Records: Host information record with CPU type and operating system.

        -   TXT Records: Generic text record.

        -   CNAME: A host's canonical name allows additional names , aliases to be used to locate a computer.

        -   RP -- Responsible person for the domain.

    -   **Dns query websites**

        -   Mxtoolbox.com

        -   Dnsqueries.com

        -   Kloth.net

        -   Dnswatch.info

        -   Networktools.info

        -   Dnsstuff.com

        -   Networktools.tom

        -   Gsuitetoolbox.com

        -   Webmaster-toolkit.com

        -   Webbasedtools.com

-   **Extra Notes**

    -   curl ipinfo.io/193.35.34.6 		     -\> ip info

    -   [ipneighbour.com](http://ipneighbour.com/)  -\> identify if there are multiple websites installed on that host or no

    -   Show the email's password that have been leaked

        -   Haveibeenpwned.com

        -   Hacked-emails.com

    -   Securityheaders.com 	 -\> checks the security of a website

    -   Osintframework.com 	 -\> data mining tool like maltego

    -   Social-searcher.com	 -\> search for people in all social media

    -   Pastebin.com 		-\> site for sharing texts can be useful in recon phase


<h2 align="center">SCANNING (Active Reconnaissance)</h2>

<p align="center">"Gather info about the target by being connected to him"</p>

-   **Ping , traceroute , tracert**

-   **Network Discover :** (ping sweep) identify live hosts on a network

    -   **Manually with ping**

        -   Ping \[ip address\]

    -   **Netdiscover**

        -   Netdiscover --I eth0 --r 192.168.1.0/24

    -   **Nmap**

        -   Nmap --sn --n 192.168.1.0/24

-   **Port scaning :**

    -   **Port scanner tools**

        -   **Hping , fping**

        -   **Nmap / zenmap**

        -   **Unicorn scan**

            -   unicornscan -H -msf -Iv 192.168.56.101 -p 1-65535

            -   unicornscan -H -mU -Iv 192.168.56.101 -p 1-65535

            -   Arguments :

                -   -H resolve hostnames during the reporting phase

                -   -m scan mode (sf - tcp, U - udp)

                -   -Iv - verbose

        -   **Masscan**

        -   **Solarwinds port Scanner**

    -   **Port Scanning Techniques**

        -   **Full Tcp Scan**

        -   **Stealth Scan**

            -   **Syn scan (half open scan)**

            -   **Fin Scan**

            -   **Null Scan**

            -   **Xmas scan**

        -   **Ack Scan**

        -   **Mainmon Scan**

        -   **Udp Scan**

        -   **Idle Scan**

-   **Version Scanning :** determine the version of services and protocols

    -   Nmap --sV \[ip address\]

-   **OS Fingerprinting**

    -   **Passive Fingerprinting :** know os of the target without interaction with him (sniffing)

        -   **Pof**

        -   **Satori**

        -   **Network minor**

    -   **Active Fingerprinting :** know os of the target by interacting with him

        -   **Banner grabbing**

            -   Nc \[ip\] \[port\]

            -   Ncat \[ip\] \[port\]

            -   telnet \[ip\] \[port\]

        -   **nmap**

            -   nmap --O \[ip address\]

        -   **xprobe2**

            -   xprobe2 -v -p tcp:80:open \[IP\]

-   **Vulnerability Scanning**

    -   **Network Vulnerability Scanners**

        -   **Nessus**

            -   dpkg -i Nessus-6.9.4-debian6\_amd64.deb

            -   /etc/init.d/nessusd start

            -   https://localhost:8834/

        -   **Openvas**

            -   Apt install openvas

            -   Openvas-setup

            -   http://localhost:9392

        -   **Nexpose**

        -   **Acunetix**

        -   **Netsparker**

    -   **Web Vulnerability Scanners**

        -   **Nikto**

            -   Nikto --h \[site\]

            -   Nikto --maxtime=30s    -\> limit the scan time because it takes a lot of time

        -   **W3af**

        -   **Vega**

        -   **Wapiti**

        -   **Skipfish**

        -   **Zed attack proxy (zap)**

        -   **sqlmap**

        -   **CMS Vulnerability Scanners**

            -   **Wpscan**

                -   wpscan \--url \[website\]    	
 
                    -   -\> to get info and possible vulnerabilities of the website

                -   wpscan \--url \[website\]  \--enumerate u   

                    -   -\> to get the username of wp-panel

                -   wpscan \--url \[website\] \--passwords passwd.txt \--usernames \[user found\]   
  
                    -   -\> bruteforce to get the password
					  

	    -   **joomscan**

    		-   joomscan -u \[website\]

    		-   joomscan -u \[website\]\--enumerate-components


-   **Network Tracing :** determine the network topology and draw a map

-   **Dns Scanning & Enumeration**

    -   **Host**

        -   Host [\[domain\]

        -   Host --t { ns,mx,soa,A,AAAA,txt,any } \[domain\]

        -   Host --a \[domain\]      			 -\> -a = -V --t any

        -   Host --a -v [\[domain\]    			-\> -v = -d = verbose

        -   Host 8.8.8.8 				-\> reverse dns lookup

        -   Host --l \[hostname\] \[name server\]        -\> dns zone transfer

    -   **Nslookup**

        -   nslookup [\[domain\]

        -   nslookup [\[domain\] \[Nameserver\] 	-\> using specific dns server

        -   nslookup --query={any,mx,ns,soa} [\[domain\]

        -   nslookup \[ip\] 				-\> reverse dns lookup

        -   nslookup -timeout=10 [\[domain\] 		-\> change default timeout to wait for reply

        -   nslookup --debug \[domain\]

    -   **Dig**

        -   Dns Query

            -   dig google.com {A\|AAAA\|NS\|MX\|CNAME\|ANY} +noall +answer

            -   dig \@8.8.8.8 \[Domain\] A +norecurse

        -   Zone Transfer

            -   dig \[domain\] NS

            -   Dig @\[nameserver\] \[domain\] axfr -\>try with all name server founds

    -   **dnsrecon**

        -   dnsrecon -d microsoft.com -t axfr

        -   dnsrecon -d \[domain\] -t axfr

-   **SSl scanning**

    -   **Sslyze**

        -   sslyze \--regular [www.example.com]

    -   **Sslscan**

        -   Sslscan \[website\]

    -   **Nmap**

        -   nmap \--script ssl-enum-ciphers -p \[port\] \[hostname\]

    -   **tls-scan**

        -   tls-scan -c [\[website\] \--all \--pretty

    -   **Testssl.sh**

        -   *git clone --depth 1* <https://github.com/drwetter/testssl.sh.git>

        -   *./testssl.sh \[website\]*

    -   [**https://pentest-tools.com/network-vulnerability-scanning/ssl-tls-scanner**](https://pentest-tools.com/network-vulnerability-scanning/ssl-tls-scanner)

    -   **Ssllabs.com**

-   **Websites Crawling**

    -   Zap

    -   Burp suite

-   **Directory Bruteforcing**

    -   **Dirbuster**

    -   **Gobuster**

        -   gobuster -w /usr/share/wordlists/dirb/common.txt -u \[ip\]

    -   **Dirb**

        -   dirb [http://example.com] -r -o output.txt

    -   **Dirsearch**

        -   git clone https://github.com/maurosoria/dirsearch.git

        -   ./dirsearch.py -u [\[website\]](http://hostname.com) -e {aspx,php,...}

        -   ./dirsearch.py -u [\[website\]](http://hostname.com) -e php --r -\> run recursively

        -   ./dirsearch.py -u [\[website\]](http://hostname.com) -e php  --x 403,404 --r -\> exclude certain http response code

    -   **Wfuzz**

        -   wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt \$ip:60080/?FUZZ=test 

        -   wfuzz -c \--hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt \$ip:60080/?page=FUZZ 

        -   wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  \"\$ip:60080/?page=mailer&mail=FUZZ\"

    -   **ffuf**

        -   apt install golang

        -   git clone <https://github.com/ffuf/ffuf.git>

        -   ffuf -w /usr/share/wordlists/dirbuster/directory-list.txt -u https//:target/FUZZ -\>by using FUZZ keyword

-   **Subdomain Bruteforcing**

    -   **Sublist3r**

        -   git clone https://github.com/aboul3la/Sublist3r

        -   cd Sublist3r

        -   pip install -r requirements.txt

        -   python sublist3r.py -v -d \[website\] -o result.txt

    -   **Knokpy**

        -   Knockpy.py \[website\]

        -   Knockpy.py \[website\] -w subdomains.txt

    -   **Subfinder**

        -   apt-get install golang

        -   git clone https://github.com/subfinder/subfinder

        -   go get github.com/subfinder/subfinder

        -   cd subfinder

        -   go build

        -   ./subfinder -d example.com -o result2.txt

    -   **Subbrute**

        -   python subbrute.py \[website\]

    -   **Amass**

        -   https://github.com/OWASP/Amass/releases

        -   unzip amass\_v3.1.9\_linux\_amd64.zip

        -   cd amass\_v3.1.9\_linux\_amd64

        -   ./amass enum \--passive -d example.com -o result1.txt

    -   **NMMAPPER.COM -\>** using Anubis, Amass, DNScan, Sublist3r,Lepus, Censys, etc

    -   **Dnsdumpster.com**

    -   **Google dorks**

        -   Ex : site:example.com -www.example.com

    -   **Combine all the result in one file**

        -   cat result1 result2 result3 \> results.txt

        -   cat results.txt \| tr \"\[A-Z\]\" \"\[a-z\]\" \| sort -u \] FinalResult.txt

-   **Mysql port 3306 open**

    -   **local**

        -   mysql -u root 	 -\> Connect to root without password

        -   mysql -u root -p     -\> A password will be asked 

    -   **remote**

        -   mysql -h \<Hostname\> -u root

        -   mysql -h \<Hostname\> -u root\@localhost

    -   **Enumeration**

        -   **Metasploit**

            -   msf\> use auxiliary/scanner/mysql/mysql\_version

            -   msf\> use uxiliary/scanner/mysql/mysql\_authbypass\_hashdump

            -   msf\> use auxiliary/scanner/mysql/mysql\_hashdump 	-\> Creds

            -   msf\> use auxiliary/admin/mysql/mysql\_enum 		-\> Creds

            -   msf\> use auxiliary/scanner/mysql/mysql\_schemadump     -\> Creds

            -   msf\> use exploit/windows/mysql/mysql\_start\_up  -\>Execute commands Windows, Creds

        -   **Nmap**

            -   nmap -sV -Pn -vv -script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122  \[ip\] -p 3306

    -   **MySQL important commands**

        -   show databases;

        -   use \[database name\]

        -   show tables;

        -   select \* from \[table\_name\]

        -   mysqldump -u root -p Password123! \--all-databases \> db\_backup.sql    	-\> dump all databases


-   **Nfs port 2049 open**

    -   NFS stands for Network File System and provides a way to mount remote file systems as if they were local to the system. The NFS service generally runs on port 2049.

    -   To know which folder has the server available to mount you an ask it using:

        -   showmount -e INSERTIPADDRESS

    -   If you found any shared directory you can mount it by

        -   mount -t nfs \[-o vers=2\] \[ip\]:\[remote\_folder\] \[local\_folder\] -o nolock

        -   Example :

            -   mkdir /mnt/new\_back

            -   mount -t nfs \[-o vers=2\] 10.12.0.150:/backup /mnt/new\_back -o nolock

-   **Other Tools**

    -   **sparta**

    -   **Wireshark**

    -   **Tcpdump**

    -   **Ncat**

    -   **Netcat**

    -   **Socat**

    -   **Powercat**


- <h2 align="center"> Nmap  </h2>

    -   **Nmap timing**

        -   T0 : paranoid ( intrusion Detection System evasion)

        -   T1 : sneaky ( intrusion Detection System evasion)

        -   T2 : polite ( slows down the scan to use less bandwidth and use less target machine resources)

        -   T3 : normal default

        -   T4 : agressive

        -   T5 : insame

            -     Ex : nmap -sX -p- 192.168.1.4 -T4


    -   **Target specification**

        -   nmap 192.168.1.1   			-\>  scan a target

        -   nmap 192.168.1.1 192.168.2.1  	-\> scan multiple targets

        -   nmap 192.168.1.0/24    		-\>scan with cidr

        -   nmap 192.168.1.1-255    		-\> scan range of addresses

        -   nmap [nmap.domain.org](http://nmap.domain.org)    -\> Scan a domain

        -   nmap -iL targets.txt        -\> scan targets from a file WITH IP addresses

        -   nmap 192.168.1.0/24 \--excludefile hosts.txt    -\> exclude ip addresses from file

    -   **Port specification**

        -   nmap 192.168.1.1 -p 21 		-\>scan single port

        -   nmap 192.168.1.1 -p 21,23,24 	-\>scan multiple ports

        -   nmap 192.168.1.1 -p 21-50 		-\>scan range of ports

        -   nmap 192.168.1.1 -p U:53,T:21-25,80   -\> Port scan multiple TCP and UDP ports

        -   nmap 192.168.1.1 -p- 		-\>scan all 65535 ports

        -   nmap 192.168.1.1 -p http,https 	-\> scan ports by name

        -   nmap 192.168.1.1 \--top-ports 2000          -\> Port scan the top x ports

        -   nmap 192.168.1.1 -F                -\> fast port scan (100 ports)

    -   **Host Discovery**

        -   nmap 192.168.1.1-3 --sL -\> No Scan. List targets only

        -   nmap 192.168.1.1-3 --sn -\> No Scan. List targets only

        -   nmap 192.168.1.1-3 --pn -\> Disable host discovery. Port scan only.

        -   nmap 192.168.1.1-3 --pr -\>arp discovery on local network

        -   nmap 192.168.1.1-5 --PA 22-25,80 -\> TCP Ack discovery on port x , port 80 by default

        -   nmap 192.168.1.1-5 --PS 22-25,80 -\> TCP SYN discovery on port x. , port 80 by default

        -   nmap 192.168.1.1-3 --n -\>no dns resolution

        -   nmap 192.168.1.1-1/24 -PR -sn -vv   -\> Arp discovery only on local network, no port scan

    -   **Saving Outpout**

        -   nmap -oA outputfile 192.168.1.1    -\>all formats

        -   nmap -oG outputfile 192.168.1.1  -\>grepable format

        -   nmap -oX outputfile 192.168.1.1    -\>xml format

        -   nmap -oN outputfile 192.168.1.1    -\>txt format

        -   nmap 192.168.3.5 \] outfile

    -   **Firewall Evasion**

        -   nmap 192.168.1.1 -f    -\>use tiny fragmented IP packets. Harder for packet filters

        -   nmap 192.168.1.1 \--mtu \[size\]    -\> Set your own offset size

        -   nmap -D decoy-ip1,decoy-ip2,decoy-ip3,decoy-ip4 remote-host-ip   -\>send scanfrom spoof ips

        -   nmap -S \[spoof ip\]   192.168.1.1     -\>use spoof ip rather than your ip

        -   nmap \--data-length 200 192.168.1.1     -\>append random data to packets

        -   nmap  192.168.1.1  \--badsum

        -   Ex :nmap -f -t 0 -n -Pn --data-length 200 -D
            192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23   192.168.1.1

    -   **Service & os detection**

        -   nmap -sO 192.168.1.1 \--osscan-guess -\> Guess OS more aggressively

        -   nmap -sO 192.168.1.1 \--osscan-Limit    

        -   nmap -sV 192.168.1.1

        -   nmap  -sV \--version-intensity 5 192.168.1.1    -\> More aggressive Service Detection  Intensity level range 0 to 9  Higher number increases possibility of correctness

        -   nmap  -sV \--version-all 192.168.1.1          -\>Enable intensity level 9. Higher possibility of correctness. Slower

        -   nmap  -sV \--version-intensity 0 192.168.1.1

        -   nmap 172.16.1.1 -sV \--version-light           -\>intensity level = 2

        -   nmap -A 192.168.1.1

        -   nmap 192.168.1.1 \--reason   -\> Display the reason a port is in a particular state, same as -vv

        -   nmap 192.168.1.1 \--open     -\>show only open ports

    -   **Nmap scripting engine**     

        -   **Scripts location**

            -    ls /usr/share/nmap/scripts/ 

        -   **Categories of scripts (nse) -\>** written in lua

            -   vuln : look for a given vuln in the target

            -   Default : run this set of scripts when -sC or -A without specefiying a category

            -   Version : detect the version of target s services

            -   Safe

            -   Malware

            -   Exploit :exploit  a discovered  vulnerability 

            -   External

            -   Brute : make a brute force authentication attempts

            -   Discovery

            -   Fuzzer : sending a lot of data to target system to crash a service to find buffer overflow vuln 

            -   Auth : test for issues associated with authentication

            -   Broadcast

            -   dos : may cause denial of service

            -   Intrusive

    -   **Examples**

        -   nmap \[ip\] -sC    -\> -sC = = \--script=default

        -   nmap \--script=vuln \[ip\]    -\>will run all scripts in vuln category

        -   /usr/share/nmap/scripts/smb\*   -\>search all scripts related to smb

        -   nmap \--script smb-enum-users \[ip\]

        -   nmap -v -p 139,445 \--script=smb-os-discovery \[ip\]     -\> os discovery and enum via smb

        -   /usr/share/nmap/scripts/nfs\*     -\>search all scripts to nfs enum

        -   nmap -p 111 \--script nfs\* 10.11.1.72   -\>run all scripts with for nfs

        -   nmap -p53 -sV \--script dns-zone-transfer zonetransfer.me

        -   nmap -p80 -sV \--script http-robots.txt 8.8.8.8

        -   nmap -p80 -sV \--script http-vuln-\* 192.168.1.1

        -   nmap -p21 -sV \--script ftp-anon 192.168.1.1

        -   nmap -p21 -sV \--script ftp-vsftpd-backdoor 192.168.100.6

        -   nmap -p139,445 -sV \--script smb-os-discovery 192.168.1.1

        -   nmap -p139,445 -sV \--script smb-vuln\* 192.168.100.18

        -   nmap -p139,445 -sV \--script smb-check-vulns \--script-args unsafe=1 192.168.1.243

        -   nmap -sV -p 443 \--script=ssl-heartbleed 192.168.1.0/24

        -   nmap -sV IP\_ADDRESS -oX scan.xml && xsltproc scan.xml -o \"\`date +%m%d%y\`\_report.html\" 

            -   -\> generating a nice report

<h2 align="center">Masscan </h2>

<p align="center">"Fastest port scanner can scan the whole internet in 6 mins " </p>

-   **port specification**

    -   masscan 10.11.0.0/16 -p443    -\> simple port scan

    -   masscan 10.11.0.0/16 -p443,80,52    -\> multiple port scan

    -   masscan 10.11.0.0/16 -p22-25    -\> range of ports

    -   masscan 10.11.0.0/16 ‐‐top-ports 100    -\> scan top ports

    -   masscan 10.11.0.0/16 --p 0-65535 ----rate 1000000    -\> scan all ports in network

-   **scan rate**

    -   By default, masscan scans at a rate of 100 packets per second

    -   masscan 10.11.0.0/16 ‐‐top-ports 100 ----rate 100000

    -   masscan 0.0.0.0/0 -p443 ----rate 10000000  -\> scan the whole internet for a specific port

    -   masscan 0.0.0.0/0 -p0-65535 ----rate 10000000  -\>  scan the whole internet for all ports

-   **Saving Result**

    -   masscan 10.11.0.0/16 ‐‐top-ports 100 ‐‐echo \> scan.txt

    -   masscan 10.11.0.0/16 ‐‐top-ports 100 \] scan.txt

    -   masscan 10.11.0.0/16 ‐‐top-ports 100  -oX result.xml

-   **Other options**

    -   masscan 10.11.0.0/16 ‐‐top-ports 100 \--exclude=10.11.0.5 \--max-rate 100000

        -   -\> exclude ips out of scan

    -   masscan 10.11.0.0/16 ‐‐top-ports 10 \--excludefile exclude.txt \--max-rate 100000

        -   -\> exclude ips from file out of scan

    -   masscan -iL ips-online.txt \--rate 10000 -p1-65535 \--only-open -oL masscan.out

        -   -\> scan ips from a file

    -   masscan -e eth0 -p1-65535,U:1-65535 10.10.10.97 \--rate 1000

        -   -\> specify the interface + udp scan


<h2 align="center">ENUMERATION</h2>

-   **Snmp Enum (port 161 , 162)**

    -   **Notes** :

        -   use snmp protocol to enumerate (if the user use snmp in his network) .Community strings are passwords there are 2 types of community strings read only , read & write . 

        - Snmp default Communities (passwords) :

            - community , public , private , manager , cisco
        
        - Snmp MIB Trees
        
            - 1.3.6.1.2.1.25.1.6.0 System Processes
            - 1.3.6.1.2.1.25.4.2.1.2 Running Programs
            - 1.3.6.1.2.1.25.4.2.1.4 Processes Path
            - 1.3.6.1.2.1.25.2.3.1.4 Storage Units
            - 1.3.6.1.2.1.25.6.3.1.2 Software Name
            - 1.3.6.1.4.1.77.1.2.25 User Accounts
            - 1.3.6.1.2.1.6.13.1.3 TCP Local Ports


    -   **snmpenum**

        -   snmpenum -t 192.168.1.5

    -   **Snmpwalk**

        -   snmpwalk -v1 -c public 192.168.1.244

        -   snmpwalk -v1 -c public 192.168.1.244 iso.3.6.1.2.1.1.5.0

    -   **Onesixtyone**

        -   onesixtyone -c community.txt 192.168.1.244

        -   onesixtyone -c community.txt -i ips.txt

    -   **Snmpset**

        -   snmpset -v1 -c private 10.0.2.10 iso.3.6.1.2.1.1.5.0 s Hacked

    -   **Snmp-check**

        -   snmpcheck -t 192.168.1.5 -c public

    -   **Metasploit**

        -   use auxiliary/scanner/snmp/snmp\_enum

        -   auxiliary/scanner/snmp/snmp_enum_hp_laserjet

        -   auxiliary/scanner/snmp/snmp_enumshares

        -   auxiliary/scanner/snmp/snmp_enumusers

        -   auxiliary/scanner/snmp/snmp_login


    -   **Nmap**

        -   nmap -p 161 --script=snmp-info [ip]



-   **Smtp Enum (port 25) or pop3 (port 110)**

    -   **Smtp commands**

        -   **HELO** -- This is the command that the client sends to the server to initiate a conversation. Generally, the IP address
            or domain name must accompany this command, such as HELO 192.168.101 or HELO  [client.microsoft.com](http://client.microsoft.com/).

        -   **EHLO** -- This command is the same as HELO, but communicates to the server that the client wants to use
            Extended SMTP. If the server does not offer ESMTP, it will still recognize this command and reply appropriately.

        -   **STARTTLS** -- Normally, SMTP servers communicate in plaintext. To improve security, the connection between SMTP
            servers can be encrypted by TLS (Transport Layer Security). This command starts the TLS session.

        -   **RCPT** -- Specifies the email address of the recipient.

        -   **DATA** -- Starts the transfer of the message contents.

        -   **RSET** -- Used to abort the current email transaction.

        -   **MAIL** -- Specifies the email address of the sender.

        -   **QUIT** -- Closes the connection.

        -   **HELP** -- Asks for the help screen.

        -   **AUTH** -- Used to authenticate the client to the server.

        -   **VRFY** -- Asks the server to verify is the email user's mailbox exists.

    -   **Smtp-user-enum**

        -   smtp-user-enum -M VRFY -U users.txt -t 192.168.1.104

    -   **With "smtp-enum" module in metasploit**

    -   **VERIFY users manually with telnet/nc**

        -   telnet 192.168.1.104 25 or nc 192.168.1.104 25

        -   VRFY \[user\]

        -   USER \[user\]

        -   EXPN \[user\]

    -   **Nmap**

        -   nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25

    -   **Metasploit**

        -   auxiliary/scanner/smtp/smtp_enum

        -   auxiliary/scanner/smtp/smtp_ntlm_domain

        -   auxiliary/scanner/smtp/smtp_relay

        -   auxiliary/scanner/smtp/smtp_version 


-   **Smb & Netbios Enum (port 135 , 139 , 445)**

    “Samba is a Linux implementation of SMB”

    -   **Nmblookup**

        -   Used to query NetBIOS names and map them to IP addresses in a network using NetBIOS
        -   nmblookup -A 192.168.1.103

    -   **Nbttscan**

        -   This is a command utility that tries to scan NetBIOS name servers open on a local or remote TCP/IP network and because it is a first step in finding open shares. It is created on the functionality of the Windows standard tool “nbtstat”,

        -   nbtscan 192.168.1.0/24 -\> who run smb

    -   **Smbclient**

        -   smbclient is a client that can ‘talk’ to an SMB/CIFS server. It offers an interface similar to that of the FTP program. It can upload/download files from and to smb server, retrieving directory information from the server and so on.  List shares …etc

        -   **List shares**

            -   smbclient -L 192.168.01.13

            -   smbclient -U TestUser -L 192.168.0.70

        -   **Access shares**

            -   smbclient //192.168.0.70/tmp

            -   smbclient -U TestUser //192.168.0.70/tmp    -> linux share

            -   smbclient –U user \\\\192.168.1.10\\share   -> windows share

    -   **Smbmap**

        -   Same as smbclient allows us to enumerate samba share drives across an entire domain.{ List shares, list drive permissions, share contents, upload/download functionality }

        -   **List shares**

            -   smbmap -H 192.168.0.34

            -   smbmap -u TestUser -p TestPass -H 192.168.0.34

    -   **Nmap**

        -   nmap --script smb-vuln* -p 139,445 [ip]

        -   nmap -p139,445 \[ip address\]

        -   nmap -p139,445 --script smb-enum-users \[ip address\]

        -   nmap -p139,445 --script smb-enum-users --script-args=unsafe=1 \[ip address\]

    -   **Metasploit**

        -   auxiliary/scanner/smb/psexec_loggedin_users

        -   auxiliary/scanner/smb/smb_enumshares

        -   auxiliary/scanner/smb/smb_enumusers

        -   auxiliary/scanner/smb/smb_enumusers_domain

        -   auxiliary/scanner/smb/smb_login

        -   auxiliary/scanner/smb/smb_lookupsid

        -   auxiliary/scanner/smb/smb_ms17_010

        -   auxiliary/scanner/smb/smb_version


-   **User Enum via smb(samba)**

    -   **Rpcclient**

        -   Depending on the host configuration, the RPC endpoint mapper can be accessed through TCP and UDP port 135 (msrpc) or , via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593

        -   rpcclient is a utility initially developed to test MS-RPC functionality in Samba itself.

        -   rpcclient -U \"\" -N 10.0.2.4 -\> null session

        -   rpcclient -U \"test\" 10.0.2.4 -\> session with user

            -   rpcclient\> srvinfo

            -   rpcclient\> enumdomusers  -> get username as well as their rid

            -   rpcclient\> getdompwinfo

            -   rpcclient\> querydominfo

            -   rpcclient\> enumalsgroups domain

            -   rpcclient\> lookupnames administrators

            -   rpcclient\> enumprivs

            -   rpcclient\> queryuser user 

    -   **Enum4linux**

        -   is a tool for enumerating information from Windows and linux os that have Samba(SMB) working on their hosts . It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net, and nmblookup  (no interaction only enum)

        -   can list users , shares , passwords policies , domain and group memberships

        -   enum4linux -{U\|S\|P\|G} 10.0.2.4

        -   enum4linux -a 10.0.2.4  -> run all scans

        -   enum4linux -{U\|S\|P\|G} -u TestUser -p TestPass 192.168.100.200

-   **Dns Enum**

    -   **Dnsenum**

        -   Dnsenum \[domain\]

        -   Dnsenum --enum \[domain\]

    -   **Dnswalk**

        -   Dnswalk \[doamain.\] -\> dot in the end of the domain

        -   dnswalk -adilrfFm \[domain.\]

    -   **Fierce**

        -   Fierce --dns \[domain\]

        -   Fierce --dns \[domain\] --threads 10 -\>default = 1

    -   **Dnstracer**

        -   Dnstracer \[domain\]

    -   **Dnsmap**

        -   Dnsmap \[domain\]

    -   **Dnsrecon**

        -   Dnsrecon --d \[domain\]

        -   Dnsrecon --d \[domain\] -a

-   **Ldap Enum**

    -   **Nmap**

        -   nmap -n -sV \--script \"ldap\* and not brute\" \[IP\] -\>Using anonymous credentials

    -   **Ldapsearch**

        -   ldapsearch -x -h \[IP\] -D \'\[DOMAIN\]\\\[username\]\' -w
            \'\[password\]\' -b \"CN=Users,DC=\[1\_SUBDOMAIN\],DC=\[TDL\]\" -\> extract users

        -   ldapsearch -x -h \[IP\] -D \'\[DOMAIN\]\\\[username\]\' -w
            \'\[password\]\' -b  \"CN=Computers,DC=\[1\_SUBDOMAIN\],DC=\[TDL\]\" -\> extract computers

        -   ldapsearch -x -h \[IP\] -D \'\[DOMAIN\]\\\[username\]\' -w
            \'\[password\]\' -b \"DC=\<1\_SUBDOMAIN\>,DC=\[TDL\]\"

            -   -x Simple Authentication

            -   -h LDAP Server

            -   -D My User

            -   -w My password

            -   -b Base site, all data from here will be given

-   **Ntp Enum :** The Network Time Protocol (**NTP**) is a networking protocol for clock synchronization between computer systems over
    packet-switched,

    -   **Ntptrace**

    -   **Ntpdc**

        -   ntpdc -n --c monlist \[IP or hostname of time server\]

    -   **Ntpq**

        -   ntpq -c readlist \[ip\_address\]

        -   ntpq -c readvar \[ip\_address\]

        -   ntpq -c monlist \[ip\_address\]

        -   ntpq -c peers \[ip\_address\]

        -   ntpq -c listpeers \[ip\_address\]

        -   ntpq -c associations \[ip\_address\]

        -   ntpq -c sysinfo \[ip\_address\]


-   **AUTORECON.PY : automate scanning tools**

    -   Git clone https://github.com/Tib3rius/AutoRecon.git

    -   **{** use enum4linux, gobuster,nbtscan,nikto,nmap,onesixtyone,oscanner,smbclient,smbmap,smtp-user-enum,snmpwalk,sslscan,svwar,tnscmd10g,whatweb,wkhtmltoimage
        ,...**}**

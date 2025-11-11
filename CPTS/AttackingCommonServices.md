# Attacking Common Services

## FTP

 FTP is a standard network protocol used to transfer files between computers. It also performs directory and files operations, such as changing the working directory, listing files, and renaming and deleting directories or files. By default, FTP listens on port TCP/21.

 <img width="1028" height="479" alt="image" src="https://github.com/user-attachments/assets/d1beaa08-8e4f-4d20-95af-049d8eb96718" />
 sudo nmap -sC -sV -p 21 <ip>

### Anonymous Authentication 
<img width="999" height="379" alt="image" src="https://github.com/user-attachments/assets/08c09bc8-2814-4216-bc2f-d84e23af539d" />
ftp <ip>

### Brute Forcing (Medusa)

<img width="1031" height="236" alt="image" src="https://github.com/user-attachments/assets/20d29559-af7e-4e98-8726-769b0ee32977" />

medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h <ip> -M ftp

### FTP Bounce Attack

A Network Attack which uses FTP servers to send outbound traffic to another device within the network (internal DMZ is not exposed) but we can use FTP_DMZ server to scan Internal_DMZ using the FTP Bounce attack and obtain information about the server's open ports.

<img width="1022" height="430" alt="image" src="https://github.com/user-attachments/assets/063af451-48d3-4995-82aa-d3961d2f08c3" />

nmap -Pn -v -n -p80 -b anonymous:password@1<ip> 172.17.0.2

Question:

What port is the FTP service running on?

Answer:

Using the nmap command, change the -p flag to '-p-' to scan all ports on the machine:
sudo nmap -sC -sV -p- <ip>

<img width="974" height="279" alt="image" src="https://github.com/user-attachments/assets/b224a3cb-f88f-46c2-af30-72c431dafe2d" />

Unfortunately the service runs on an uncommon port so it is painfully slow but we find out it is running on port 2121

Question:

What username is available for the FTP server?

Answer: 

After using the following command:

frp <ip> -p 2121 we find out the user is: robin

Question:

Using the credentials obtained earlier, retrieve the flag.txt file. Submit the contents as your answer.

Answer: 

Using the medusa command: 

medusa -u robin -P /usr/share/wordlists/rockyou.txt -h <ip> -M ftp

HTB{ATT4CK1NG_F7P_53RV1C3}


## SMB

Server Message Block (SMB) is a communication protocol created for providing shared access to files and printers across nodes on a network. Initially, it was designed to run on top of NetBIOS over TCP/IP (NBT) using TCP port 139 and UDP ports 137 and 138. However, with Windows 2000, Microsoft added the option to run SMB directly over TCP/IP on port 445 without the extra NetBIOS layer. Nowadays, modern Windows operating systems use SMB over TCP but still support the NetBIOS implementation as a failover.

### Enumeration 

<img width="1018" height="471" alt="image" src="https://github.com/user-attachments/assets/f4ec5fef-8c65-4359-800d-7d90e59b4d15" />

Command:

sudo nmap <ip> -sV -sC -p139,445

 ### File share

 <img width="1077" height="278" alt="image" src="https://github.com/user-attachments/assets/00c28b9d-8554-4b5c-ad04-2cf2beefd25a" />

 Command:

 smbclient -N -L //<ip>


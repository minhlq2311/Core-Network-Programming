# Core-Network-Programming
This repository is about creating a ping packet, parseHTTP and parseDNS packet on Linux system
## 1. Create ping packet
This is a custom Ping program written in C, supporting two different methods:
- **Ping with Libnet**: Uses the `libnet` library to create and send ICMP packets.
- **Ping with Raw Socket**: Manually creates ICMP packets and sends them directly via raw sockets.

### 1.1. Requirements

#### 1.1.1. System
- **Linux** or **Unix-based OS** (Root privileges required for using raw sockets).
  
#### 1.1.2. Required Libraries
- **libnet-dev**: A library for network packet creation.
  
To install `libnet`, run the following command:

> sudo apt-get install libnet-dev

### 1.2. Directory Structure
- **ping_with_libnet.c    :**  Source code for ping using libnet
- **ping_with_raw_socket.c  :** Source code for ping using raw socket

### 1.3. Compile and Run program
**1. Ping with Libnet**

- **Compile**
To compile the ping_with_libnet.c program, use the following command:


> gcc -o ping_with_libnet ping_with_libnet.c -lnet

- **Run**
After successful compilation, to run the program, use:

> sudo ./ping_with_libnet [OPTIONS] [DESTINATION]

- **Options:**
  - -t: Ping continuously until Ctrl+C is pressed.
  - -a: Resolve the IP address to a hostname.
  - -n <count>: Send a fixed number of echo request packets.

- **Destination:** A hostname or an IP address

- **Examples:**
    Continuously ping google.com:
    > sudo ./ping_with_libnet -t google.com


**2. Ping with Raw Socket**

- **Compile**
To compile the ping_with_raw_socket.c program, use the following command:
> gcc -o ping_with_raw_socket ping_with_raw_socket.c

- **Run**
After successful compilation, to run the program, use:

> sudo ./ping_with_raw_socket [OPTIONS] [DESTINATION]

-  **Options:**
    -t: Ping continuously until Ctrl+C is pressed.
    -a: Resolve the IP address to a hostname.
    -n <count>: Send a fixed number of echo request packets.

- **Destination:** A hostname or an IP address

- **Examples:**
Continuously ping google.com:
> sudo ./ping_with_raw_socket -t google.com


## 2. ParseHTTP and Logging

This is a simple packet capture program using `libpcap` that captures and logs HTTP packets on a specific network interface. It extracts and logs key information from the captured HTTP packets, including MAC addresses, IP addresses, ports, and HTTP content such as headers and the body.

### 2.1. Features
- Capture HTTP packets on port 80.
- Log HTTP request/response headers such as Content-Type, Content-Length, Date, Last-Modified, etc.
- Log the packet timestamp, MAC addresses, IP addresses, port numbers, TCP sequence, and acknowledgment numbers.

### 2.2. Requirements

To build and run this program, you need **Libpcap** library installed on your system.

Run the following command to install libpcap:

  > sudo apt-get install libpcap-dev

### 2.3. Directory Structure
- parseHTTP.c : Source code for parseHTTP
- packet_log.txt: File log HTTP packet
- request_with_3way_libnet.c: Source code if you want to test HTTP request
### 2.4. Build
Open a terminal in the project directory and compile the program using the following command:

  > gcc parseHTTP.c -o parseHTTP -lpcap

### 2.5. Run
Make sure you have appropriate privileges (you might need sudo to run pcap programs).

> sudo ./parseHTTP [Network Interface]

You must specify the network interface that you want to sniff on. For example, to run the program on interface enp0s3, use the following command:

> sudo ./parseHTTP enp0s3

(You can use ifconfig or ip a s to list available interfaces).

The program will log packet details to the packet_log.txt file in the current directory. 

**Example**
: Capture packet on my network interface:

  > sudo ./parseHTTP enp0s3

Output:

Packet number 1:
Time: 2024-09-19 12:34:56
Source MAC: 00:1a:2b:3c:4d:5e
Destination MAC: 6f:7g:8h:9i:0j:1k
Source IP: 192.168.1.100
Destination IP: 93.184.216.34
Source Port: 54321
Destination Port: 80
Sequence number: 123456789
Acknowledge number: 987654321

HTTP content:
Status Line: HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234
Date: Wed, 19 Sep 2024 12:34:56 GMT
Last-Modified: Tue, 18 Sep 2024 10:15:30 GMT

Body:
< html> ... < /html>

End of packet

### 2.6. Cleanup and Shutdown
To stop the program, press Ctrl+C. The program will catch the interrupt signal and shutdown by closing the pcap handle and the log file.

## 3. ParseDNS and Logging

The program displays detailed information about DNS packets, including answer records, authoritative records, and additional records. Other information is similar to parseHTTP program.

### 3.1. Requirements
 The same as requirements for parseHTTP program 

### 3.2. Directory Structure
- parseDNS.c: Source code for parseDNS
- dnsHeader.h: Header file containing necessary structure definitions for the program.
- dns_log.txt: File log DNS packet
- dns_libnet.c: Source code if you want to test DNS query

### 3.3. Build

To compile the program, use the following command in the terminal:

> gcc -o parseDNS parseDNS.c -lpcap

### 3.4. Run

Similar to parseHTTP
Make sure you have appropriate privileges (you might need sudo to run pcap programs).

> sudo ./parseDNS [Network Interface]

You must specify the network interface that you want to sniff on. For example, to run the program on interface enp0s3, use the following command:

> sudo ./parseDNS enp0s3

(You can use ifconfig or ip a s to list available interfaces).


The program will log packet details to the dns_log.txt file in the current directory.

### 3.5. Cleanup and Shutdown

Same as cleanup and shutdown for parseHTTP, press Ctrl+C to stop the program. 
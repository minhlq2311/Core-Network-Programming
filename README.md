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

```bash
sudo apt-get install libnet-dev
```
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
    Continuously ping google.com and resolve the IP to hostname:
    > sudo ./ping_with_libnet -t -a google.com


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
Continuously ping google.com and resolve the IP to hostname:
> sudo ./ping_with_raw_socket -t -a google.com





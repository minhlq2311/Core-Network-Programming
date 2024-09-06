# Libnet
- [Libnet](#libnet)
  - [1. Introduction](#1-introduction)
  - [2. Installing Libnet](#2-installing-libnet)
  - [3. Key Concepts](#3-key-concepts)
  - [4. Key Features](#4-key-features)
  - [5. Use Cases](#5-use-cases)
  - [6. Usage](#6-usage)
  - [7. Example Use Cases](#7-example-use-cases)
  - [8. Note](#8-note)
  - [9. References](#9-references)

## 1. Introduction 
Libnet is a low-level network library that enables developers to build and inject network packets. It provides a flexible API for crafting various types of packets at different layers of the network protocol stack, making it suitable for use in network testing, attack simulations, and protocol research. 
It is widely used for writing tools that need to generate custom network traffic, such as packet crafting, manipulation, and injection.

## 2. Installing Libnet
Libnet can be installed through package managers or by compiling from source. Since this project work on Linux, it can be installed by:
> sudo apt-get update
> sudo apt-get install libnet1-dev


## 3. Key Concepts

- Libnet Context: Every Libnet operation needs a context that manages the state of the packet crafting process.
- Packet Buffers: Libnet provides buffers for holding the packet data that will be sent.
- Network Layers: Libnet handles multiple layers (Link, Network, Transport), allowing for full control over packet creation.

## 4. Key Features
- **Support for multiple protocols:** Libnet supports a variety of protocols, including Ethernet, ARP, IP, ICMP, TCP, UDP, and more.
- **Packet crafting:** Provides high-level APIs to build and inject custom packets.
- **Easy-to-use:** Abstracts complex operations like checksum calculation and header manipulation.
- **Cross-platform support:** Works on Unix-like operating systems (Linux, BSD) and Windows with proper adaptations.

## 5. Use Cases

- **Custom your own packet:** Can custom your network based on API that libnet provided.
- **Network scanning and analysis:** Used to send custom crafted packets to discover open ports, analyze network protocols, or conduct penetration testing.
- **Protocol development and testing:** Allows developers to create custom network protocols and test them by sending and receiving raw packets.
- **Security research:** Employed in crafting malicious packets for vulnerability testing, simulating denial-of-service (DoS) attacks, and crafting exploits.


## 6. Usage

**6.1. Creating a Libnet Context**
A context is required for Libnet to operate. It stores data about the network interface, error messages, and other states.

```c
#include <libnet.h>

libnet_t *l;
char errbuf[LIBNET_ERRBUF_SIZE];

l = libnet_init(LIBNET_RAW4, "eth0", errbuf);
if (l == NULL) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
}
LIBNET_RAW4: Specifies that we want to work with raw IP version 4 packets.
"eth0": The network interface to send packets from.
errbuf: Buffer to hold error messages.
```

**6.2. Building and Injecting Packets**

To create a packet, Libnet offers different API functions based on the layer being worked on.

**Example: Building an ICMP Echo Request (Ping)**

```c
libnet_ptag_t icmp_tag;

icmp_tag = libnet_build_icmpv4_echo(
    ICMP_ECHO,   // Type
    0,           // Code
    0,           // Checksum (Libnet calculates this automatically)
    1,           // ID
    0,           // Sequence number
    NULL,        // Payload (None in this case)
    0,           // Payload size
    l,           // Libnet context
    0            // Protocol tag (0 means new packet)
);

if (icmp_tag == -1) {
    fprintf(stderr, "Failed to build ICMP header: %s\n", libnet_geterror(l));
}
```

**6.3. Handling Network Layers**
Libnet can construct packets at any layer of the OSI model. For example, you can combine the ICMP layer with an IP header:

```c
libnet_ptag_t ip_tag;

ip_tag = libnet_build_ipv4(
    LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,  // Total length
    0,             // Type of service
    0,             // Identification
    0,             // Fragment offset
    64,            // Time to live
    IPPROTO_ICMP,  // Protocol (ICMP)
    0,             // Checksum (Calculated by Libnet)
    libnet_name2addr4(l, "192.168.1.1", LIBNET_DONT_RESOLVE),  // Source IP
    libnet_name2addr4(l, "8.8.8.8", LIBNET_DONT_RESOLVE),      // Destination IP
    NULL,          // Payload
    0,             // Payload size
    l,             // Libnet context
    0              // Protocol tag
);
```
**6.4. Sending packet**
```c
int bytes_written = libnet_write(l);
if (bytes_written == -1) {
    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
    exit(EXIT_FAILURE);
}
printf("%d bytes written.\n", bytes_written);
```

**6.5 Release resources**
```c
libnet_destroy(l);
```

## 7. Example Use Cases
**Crafting an ICMP Echo Request (Ping)**
```c
#include <libnet.h>

int main() {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);

    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return 1;
    }

    libnet_ptag_t icmp = libnet_build_icmpv4_echo(
        ICMP_ECHO, 0, 0, 1, 0, NULL, 0, l, 0
    );

    if (icmp == -1) {
        fprintf(stderr, "libnet_build_icmpv4_echo() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    libnet_ptag_t ip = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, 
        0, 
        0, 
        0, 
        64,
        IPPROTO_ICMP, 
        0, 
        libnet_name2addr4(l, "192.168.0.2", LIBNET_DONT_RESOLVE), 
        libnet_name2addr4(l, "8.8.8.8", LIBNET_DONT_RESOLVE), 
        NULL, 
        0, 
        l, 
        0
    );

    if (ip == -1) {
        fprintf(stderr, "libnet_build_ipv4() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    int bytes_written = libnet_write(l);
    if (bytes_written == -1) {
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
    } else {
        printf("Packet sent: %d bytes\n", bytes_written);
    }

    libnet_destroy(l);
    return 0;
}
```
## 8. Note
**1. Compile**
- When using GCC or any other C compiler, you need to link the Libnet library using the -lnet flag.
> gcc your_program.c -o your_program -lnet

**2.Access Right:**
- To run any program that uses Libnet, you need to execute it as a root user or with sudo:

> sudo ./your_program

## 9. References
- [Libnet API Documentation](https://codedocs.xyz/libnet/libnet/libnet-functions_8h.html#a5829f525c067e1d99826865292542d8a)
- [Libnet API UNIX Network Programming, Volume 1 - W. Richard Stevens](https://putregai.org/books/unix_netprog_v1.pdf)
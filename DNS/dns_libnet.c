#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnet.h>

#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20
#define SOURCE_IP "10.0.2.15"
#define DEST_IP "8.8.8.8"
#define SOURCE_PORT 12345
#define DEST_PORT 80

// Ensure this file exists and contains necessary definitions
#include "/home/minhlq2311/Documents/Core Net 2.0/packet_header.h"

void formatDomainName(unsigned char *dns, char *host) {
    int lock = 0, i;
    strcat(host, ".");
    for(i = 0 ; i < strlen(host) ; i++) {
        if(host[i] == '.') {
            *dns++ = i-lock;
            for(; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int createDnsQuery(libnet_t *l, int srcPort, int destPort, char *domainName){
    unsigned char dns_formatted_name[256];
    formatDomainName(dns_formatted_name, (unsigned char *)domainName);
    int dnsQueryLen = strlen((char *)dns_formatted_name) + 1;
    
    // ADD type A record and class IN
    uint16_t qtype = htons(1);  // A record
    uint16_t qclass = htons(1); // IN class
    memcpy(dns_formatted_name + dnsQueryLen, &qtype, 2);
    memcpy(dns_formatted_name + dnsQueryLen + 2, &qclass, 2);
    dnsQueryLen += 4;

    libnet_ptag_t dns_tag = libnet_build_dnsv4(
        LIBNET_DNS_H, // Length
        libnet_get_prand(LIBNET_PRu16), // ID
        0x0100, // Flags
        1, // Number of questions
        0, // Number of answers
        0, // Number of authority
        0, // Number of additional
        (char *)dns_formatted_name, // Query
        dnsQueryLen, // Query length (including QTYPE and QCLASS)
        l, // Libnet context
        0 // Ptag
    );
    if (dns_tag == -1) {
        fprintf(stderr, "Can't build DNS header: %s\n", libnet_geterror(l));
        return -1;
    }

    libnet_ptag_t udp_tag = libnet_build_udp(
        srcPort, // Source port
        destPort, // Destination port
        LIBNET_UDP_H + LIBNET_DNS_H + dnsQueryLen, // Length
        0, // Checksum
        NULL, // Payload
        0, // Payload length
        l, // Libnet context
        0 // Ptag
    );
    if (udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        return -1;
    }

    libnet_ptag_t ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + dnsQueryLen, // Length
        0, // TOS
        libnet_get_prand(LIBNET_PRu16), // ID
        0, // Fragmentation
        64, // TTL
        IPPROTO_UDP, // Protocol
        0, // Checksum
        inet_addr(SOURCE_IP), // Source IP
        inet_addr(DEST_IP), // Destination IP
        NULL, // Payload
        0, // Payload length
        l, // Libnet context
        0 // Ptag
    );
    if (ip_tag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        return -1;
    }

    return 0;
}

int main(){
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if(l == NULL){
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    char *domainName = malloc(100);
    if (domainName == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Enter domain name: ");
    scanf("%99s", domainName); // read directly into domainName

    int srcPort = 12345;
    int destPort = 53;

    if (createDnsQuery(l, srcPort, destPort, domainName) != 0) {
        free(domainName);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    int bytes_written = libnet_write(l);
    if(bytes_written < 0){
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
        free(domainName);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
    printf("Sent DNS query\n");

    free(domainName);
    libnet_destroy(l);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include<libnet.h>

#define unsgined char u_char;

int main() {
    libnet_t *l;
    libnet_ptag_t ipTag, icmpTag;
    char errbuf[LIBNET_ERRBUF_SIZE];  

    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if(l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    char *data = "Hello";
    int dataLen = strlen(data);
     
    char *srcIp = "10.0.2.15";
    char *destIp = "8.8.8.8";

    icmpTag = libnet_build_icmpv4_echo(
        ICMP_ECHO, // type
        0,  // code
        0, // checksum 
        12345, // ID
        0,  // sequence
        data, 
        dataLen, 
        l, //libnet context
        0 //ptag
    );

    if (icmpTag == -1) {
        fprintf(stderr, "Error building ICMP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    ipTag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + dataLen, 
        0,  //TOS
        54321, //ID
        0,  // IP Frag
        64, // TTl
        IPPROTO_ICMP, //Protocol
        0, //Checksum
        inet_addr(srcIp), 
        inet_addr(destIp), 
        NULL, //Payload
        0, // Payload size
        l, //libnet context
        0 //ptag
    );

    if(ipTag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        exit(EXIT_FAILURE);
    }

    int bytesWritten = libnet_write(l);
    if(bytesWritten == -1) {
        fprintf(stderr, "Write failed: %s\n", libnet_geterror(l));
    } else {
        printf("%d bytes written\n", bytesWritten);
    }

    libnet_destroy(l);
}

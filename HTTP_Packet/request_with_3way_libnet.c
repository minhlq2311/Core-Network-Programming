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
#define DEST_IP "93.184.215.14"
#define SOURCE_PORT 12345
#define DEST_PORT 80

libnet_ptag_t tcp_tag, ip_tag;
struct sockaddr_in src, dst;

void threeWayHandshake(int sockFd, libnet_t *l, uint32_t seq_num, uint32_t ack_num) {
    // Create SYN packet
    tcp_tag = libnet_build_tcp(
        SOURCE_PORT,         
        DEST_PORT,            
        seq_num,              // Sequence number
        0,                    // ACK number
        TH_SYN,               // Flags
        32768,                // Window size
        0,                    // Checksum
        0,                    // Urgent pointer
        LIBNET_TCP_H,         // TCP header length
        NULL,                 // Payload
        0,                    // Payload length
        l,                    // Libnet context
        0                     // Ptag
    );

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,  // Header length
        0,                             // TOS
        libnet_get_prand(LIBNET_PRu16), // ID
        0,                             // Fragmentation
        64,                            // TTL
        IPPROTO_TCP,                   // Protocol
        0,                             // Checksum
        inet_addr(SOURCE_IP),          
        inet_addr(DEST_IP),            
        NULL,                          // Payload
        0,                             // Payload length
        l,                             // Libnet context
        0                              // Ptag
    );

    int bytes_written = libnet_write(l);
    if (bytes_written < 0) {
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
    printf("Sent SYN packet\n");

    // Receive SYN-ACK packet
    char buffer[4096];
    socklen_t len = sizeof(struct sockaddr_in);
    if(recvfrom(sockFd, buffer, sizeof(buffer), 0, (struct sockaddr *)&dst, &len) < 0) {
        perror("Receive failed");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    struct ip *iph = (struct ip *)buffer;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + IP_HEADER_SIZE);
    if(tcph->syn == 1 && tcph->ack == 1) {
        printf("Received SYN-ACK packet\n");

        // Create and send ACK packet
        uint32_t ack_num = ntohl(tcph->seq) + 1;
        tcp_tag = libnet_build_tcp(
            SOURCE_PORT,         
            DEST_PORT,            
            seq_num + 1,          // Sequence number
            ack_num,              // ACK number
            TH_ACK,               // Flags
            32768,                // Window size
            0,                    // Checksum
            0,                    // Urgent pointer
            LIBNET_TCP_H,         // TCP header length
            NULL,                 // Payload
            0,                    // Payload length
            l,                    // Libnet context
            tcp_tag               // Ptag
        );

        ip_tag = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,  // Header length
            0,                             // TOS
            libnet_get_prand(LIBNET_PRu16), // ID
            0,                             // Fragmentation
            64,                            // TTL
            IPPROTO_TCP,                   // Protocol
            0,                             // Checksum
            inet_addr(SOURCE_IP),          
            inet_addr(DEST_IP),            
            NULL,                          // Payload
            0,                             // Payload length
            l,                             // Libnet context
            ip_tag                         // Ptag
        );

        bytes_written = libnet_write(l);
        if (bytes_written < 0) {
            fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }
        printf("Sent ACK packet, completing 3-way handshake\n");
    } else {
        printf("Unexpected packet received\n");
    }
}

void createHTTPRequest(int sockFd, libnet_t *l, uint32_t seq_num, uint32_t ack_num) {   
    // Send HTTP request after 3-way handshake
    char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    int dataLen = strlen(data);

    tcp_tag = libnet_build_tcp(
        SOURCE_PORT,              // Source port
        DEST_PORT,                // Destination port
        seq_num + 1,              // Sequence number
        ack_num,                  // ACK number
        TH_PUSH | TH_ACK,         // Flags
        32767,                    // Window size
        0,                        // Checksum
        0,                        // Urgent pointer
        LIBNET_TCP_H + dataLen,   // Header length
        data,                     // Payload
        dataLen,                  // Payload length
        l,                        // Libnet context
        tcp_tag                   // Using previous libnet context
    );

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + dataLen,  // Header length
        0,                                      // TOS
        libnet_get_prand(LIBNET_PRu16),          // ID
        0,                                      // Fragmentation
        64,                                     // TTL
        IPPROTO_TCP,                            // Protocol
        0,                                      // Checksum
        inet_addr(SOURCE_IP),                   // Source IP
        inet_addr(DEST_IP),                     // Destination IP
        NULL,                                   // Payload
        0,                                      // Payload length
        l,                                      // Libnet context
        ip_tag                                  // Using previous libnet context
    );

    int bytes_written = libnet_write(l);
    if (bytes_written == -1) {
        fprintf(stderr, "Write failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
    printf("Sent HTTP GET request\n");
}

int main() {
    // Create raw socket
    int sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockFd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Create libnet context
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    u_int32_t seqNum = libnet_get_prand(LIBNET_PRu32);

    threeWayHandshake(sockFd, l, seqNum, 0);
    createHTTPRequest(sockFd, l, seqNum, 0);
    
    libnet_destroy(l);
    close(sockFd);
    return 0;
}
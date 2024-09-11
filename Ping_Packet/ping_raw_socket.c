#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <ifaddrs.h>

#define ICMP_HEADER_SIZE 8
#include "../packet_header.h"

int sockFd;
int isHost = -1;

// Calculate checksum for ICMP header
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    unsigned short result;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Check if a string is a valid IP address
int is_ip_address(const char *str) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, str, &(sa.sin_addr));
    if(result != 0) {
        isHost = 0;
        return 1;
    }
    return 0; // Return 0 if not a valid IP address
}

// Create ICMP header
void createIcmpHeader(struct icmpHeader *icmp_hdr, int seq, int dataLen) {
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_chksum = 0;
    icmp_hdr->id = htons(12345);
    icmp_hdr->seq = htons(seq);
    icmp_hdr->icmp_chksum = checksum((unsigned short *)icmp_hdr, dataLen + ICMP_HEADER_SIZE);
}

// Print usage instructions
void print_usage() {
    printf("Usage: ping [-t] [-a] [-n count] destination\n");
    printf("Options:\n");
    printf("  -t\t\tPing the specified host until stopped.\n");
    printf("  -a\t\tResolve addresses to hostnames.\n");
    printf("  -n count\tNumber of echo requests to send.\n");
}

// Parse command line arguments
void parse_args(int argc, char *argv[], int *continuous, int *resolveIpToHost, int *count, char **destIp) {
    int opt;
    while ((opt = getopt(argc, argv, "tan:")) != -1) {
        switch (opt) {
            case 't':
                *continuous = 1;
                break;
            case 'a':
                *resolveIpToHost = 1;
                break;
            case 'n':
                *count = atoi(optarg);
                break;
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    *destIp = argv[optind];
}

// Resolve hostname to IP address
char *resolve_hostname(const char *hostname) {
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        fprintf(stderr, "Could not resolve hostname: %s\n", hostname);
        exit(EXIT_FAILURE);
    }
    return inet_ntoa(*(struct in_addr *)he->h_addr_list[0]);
}

// Send ICMP packet
void send_icmp(int sockFd, struct icmpHeader *icmp, const char *data, int dataLen, int sequence, const char *srcIp, const char *destIp) {
    createIcmpHeader(icmp, sequence, dataLen);

    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0; // ICMP doesn't use port numbers
    destAddr.sin_addr.s_addr = inet_addr(destIp);

    if (sendto(sockFd, icmp, dataLen + ICMP_HEADER_SIZE, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) <= 0) {
        perror("Sendto failed");
        exit(EXIT_FAILURE);
    }
}

// Receive ICMP response
void receive_icmp_response(int sockFd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buf[1024];
    
    int bytesReceived = recvfrom(sockFd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len);
    if (bytesReceived > 0) {
        struct ipHeader *ipHeader = (struct ipHeader *)buf;
        int ipHeaderLen = ipHeader->iph_ihl * 4;

        struct icmpHeader *icmp= (struct icmpHeader *)(buf + ipHeaderLen);
        int icmpHeaderLen = sizeof(struct icmpHeader);
        int icmpDataLen = bytesReceived - ipHeaderLen - icmpHeaderLen;

        if (icmp->icmp_type == ICMP_ECHOREPLY) {
            printf("Reply from %s: bytes=%d TTL=%d\n", inet_ntoa(addr.sin_addr), icmpDataLen, ipHeader->iph_ttl);
        } else {
            printf("Received ICMP packet of type %d\n", icmp->icmp_type);
        }
    } else {
        printf("Request timed out.\n");
    }
}

// Resolve IP address to hostname
char *resolve_ip_to_hostname(const char *ip_addr) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr, &sa.sin_addr);
    
    char host[1024];
    char service[20];
    
    int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0);
    
    if (res != 0) {
        return NULL;  // Cannot resolve
    }
    
    return strdup(host);  // Copy the resolved hostname
}

// Main function
int main(int argc, char *argv[]) {
    int continuous = 0, resolveIpToHost = 0, count = 4;
    char *destIp = NULL;
    int sequence = 0;
    int pings_sent = 0;
    char *data = "Hello";
    int dataLen = strlen(data);
    
    // Parse command-line arguments
    parse_args(argc, argv, &continuous, &resolveIpToHost, &count, &destIp);
    
    char *finalDestIp;
    
    // Determine if destination is IP or hostname
    if (is_ip_address(destIp)) {
        finalDestIp = destIp;
        if (resolveIpToHost) {
            printf("Pinging %s [%s] with %d bytes of data\n", resolve_ip_to_hostname(destIp), destIp, dataLen);
        } else {
            printf("Pinging %s with %d bytes of data\n", destIp, dataLen);
        }
    } else {
        isHost = 1;
        finalDestIp = resolve_hostname(destIp);
        printf("Pinging %s [%s] with %d bytes of data\n", destIp, finalDestIp, dataLen);
    }
    
    sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockFd < 0) {
        perror("Socket error");
        return 1;
    }

    struct icmpHeader icmp;
    while (continuous || pings_sent < count) {
        send_icmp(sockFd, &icmp, data, dataLen, sequence, NULL, finalDestIp);
        receive_icmp_response(sockFd);

        pings_sent++;
        sequence++;
        sleep(1);
    }

    // Release resources
    close(sockFd);
    return 0;
}

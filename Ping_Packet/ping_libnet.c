#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <libnet.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>

#define MAX_PINGS 100

int running = 1;

// Check if a string is a valid IP address
int is_valid_ip(const char *ip_str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr)) != 0;
}

// Create ICMP header
void createIcmpHeader(libnet_t *l, char *data, int dataLen, int sequence) {
    libnet_ptag_t icmpTag;
    icmpTag = libnet_build_icmpv4_echo(
        ICMP_ECHO, // type
        0,  // code
        0, // checksum 
        12345, // ID
        sequence,  // sequence
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
}

// Create IP header
void createIpheader(libnet_t *l, int dataLen, char *srcIp, char *destIp) {
    libnet_ptag_t ipTag;
    ipTag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + dataLen, 
        0,  //TOS
        54321, //ID
        0,  // IP Frag
        64, // TTL
        IPPROTO_ICMP, // Protocol
        0, // Checksum
        inet_addr(srcIp), 
        inet_addr(destIp), 
        NULL, // Payload
        0, // Payload size
        l, // libnet context
        0 // ptag
    );
    if (ipTag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        exit(EXIT_FAILURE);
    }
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
void parse_args(int argc, char *argv[], int *continuous, int *resolveHost, int *count, char **destIp) {
    int opt;
    while ((opt = getopt(argc, argv, "tan:")) != -1) {
        switch (opt) {
            case 't':
                *continuous = 1;
                break;
            case 'a':
                *resolveHost = 1;
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
void send_icmp(libnet_t *l, const char *data, int dataLen, int sequence, const char *srcIp, const char *destIp) {
    createIcmpHeader(l, (char *)data, dataLen, sequence);
    createIpheader(l, dataLen, (char *)srcIp, (char *)destIp);

    int bytesWritten = libnet_write(l);
    if (bytesWritten == -1) {
        fprintf(stderr, "Write failed: %s\n", libnet_geterror(l));
    } else {
        printf("Sent %d bytes to %s\n", bytesWritten, destIp);
    }
}

// Receive ICMP response
void receive_icmp_response(int sockfd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buf[1024];
    
    int bytesReceived = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len);
    if (bytesReceived > 0) {
        struct ip *ipHeader = (struct ip *)buf;
        struct icmphdr *icmpHeader = (struct icmphdr *)(buf + (ipHeader->ip_hl << 2));

        if (icmpHeader->type == ICMP_ECHOREPLY) {
            printf("Received ICMP echo reply from %s\n", inet_ntoa(addr.sin_addr));
        } else {
            printf("Received ICMP packet of type %d\n", icmpHeader->type);
        }
    } else {
        printf("Request timed out.\n");
    }
}

// Main function
int main(int argc, char *argv[]) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    
    int continuous = 0, resolveHost = 0, count = 4;
    char *destIp = NULL;
    int sockfd;
    int sequence = 0;
    int pings_sent = 0;
    char *data = "Hello";
    int dataLen = strlen(data);
    char srcIp[16] = "10.0.2.15"; // My IP address, replace with your own

    parse_args(argc, argv, &continuous, &resolveHost, &count, &destIp);

    if (resolveHost && !is_valid_ip(destIp)) {
        destIp = resolve_hostname(destIp);
        printf("Resolved %s to %s\n", argv[optind], destIp);
    }

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    while (running && (continuous || pings_sent < count)) {
        send_icmp(l, data, dataLen, sequence, srcIp, destIp);
        receive_icmp_response(sockfd);

        pings_sent++;
        sequence++;
        sleep(1);
    }
    // Release resources
    libnet_destroy(l);
    close(sockfd);
    return 0;
}

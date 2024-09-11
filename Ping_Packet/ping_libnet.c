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
#include <ifaddrs.h>

int isHost = -1;

// Get the first Ip address of the network interface
char* get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char *ip_addr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            ip_addr = malloc(INET_ADDRSTRLEN);
            if (ip_addr == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip_addr, INET_ADDRSTRLEN);
            if (strcmp(ifa->ifa_name, "lo") != 0) { // Avoid using loopback interface
                break;
            }
            free(ip_addr);
            ip_addr = NULL;
        }
    }
    freeifaddrs(ifaddr);
    return ip_addr;
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
void parse_args(int argc, char *argv[], int *continuous, int *resoleIpTohost, int *count, char **destIp) {
    int opt;
    while ((opt = getopt(argc, argv, "tan:")) != -1) {
        switch (opt) {
            case 't':
                *continuous = 1;
                break;
            case 'a':
                *resoleIpTohost = 1;
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

// Send ICMP packet
void send_icmp(libnet_t *l, const char *data, int dataLen, int sequence, const char *srcIp, const char *destIp) {
    libnet_clear_packet(l);
    createIcmpHeader(l, (char *)data, dataLen, sequence);
    createIpheader(l, dataLen, (char *)srcIp, (char *)destIp);

    int bytesWritten = libnet_write(l);
    if (bytesWritten == -1) {
        fprintf(stderr, "Write failed: %s\n", libnet_geterror(l));
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
        int ipHeaderLen = ipHeader->ip_hl * 4;

        struct icmphdr *icmpHeader = (struct icmphdr *)(buf + ipHeaderLen);
        int icmpHeaderLen = sizeof(struct icmphdr);
        int icmpDataLen = bytesReceived - ipHeaderLen - icmpHeaderLen;

        if (icmpHeader->type == ICMP_ECHOREPLY) {
            printf("Reply from %s: bytes=%d TTL=%d\n", inet_ntoa(addr.sin_addr), icmpDataLen, ipHeader->ip_ttl);
        } else {
            printf("Received ICMP packet of type %d\n", icmpHeader->type);
        }
    } else {
        printf("Request timed out.\n");
    }
}

// Check if a string is an IP address or hostname
int is_ip_address(const char *str) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, str, &(sa.sin_addr));
    if(result != 0) {
        isHost = 0;
        return 1;
    }
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

// Resolve IP address to hostname
char *resolve_ip_to_hostname(const char *ip_addr) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr, &sa.sin_addr);
    
    char host[1024];
    char service[20];
    
    int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0);
    if (res != 0) {
        return NULL;  // Cant resolve
    }
    
    return strdup(host);  // Copy the resolved hostname
}

int main(int argc, char *argv[]) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    
    int continuous = 0, resoleIpTohost = 0, count = 4;
    char *destIp = NULL;
    int sequence = 0;
    int pings_sent = 0;
    char *data = "Hello";
    int dataLen = strlen(data);

    char *srcIp = get_local_ip(); // Get the first IP address of the network interface

    parse_args(argc, argv, &continuous, &resoleIpTohost, &count, &destIp);
    char *finalDestIp;
    
    // If enter hostname, resolve it to IP
    if(!is_ip_address(destIp)){
        isHost = 1;
        finalDestIp = resolve_hostname(destIp);
    }

    // If enter IP address
    if(isHost == 0){
        if(resoleIpTohost){
            printf("Pinging %s [%s] with %d bytes of data\n", resolve_ip_to_hostname(destIp), destIp, dataLen);
        }
        else{
            printf("Pinging %s with %d bytes of data\n", destIp, dataLen);
        }
    }
        
    // If enter hostname
    else{
        printf("Pinging %s [%s] with %d bytes of data\n", destIp, finalDestIp, dataLen);
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    // Loop until Ctrl C if -t flag is set and until count if -n or -a flag is set
    while (continuous || pings_sent < count) {
        if(isHost == 0){
            send_icmp(l, data, dataLen, sequence, srcIp, destIp);
        }
        else{
            send_icmp(l, data, dataLen, sequence, srcIp, finalDestIp);
        }
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

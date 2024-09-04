#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define DNS_HEADER_SIZE 12

#define SOURCE_IP "10.0.2.15"
#define DEST_IP "8.8.8.8"
#define SOURCE_PORT 12345
#define DEST_PORT 53

// DNS header structure
struct dns_header {
    unsigned short id;       // Identification
    unsigned short flags;    // Flags
    unsigned short q_count;  // Number of questions
    unsigned short ans_count;// Number of answers
    unsigned short auth_count;// Number of authority RRs
    unsigned short add_count; // Number of additional RRs
};

// UDP pseudo header structure
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to format domain name for DNS query
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

// Function to create IP header
void createIpHeader(struct iphdr *iph, int data_len) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(IP_HEADER_SIZE + UDP_HEADER_SIZE + data_len);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(SOURCE_IP);
    iph->daddr = inet_addr(DEST_IP);

    iph->check = checksum((unsigned short *) iph, IP_HEADER_SIZE);
}

// Function to create UDP header
void createUdpHeader(struct udphdr *udph, int data_len) {
    udph->source = htons(SOURCE_PORT);
    udph->dest = htons(DEST_PORT);
    udph->len = htons(UDP_HEADER_SIZE + data_len);
    udph->check = 0;
}

// Function to create DNS header
void createDnsHeader(struct dns_header *dnsh) {
    dnsh->id = htons(0x1234);
    dnsh->flags = htons(0x0100); // Standard query
    dnsh->q_count = htons(1);    // 1 question
    dnsh->ans_count = 0;
    dnsh->auth_count = 0;
    dnsh->add_count = 0;
}

// Function to calculate UDP checksum with pseudo header
unsigned short calculateUdpChecksum(struct pseudo_header *psh, struct udphdr *udph, int data_len) {
    int psize = sizeof(struct pseudo_header) + UDP_HEADER_SIZE + data_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *) psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, UDP_HEADER_SIZE + data_len);

    unsigned short checksum_value = checksum((unsigned short *) pseudogram, psize);
    free(pseudogram);
    return checksum_value;
}

// Main function to create and send DNS query
int main() {
    int sock;
    struct sockaddr_in dest;
    char packet[4096], *dns_data;
    struct iphdr *iph = (struct iphdr *) packet;
    struct udphdr *udph = (struct udphdr *) (packet + IP_HEADER_SIZE);
    struct dns_header *dnsh = (struct dns_header *) (packet + IP_HEADER_SIZE + UDP_HEADER_SIZE);
    struct pseudo_header psh;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    dest.sin_addr.s_addr = inet_addr(DEST_IP);

    memset(packet, 0, 4096);

    dns_data = packet + IP_HEADER_SIZE + UDP_HEADER_SIZE;
    char domain_name[100];
    printf("Enter domain name: ");
    scanf("%99s", domain_name);
    formatDomainName((unsigned char *) dns_data, domain_name);

    int dns_data_len = strlen((char *) dns_data) + 1 + 4; // +4 for QTYPE and QCLASS

    createIpHeader(iph, UDP_HEADER_SIZE + DNS_HEADER_SIZE + dns_data_len);
    createUdpHeader(udph, DNS_HEADER_SIZE + dns_data_len);
    createDnsHeader(dnsh);

    uint16_t qtype = htons(1);  // A record
    uint16_t qclass = htons(1); // IN class
    memcpy(dns_data + strlen((char *)dns_data) + 1, &qtype, 2);
    memcpy(dns_data + strlen((char *)dns_data) + 3, &qclass, 2);

    psh.source_address = inet_addr(SOURCE_IP);
    psh.dest_address = inet_addr(DEST_IP);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(UDP_HEADER_SIZE + DNS_HEADER_SIZE + dns_data_len);

    udph->check = calculateUdpChecksum(&psh, udph, DNS_HEADER_SIZE + dns_data_len);

    if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Sendto failed");
    } else {
        printf("DNS query sent\n");
    }

    close(sock);
    return 0;
}

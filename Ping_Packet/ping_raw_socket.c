#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

typedef unsigned char u_char;
typedef unsigned short u_short;

#include "packet_header.h"
// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(u_char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Create IP header
void createIpHeader(struct ipHeader *ip, char *srcIp, char *destIp, int dataLen){
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len = htons(sizeof(struct ipHeader) + sizeof(struct icmpHeader) + dataLen);
    ip->iph_ident = htons(54321);
    ip->iph_offset = 0;
    ip->iph_ttl = 255;
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_chksum = 0;
    ip->iph_sourceip.s_addr = inet_addr(srcIp);
    ip->iph_destip.s_addr = inet_addr(destIp);
    ip->iph_chksum = checksum((u_short *)ip, sizeof(struct ipHeader));  
}

// Create ICMP header
void createIcmpHeader(struct icmpHeader *icmp, int dataLen){
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->id = htons(12345);
    icmp->seq = htons(0);
    icmp->icmp_chksum = checksum((u_short *)icmp, sizeof(struct icmpHeader) + dataLen);
}

int main(){
    char buffer[1500] = {0};
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0){
        perror("Socket creation failed");
        exit(1);
    }

    char *srcIp= "10.0.2.15";
    char *destIp = "8.8.8.8";
    char *data = "Hello World";
    int dataLen = strlen(data);

    struct ipHeader *ip = (struct ipHeader *)buffer;
    struct icmpHeader *icmp = (struct icmpHeader *)(buffer + sizeof(struct ipHeader));

    createIpHeader(ip, srcIp, destIp, dataLen);
    createIcmpHeader(icmp, dataLen);

    // Format dest address
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->iph_destip.s_addr;

    // Send packet
    if(sendto(sockfd, buffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0){
        perror("Sendto failed");
        exit(1);
    }
    else{
        printf("Packet sent successfully\n");
    }

    close(sockfd);
    return 0;
}
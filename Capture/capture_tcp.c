#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <linux/if_ether.h> 

#define SIZE_ETHERNET 14
#include "packet_header.h"

int count = 1;
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    struct ethernetHeader *eth = (struct ethernetHeader *)packet;

    struct ipHeader *ip = (struct ipHeader *)(packet + SIZE_ETHERNET);

    size_t ip_len = (ip->iph_ihl) * 4;
    struct tcpHeader *tcp = (struct tcpHeader *)(packet + 14 + ip_len);

    size_t tcp_len = (tcp->tcph_offset) * 4;
    unsigned char payload = (unsigned char *)(packet + 14 + ip_len + tcp_len);

    printf("\nPacket number %d:\n", count++);

    printf("Source MAC: ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->src[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("Destination MAC: ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->dest[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("Source Port: %d\n", ntohs(tcp->tcph_srcport));
    printf("Destination Port: %d\n", ntohs(tcp->tcph_destport));

    int tcp_seq = ntohl(tcp->tcph_seqnum);
    printf("Sequence number: %d\n", tcp_seq);
    int tcp_ack = ntohl(tcp->tcph_acknum);
    printf("Acknowledge number: %d\n", tcp_ack);

    printf("\nEnd of packet\n");
}
int main(){
    char errbuf[PCAP_ERRBUF_SIZE];

    // Getting the network interface name
    char *dev = NULL;
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    // Open the session 
    pcap_t *handle = NULL;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    // Check if the device provides Ethernet headers
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // Get network number and mask 
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // Compile filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Apply filter
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Start capturing packets
    pcap_loop(handle, 4, got_packet, NULL);
}

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
#include "/home/minhlq2311/Documents/Core Net 2.0/packet_header.h"
#include "dnsHeader.h"

int packetCount = 1;

char *readName(unsigned char *reader, unsigned char *buffer, int *count);

void parseDnsPacket(unsigned char *buffer){
    struct dnsHeader *dns = (struct dnsHeader *)buffer;
    struct dnsRecord ans[10], auth[10], addit[10];
    struct QUESTION *qinfo = NULL;
    struct sockaddr_in a;

    unsigned char *reader, *qname;
    // Get value of the query name (under DNS format)
    qname = (unsigned char *)&buffer[sizeof(struct dnsHeader)];
    // Get the query type and class
    qinfo = (struct QUESTION *)&buffer[sizeof(struct dnsHeader) + (strlen((const char *)qname) + 1)];
    printf("Query type: %d\n", ntohs(qinfo->qtype));
    printf("Query class: %d\n", ntohs(qinfo->qclass));

    // Move past the query section
    dns = (struct dnsHeader *)buffer;
    reader = &buffer[sizeof(struct dnsHeader) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

    int i, j, stop;
    // Start reading answers
    for(i = 0; i < ntohs(dns->ansCount); i++) {
        ans[i].name = readName(reader, buffer, &stop);
        reader += stop;
 
        ans[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);
 
        if(ntohs(ans[i].resource->type) == 1) { // IPv4 address
            ans[i].rdata = (unsigned char*)malloc(ntohs(ans[i].resource->data_len));
 
            for(j = 0; j < ntohs(ans[i].resource->data_len); j++) {
                ans[i].rdata[j] = reader[j];
            }
 
            reader += ntohs(ans[i].resource->data_len);
        } else {
            ans[i].rdata = readName(reader, buffer, &stop);
            reader += stop;
        }
    }
 
    // Read authorities
    for(i = 0; i < ntohs(dns->authorCount); i++) {
        auth[i].name = readName(reader, buffer, &stop);
        reader += stop;
 
        auth[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);
 
        auth[i].rdata = readName(reader, buffer, &stop);
        reader += stop;
    }
 
    // Read additional
    for(i = 0; i < ntohs(dns->addCount); i++) {
        addit[i].name = readName(reader, buffer, &stop);
        reader += stop;
 
        addit[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type) == 1) {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j = 0; j < ntohs(addit[i].resource->data_len); j++) {
                addit[i].rdata[j] = reader[j];
            }
 
            reader += ntohs(addit[i].resource->data_len);
        } else {
            addit[i].rdata = readName(reader, buffer, &stop);
            reader += stop;
        }
    }
 
    // Print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ansCount));
    for(i = 0; i < ntohs(dns->ansCount); i++) {
        printf("Name : %s ", ans[i].name);
 
        if(ntohs(ans[i].resource->type) == 1) { // IPv4 address
            long *p = (long*)ans[i].rdata;
            a.sin_addr.s_addr = (*p); // working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        } else if(ntohs(ans[i].resource->type) == 5) {
            // Canonical name for an alias
            printf("has alias name : %s", ans[i].rdata);
        }
 
        printf("\n");
    }
 
    // Print authorities
    printf("\nAuthoritative Records : %d \n", ntohs(dns->authorCount));
    for(i = 0; i < ntohs(dns->authorCount); i++) {
        printf("Name : %s ", auth[i].name);
        if(ntohs(auth[i].resource->type) == 2) {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }
 
    // Print additional resource records
    printf("\nAdditional Records : %d \n", ntohs(dns->addCount));
    for(i = 0; i < ntohs(dns->addCount); i++) {
        printf("Name : %s ", addit[i].name);
        if(ntohs(addit[i].resource->type) == 1) {
            long *p = (long*)addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    struct ethernetHeader *eth = (struct ethernetHeader *)packet;

    struct ipHeader *ip = (struct ipHeader *)(packet + SIZE_ETHERNET);

    size_t ip_len = (ip->iph_ihl) * 4;
    struct udpHeader *udp = (struct udpHeader *)(packet + 14 + ip_len);

    size_t udp_len = 8;
    
    unsigned char *dns = (unsigned char *)(packet + 14 + ip_len + udp_len);

    printf("\nPacket number %d:\n", packetCount++);

    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("Source Port: %d\n", ntohs(udp->udph_srcport));
    printf("Destination Port: %d\n", ntohs(udp->udph_destport));
    printf("Length: %d\n", ntohs(udp->udph_len));

    parseDnsPacket(dns);
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
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
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
    char filter_exp[] = "udp port 53";
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
    pcap_loop(handle, 2, got_packet, NULL);
}

char *readName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
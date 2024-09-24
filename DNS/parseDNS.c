#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define SIZE_ETHERNET 14

int packetCount = 1;
FILE *log_file = NULL;
pcap_t *handle = NULL;

#include "dnsHeader.h"
char *readName(const unsigned char *reader, const unsigned char *buffer, int *count);
void parseDnsPacket(const unsigned char *buffer);
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

void cleanup(int signum) {
    printf("\nCaught signal %d, cleaning up...\n", signum);
    if (log_file != NULL) {
        fclose(log_file);
        printf("Log file closed.\n");
    }
    if (handle != NULL) {
        pcap_breakloop(handle);  // Stop pcap loop
        printf("Stopped pcap loop.\n");
    }
    exit(0);  // Exit the program safely
}

int main(int argc, char *argv[]){
    log_file = fopen("dns_log.txt", "w");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    // Getting the network interface name
    if(argc < 2){
        printf("Usage: parseDNS [interface]\n");
        return 1;
    }
    char *dev = argv[1];
    signal(SIGINT, cleanup);
    // Open the session 
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
    // The filter expression for DNS packets
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
    pcap_loop(handle, -1, got_packet, NULL);
}

char* readName(const unsigned char* reader,const unsigned char* buffer,int* count)
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
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up
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


void parseDnsPacket(const unsigned char *buffer){
    struct dnsHeader *dns = (struct dnsHeader *)buffer;
    struct dnsRecord ans[20], auth[20], addit[20];
    struct QUESTION *qinfo = NULL;
    struct sockaddr_in a;
    int stop = 0;

    const unsigned char *reader = buffer + sizeof(struct dnsHeader);

    // Read the query name
    unsigned char *qname = readName(reader, buffer, &stop);
    reader += stop;

    // Read the query info
    qinfo = (struct QUESTION*)reader;
    reader += sizeof(struct QUESTION);

    printf("Query Name: %s\n", qname);
    fprintf(log_file, "Query Name: %s\n", qname);
    printf("Query type: %d\n", ntohs(qinfo->qtype));
    fprintf(log_file, "Query type: %d\n", ntohs(qinfo->qtype));
    printf("Query class: %d\n", ntohs(qinfo->qclass));
    fprintf(log_file, "Query class: %d\n", ntohs(qinfo->qclass));

    int i, j;
    unsigned short type, data_len;

    // Start reading answers
    for(i = 0; i < ntohs(dns->ansCount); i++) {
        ans[i].name = readName(reader, buffer, &stop);
        reader += stop;

        ans[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);

        type = ntohs(ans[i].resource->type);
        data_len = ntohs(ans[i].resource->data_len);

        if (type == 1) { // IPv4 address
            ans[i].rdata = (unsigned char*)malloc(data_len);
            memcpy(ans[i].rdata, reader, data_len);
            reader += data_len;
        } else if (type == 5 || type == 2 || type == 15 || type == 6) {
            // CNAME, NS, MX, SOA
            ans[i].rdata = readName(reader, buffer, &stop);
            reader += stop;
        } else if (type == 28) {
            // IPv6 address
            ans[i].rdata = (unsigned char*)malloc(data_len);
            memcpy(ans[i].rdata, reader, data_len);
            reader += data_len;
        } else {
            // Other types, skip the data
            ans[i].rdata = NULL;
            reader += data_len;
        }
    }

    // Reading authoritative records
    for(i = 0; i < ntohs(dns->authorCount); i++) {
        auth[i].name = readName(reader, buffer, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);

        type = ntohs(auth[i].resource->type);
        data_len = ntohs(auth[i].resource->data_len);

        if (type == 2 || type == 6) { // NS or SOA
            auth[i].rdata = readName(reader, buffer, &stop);
            reader += stop;
        } else {
            auth[i].rdata = NULL;
            reader += data_len;
        }
    }

    // Reading additional records
    for(i = 0; i < ntohs(dns->addCount); i++) {
        // Check if the name is zero-length (root domain)
        if (*reader == 0) {
            addit[i].name = strdup("<Root>");
            reader++;
            stop = 1;
        } else {
            addit[i].name = readName(reader, buffer, &stop);
            reader += stop;
        }

        addit[i].resource = (struct R_DATA*)reader;
        reader += sizeof(struct R_DATA);

        type = ntohs(addit[i].resource->type);
        data_len = ntohs(addit[i].resource->data_len);

        if (type == 1) { // IPv4 address
            addit[i].rdata = (unsigned char*)malloc(data_len);
            memcpy(addit[i].rdata, reader, data_len);
            reader += data_len;
        } else if (type == 28) { // IPv6 address
            addit[i].rdata = (unsigned char*)malloc(data_len);
            memcpy(addit[i].rdata, reader, data_len);
            reader += data_len;
        } else if (type == 41) { // OPT Record
            // OPT record has a special structure
            addit[i].rdata = NULL;
            reader += data_len; // Skip the RDATA
        } else if (type == 6 || type == 2 || type == 15 || type == 5) {
            // SOA, NS, MX, CNAME
            addit[i].rdata = readName(reader, buffer, &stop);
            reader += stop;
        } else {
            // Other types, skip the data
            addit[i].rdata = NULL;
            reader += data_len;
        }
    }

    // Print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ansCount));
    for(i = 0; i < ntohs(dns->ansCount); i++) {
		type = ntohs(ans[i].resource->type);

        printf("Type: %d\n", type);
        fprintf(log_file, "Type: %d\n", type);

        printf("Name: %s ", ans[i].name);
        fprintf(log_file, "Name: %s ", ans[i].name); 

        if(type == 1) { // IPv4 address
            struct in_addr addr;
            memcpy(&addr, ans[i].rdata, sizeof(struct in_addr));
            printf("has IPv4 address : %s", inet_ntoa(addr));
            fprintf(log_file, "has IPv4 address : %s", inet_ntoa(addr));
        } else if(type == 5) {
            // Canonical name for an alias
            printf("has alias name: %s", ans[i].rdata);
            fprintf(log_file, "has alias name: %s", ans[i].rdata);
        } else if(type == 2) {
            // Name server
            printf("has nameserver: %s", ans[i].rdata);
            fprintf(log_file, "has nameserver: %s", ans[i].rdata);
        } else if(type == 28) {
            // IPv6 address
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ans[i].rdata, ipv6_str, sizeof(ipv6_str));
            printf("has IPv6 address: %s", ipv6_str);
            fprintf(log_file, "has IPv6 address: %s", ipv6_str);
        } else {
            printf("has unknown type");
            fprintf(log_file, "has unknown type");
        }

        printf("\n");
		fprintf(log_file, "\n");
    }

    // Print authoritative records
    printf("\nAuthoritative Records: %d\n", ntohs(dns->authorCount));
    for(i = 0; i < ntohs(dns->authorCount); i++) {
		type = ntohs(auth[i].resource->type);

        printf("Type: %d\n", type);
        fprintf(log_file, "Type: %d\n", type);

        printf("Name: %s ", auth[i].name);
        fprintf(log_file, "Name: %s ", auth[i].name);

        if(type == 2) { // NS record
            printf("has nameserver: %s", auth[i].rdata);
            fprintf(log_file, "has nameserver: %s", auth[i].rdata);
        } else if(type == 6) { // SOA record
            printf("has SOA: %s", auth[i].rdata);
            fprintf(log_file, "has SOA: %s", auth[i].rdata);
        } else {
            printf("has unknown type");
            fprintf(log_file, "has unknown type");
        }
        printf("\n");
		fprintf(log_file, "\n");
    }

    // Print additional records
    printf("\nAdditional Records : %d \n", ntohs(dns->addCount));
    for(i = 0; i < ntohs(dns->addCount); i++) {
		type = ntohs(addit[i].resource->type);

        printf("Type: %d\n", type);
        fprintf(log_file, "Type: %d\n", type);

        printf("Name: %s ", addit[i].name);
        fprintf(log_file, "Name: %s ", addit[i].name);

        if(type == 1) { // IPv4 address
            struct in_addr addr;
            memcpy(&addr, addit[i].rdata, sizeof(struct in_addr));
            printf("has IPv4 address: %s", inet_ntoa(addr));
            fprintf(log_file, "has IPv4 address: %s", inet_ntoa(addr));
        } else if(type == 28) { // IPv6 address
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, addit[i].rdata, ipv6_str, sizeof(ipv6_str));
            printf("has IPv6 address: %s", ipv6_str);
            fprintf(log_file, "has IPv6 address: %s", ipv6_str);
        } else if(type == 41) { // OPT Record
            // Extract OPT record details
            unsigned short opt_payload_size = ntohs(addit[i].resource->_class);
            unsigned char extended_rcode = (ntohl(addit[i].resource->ttl) >> 24) & 0xFF;
            unsigned char edns_version = (ntohl(addit[i].resource->ttl) >> 16) & 0xFF;
            // The Z field is in the lower 16 bits of TTL
            unsigned short z = ntohl(addit[i].resource->ttl) & 0xFFFF;

            printf("has OPT record: payload size %u, extended RCODE %u, EDNS version %u", opt_payload_size, extended_rcode, edns_version);
            fprintf(log_file, "has OPT record: payload size %u, extended RCODE %u, EDNS version %u", opt_payload_size, extended_rcode, edns_version);
        } else if(type == 6 || type == 2 || type == 15 || type == 5) {
            // SOA, NS, MX, CNAME
            printf("has data: %s\n", addit[i].rdata);
            fprintf(log_file, "has data: %s\n", addit[i].rdata);
        } else {
            printf("has unknown type");
            fprintf(log_file, "has unknown type");
        }
        printf("\n");
		fprintf(log_file, "\n");
    }

    // Free allocated memory
    free(qname);
    for(i = 0; i < ntohs(dns->ansCount); i++) {
        free(ans[i].name);
        if(ans[i].rdata != NULL)
            free(ans[i].rdata);
    }
    for(i = 0; i < ntohs(dns->authorCount); i++) {
        free(auth[i].name);
        if(auth[i].rdata != NULL)
            free(auth[i].rdata);
    }
    for(i = 0; i < ntohs(dns->addCount); i++) {
        free(addit[i].name);
        if(addit[i].rdata != NULL)
            free(addit[i].rdata);
    }
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    struct ether_header *eth = (struct ether_header *)packet;

    struct ip *ip = (struct ip *)(packet + SIZE_ETHERNET);

    size_t ip_len = ip->ip_hl * 4;
    struct udphdr *udp = (struct udphdr *)(packet + SIZE_ETHERNET + ip_len);

    size_t udp_len = 8;

    const unsigned char *dns = packet + SIZE_ETHERNET + ip_len + udp_len;

    printf("\nPacket number %d:\n", packetCount);
    fprintf(log_file, "\nPacket number %d:\n", packetCount);

    printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
    fprintf(log_file, "Source IP: %s\n", inet_ntoa(ip->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
    fprintf(log_file, "Destination IP: %s\n", inet_ntoa(ip->ip_dst));

    printf("Source Port: %d\n", ntohs(udp->uh_sport));
    fprintf(log_file, "Source Port: %d\n", ntohs(udp->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp->uh_dport));
    fprintf(log_file, "Destination Port: %d\n", ntohs(udp->uh_dport));
    printf("Length: %d\n", ntohs(udp->uh_ulen));
    fprintf(log_file, "Length: %d\n", ntohs(udp->uh_ulen));

    parseDnsPacket(dns);
    printf("\nEnd of packet\n");

    packetCount++;
    sleep(1);
}

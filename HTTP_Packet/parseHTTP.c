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

#include "packet_header.h"
#define SIZE_ETHERNET 14

int count = 1;
char *get_header_value(const char *response, const char *header_name) {
    char *header_start = strstr(response, header_name);
    if (header_start == NULL) {
        return NULL;
    }

    // Find start of content in header
    char *value_start = strstr(header_start, ": ");
    if (value_start == NULL) {
        return NULL;
    }

    // Skip ": " to get to the value
    value_start += 2;

    // Find end of header
    char *value_end = strstr(value_start, "\r\n");
    if (value_end == NULL) {
        return NULL;
    }

    // Length of content in header
    size_t value_length = value_end - value_start;

    // Store in a string
    char *header_value = (char *)malloc(value_length + 1);
    if (header_value == NULL) {
        perror("Malloc failed");
        exit(EXIT_FAILURE);
    }
    snprintf(header_value, value_length + 1, "%s", value_start);

    return header_value;
}

void parse_http_response(const char *response) {
    char *status_line_end = strstr(response, "\r\n");
    if (status_line_end == NULL) {
        printf("Invalid HTTP response: no status line found\n");
        return;
    }
    // Print status line
    printf("Status Line: %.*s\n", (int)(status_line_end - response), response);

    // Find some in4 about HTTP
    char *content_type = get_header_value(response, "Content-Type");
    if (content_type != NULL) {
        printf("Content-Type: %s\n", content_type);
        free(content_type);
    }
    char *content_length = get_header_value(response, "Content-Length");
    if (content_length != NULL) {
        printf("Content-Length: %s\n", content_length);
        free(content_length);
    }
    char *date = get_header_value(response, "Date");
    if (date != NULL) {
        printf("Date: %s\n", date);
        free(date);
    }
    char *last_modified = get_header_value(response, "Last-Modified");
    if (last_modified != NULL) {
        printf("Last-Modified: %s\n", last_modified);
        free(last_modified);
    }
    // Find body of HTTP response
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start != NULL) {
        body_start += 4;  // Skip "\r\n\r\n" to get to the body
        printf("Body:\n%s\n", body_start);
    } 
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    struct ethernetHeader *eth = (struct ethernetHeader *)packet;

    struct ipHeader *ip = (struct ipHeader *)(packet + SIZE_ETHERNET);

    size_t ip_len = (ip->iph_ihl) * 4;
    struct tcpHeader *tcp = (struct tcpHeader *)(packet + 14 + ip_len);

    size_t tcp_len = (tcp->tcph_offset) * 4;
    unsigned char *payload = (unsigned char *)(packet + 14 + ip_len + tcp_len);
    int payload_len = ntohs(ip->iph_len) - (ip_len + tcp_len);

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

    if(payload_len > 0){
        printf("\nHTTP content:\n");
        parse_http_response(payload);
    }
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

    // Open the session in promiscuous mode
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

    // Get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // Compile the filter expression
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Apply the compiled filter
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Start capturing packets
    pcap_loop(handle, 9, got_packet, NULL);
}

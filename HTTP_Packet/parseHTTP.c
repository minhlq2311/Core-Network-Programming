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
#include <time.h>  // Include time.h for timestamp

#include "/home/minhlq2311/Documents/CoreNetwork/Core-Network-Programming/packet_header.h"
#define SIZE_ETHERNET 14

int count = 1;
FILE *log_file = NULL;

char *get_header_value(const char *response, const char *header_name) {
    char *header_start = strstr(response, header_name);
    if (header_start == NULL) {
        return NULL;
    }

    char *value_start = strstr(header_start, ": ");
    if (value_start == NULL) {
        return NULL;
    }

    value_start += 2;
    char *value_end = strstr(value_start, "\r\n");
    if (value_end == NULL) {
        return NULL;
    }

    size_t value_length = value_end - value_start;
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
    printf("Status Line: %.*s\n", (int)(status_line_end - response), response);
    fprintf(log_file, "Status Line: %.*s\n", (int)(status_line_end - response), response);

    char *content_type = get_header_value(response, "Content-Type");
    if (content_type != NULL) {
        printf("Content-Type: %s\n", content_type);
        fprintf(log_file, "Content-Type: %s\n", content_type);
        free(content_type);
    }
    char *content_length = get_header_value(response, "Content-Length");
    if (content_length != NULL) {
        printf("Content-Length: %s\n", content_length);
        fprintf(log_file, "Content-Length: %s\n", content_length);
        free(content_length);
    }
    char *date = get_header_value(response, "Date");
    if (date != NULL) {
        printf("Date: %s\n", date);
        fprintf(log_file, "Date: %s\n", date);
        free(date);
    }
    char *last_modified = get_header_value(response, "Last-Modified");
    if (last_modified != NULL) {
        printf("Last-Modified: %s\n", last_modified);
        fprintf(log_file, "Last-Modified: %s\n", last_modified);
        free(last_modified);
    }

    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start != NULL) {
        body_start += 4;
        printf("Body:\n%s\n", body_start);
        fprintf(log_file, "Body:\n%s\n", body_start);
    } 
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[80];

    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_buffer, 80, "%Y-%m-%d %H:%M:%S", time_info);

    struct ethernetHeader *eth = (struct ethernetHeader *)packet;
    struct ipHeader *ip = (struct ipHeader *)(packet + SIZE_ETHERNET);
    size_t ip_len = (ip->iph_ihl) * 4;
    struct tcpHeader *tcp = (struct tcpHeader *)(packet + 14 + ip_len);
    size_t tcp_len = (tcp->tcph_offset) * 4;
    unsigned char *payload = (unsigned char *)(packet + 14 + ip_len + tcp_len);
    int payload_len = ntohs(ip->iph_len) - (ip_len + tcp_len);

    printf("\nPacket number %d:\n", count);
    printf("Time: %s\n", time_buffer);
    fprintf(log_file, "\nPacket number %d:\n", count);
    fprintf(log_file, "Time: %s\n", time_buffer);

    printf("Source MAC: ");
    fprintf(log_file, "Source MAC: ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->src[i]);
        fprintf(log_file, "%02x", eth->src[i]);
        if(i < 5){
            printf(":");
            fprintf(log_file, ":");
        }
    }
    printf("\n");
    fprintf(log_file, "\n");

    printf("Destination MAC: ");
    fprintf(log_file, "Destination MAC: ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->dest[i]);
        fprintf(log_file, "%02x", eth->dest[i]);
        if(i < 5){
            printf(":");
            fprintf(log_file, ":");
        }
    }
    printf("\n");
    fprintf(log_file, "\n");

    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("Source Port: %d\n", ntohs(tcp->tcph_srcport));
    fprintf(log_file, "Source Port: %d\n", ntohs(tcp->tcph_srcport));
    printf("Destination Port: %d\n", ntohs(tcp->tcph_destport));
    fprintf(log_file, "Destination Port: %d\n", ntohs(tcp->tcph_destport));

    int tcp_seq = ntohl(tcp->tcph_seqnum);
    printf("Sequence number: %d\n", tcp_seq);
    fprintf(log_file, "Sequence number: %d\n", tcp_seq);
    int tcp_ack = ntohl(tcp->tcph_acknum);
    printf("Acknowledge number: %d\n", tcp_ack);
    fprintf(log_file, "Acknowledge number: %d\n", tcp_ack);

    if(payload_len > 0){
        printf("\nHTTP content:\n");
        fprintf(log_file, "\nHTTP content:\n");
        parse_http_response(payload);
    }
    else {
        if(tcp -> tcph_flags & TH_SYN && tcp -> tcph_flags & TH_ACK) {
            printf("\nThis is SYN-ACK packet\n");
            fprintf(log_file, "\nThis is SYN-ACK packet\n");
        }
        else if(tcp -> tcph_flags & TH_SYN) {
            printf("\nThis is SYN packet\n");
            fprintf(log_file, "\nThis is SYN packet\n");
        }
        else if(tcp -> tcph_flags & TH_ACK) {
            printf("\nThis is ACK packet\n");
            fprintf(log_file, "\nThis is ACK packet\n");
        }
    }
    printf("\nEnd of packet\n");
    fprintf(log_file, "\nEnd of packet\n");

    count++;
}

int main() {
    log_file = fopen("packet_log.txt", "w");
    if(log_file == NULL) {
        perror("Unable to open log file");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, 7, got_packet, NULL);
    fclose(log_file);
    return 0;
}

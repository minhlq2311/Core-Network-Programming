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
#include <signal.h>  // Include signal.h for signal handling
#include "../packet_header.h"
#define SIZE_ETHERNET 14

int count = 1;
FILE *log_file = NULL;
pcap_t *handle;

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
        body_start += 4; // Skip the header
        if (*body_start != '\0') { // Check if the body is not empty
            printf("Body:\n%s\n", body_start);
            fprintf(log_file, "Body:\n%s\n", body_start);
        }
    }
}


void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Get the current time
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[80];

    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_buffer, 80, "%Y-%m-%d %H:%M:%S", time_info);

    // Parse the packet
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + SIZE_ETHERNET);
    size_t ip_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_len);
    size_t tcp_len = tcp->doff * 4;
    unsigned char *payload = (unsigned char *)(packet + SIZE_ETHERNET + ip_len + tcp_len);
    int payload_len = ntohs(ip->tot_len) - (ip_len + tcp_len);

    printf("\nPacket number %d:\n", count);
    printf("Time: %s\n", time_buffer);
    fprintf(log_file, "\nPacket number %d:\n", count);
    fprintf(log_file, "Time: %s\n", time_buffer);

    printf("Source MAC: ");
    fprintf(log_file, "Source MAC: ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->h_source[i]);
        fprintf(log_file, "%02x", eth->h_source[i]);
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
        printf("%02x", eth->h_dest[i]);
        fprintf(log_file, "%02x", eth->h_dest[i]);
        if(i < 5){
            printf(":");
            fprintf(log_file, ":");
        }
    }
    printf("\n");
    fprintf(log_file, "\n");

    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    fprintf(log_file, "Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    fprintf(log_file, "Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

    printf("Source Port: %d\n", ntohs(tcp->source));
    fprintf(log_file, "Source Port: %d\n", ntohs(tcp->source));
    printf("Destination Port: %d\n", ntohs(tcp->dest));
    fprintf(log_file, "Destination Port: %d\n", ntohs(tcp->dest));

    unsigned int tcp_seq = ntohl(tcp->seq);
    printf("Sequence number: %u\n", tcp_seq);
    fprintf(log_file, "Sequence number: %u\n", tcp_seq);
    unsigned int tcp_ack = ntohl(tcp->ack_seq);
    printf("Acknowledge number: %u\n", tcp_ack);
    fprintf(log_file, "Acknowledge number: %u\n", tcp_ack);

    if(payload_len > 0){
        printf("\nHTTP content:\n");
        fprintf(log_file, "\nHTTP content:\n");
        parse_http_response((const char *)payload);
    }
    printf("\nEnd of packet\n");
    fprintf(log_file, "\nEnd of packet\n");

    count++;
}

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

int main(int argc, char *argv[]) {
    log_file = fopen("packet_log.txt", "w");
    if(log_file == NULL) {
        perror("Unable to open log file");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // The first argument is the device name to sniff on
    char *dev = argv[1];
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    signal(SIGINT, cleanup);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80 and (tcp[13] & 8 != 0)";
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

    pcap_loop(handle, -1, got_packet, NULL);
    fclose(log_file);
    return 0;
}

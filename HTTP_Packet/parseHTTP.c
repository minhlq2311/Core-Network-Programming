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
#include <linux/if_ether.h> // Add this line to include the header file that defines "ETH_P_ALL

#define SIZE_ETHERNET 14
struct ethernetHeader {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};

struct ipHeader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_offset;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpHeader{
    unsigned short tcph_srcport;
    unsigned short tcph_destport;
    unsigned int tcph_seqnum;
    unsigned int tcph_acknum;
    unsigned char tcph_reserved:4, tcph_offset:4;
    unsigned char tcph_flags;
    unsigned short tcph_win;
    unsigned short tcph_chksum;
    unsigned short tcph_urgptr;
};

int count = 1;

char *get_header_value(const char *response, const char *header_name) {
    char *header_start = strstr(response, header_name);
    if (header_start == NULL) {
        return NULL;
    }

    // Tìm dấu ":" sau tên header
    char *value_start = strstr(header_start, ": ");
    if (value_start == NULL) {
        return NULL;
    }

    // Bỏ qua dấu ": " để đến giá trị
    value_start += 2;

    // Tìm vị trí kết thúc của header (tức là tìm vị trí xuống dòng "\r\n")
    char *value_end = strstr(value_start, "\r\n");
    if (value_end == NULL) {
        return NULL;
    }

    // Tính độ dài giá trị header
    size_t value_length = value_end - value_start;

    // Tạo một chuỗi mới để lưu giá trị của header
    char *header_value = (char *)malloc(value_length + 1);
    if (header_value == NULL) {
        perror("Malloc failed");
        exit(EXIT_FAILURE);
    }
    strncpy(header_value, value_start, value_length);
    header_value[value_length] = '\0';

    return header_value;
}

void parse_http_response(const char *response) {
    char *status_line_end = strstr(response, "\r\n");
    if (status_line_end == NULL) {
        printf("Invalid HTTP response: no status line found\n");
        return;
    }

    // In ra dòng trạng thái (status line)
    printf("Status Line: %.*s\n", (int)(status_line_end - response), response);

    // Tìm phần body của HTTP response
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start != NULL) {
        body_start += 4;  // Bỏ qua "\r\n\r\n" để đến phần body
        printf("Body:\n%s\n", body_start);
    }

    // Lấy một số header cụ thể (ví dụ: Content-Type, Content-Length)
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
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    struct ethernetHeader *eth = (struct ethernetHeader *)packet;

    struct ipHeader *ip = (struct ipHeader *)(packet + SIZE_ETHERNET);

    size_t ip_len = (ip->iph_ihl) * 4;
    struct tcpHeader *tcp = (struct tcpHeader *)(packet + 14 + ip_len);

    size_t tcp_len = (tcp->tcph_offset) * 4;
    unsigned char *payload = (unsigned char *)(packet + 14 + ip_len + tcp_len);

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

    parse_http_response((const char *)payload);
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

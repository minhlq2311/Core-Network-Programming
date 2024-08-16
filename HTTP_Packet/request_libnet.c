#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <unistd.h>

#define SOURCE_IP "10.0.2.15"  
#define DEST_IP "93.184.215.14"    
#define SOURCE_PORT 12345         
#define DEST_PORT 80               

int main(){
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    libnet_ptag_t ip_tag, tcp_tag;

    char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    int dataLen = strlen(data);
    tcp_tag = libnet_build_tcp(
        SOURCE_PORT,
        DEST_PORT,
        libnet_get_prand(LIBNET_PRu32), //Sequence number
        0, // ACK number
        TH_PUSH | TH_ACK, // flags
        32767, // window size
        0, // checksum
        0, // urgent pointer
        LIBNET_TCP_H + dataLen, // header length
        data,
        dataLen,
        l,
        0
    );
    if(tcp_tag == -1){
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
    }

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + dataLen,
        0,
        libnet_get_prand(LIBNET_PRu16),
        0,
        64,
        IPPROTO_TCP,
        0,
        inet_addr(SOURCE_IP),
        inet_addr(DEST_IP),
        NULL,
        0,
        l,
        0
    );
    if(ip_tag == -1){
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
    }
    int bytesWritten = libnet_write(l);
    if(bytesWritten == -1){
        fprintf(stderr, "Write failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
    }
}
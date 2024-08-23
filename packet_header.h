#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <netinet/in.h> 
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

struct udpHeader{
    unsigned short udph_srcport;
    unsigned short udph_destport;
    unsigned short udph_len;
    unsigned short udph_chksum;
};

struct icmpHeader{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_chksum;
    unsigned short id;
    unsigned short seq;
};
#include <netinet/ip.h>

struct ipHeader{
    u_char iph_ihl:4, iph_ver:4;
    u_char iph_tos;
    u_short iph_len;
    u_short iph_ident;
    u_short iph_offset;
    u_char iph_ttl;
    u_char iph_protocol;
    u_short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct icmpHeader{
    u_char icmp_type;
    u_char icmp_code;
    u_short icmp_chksum;
    u_short id;
    u_short seq;
};
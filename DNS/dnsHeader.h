#pragma pack(push, 1)
struct dnsHeader{
    unsigned short id;
    unsigned short flags;
    unsigned short quesCount;
    unsigned short ansCount;
    unsigned short authorCount;
    unsigned short addCount;
};

struct QUESTION{
    unsigned short qtype;
    unsigned short qclass;
};

struct R_DATA{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

struct dnsRecord{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
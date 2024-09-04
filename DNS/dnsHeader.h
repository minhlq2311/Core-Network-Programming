
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
#pragma pack(push, 1)
struct R_DATA{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
struct dnsQuery{
    unsigned char *name;
    struct QUESTION *ques;
};

struct dnsRecord{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
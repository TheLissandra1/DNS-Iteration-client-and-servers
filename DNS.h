#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED

/*定义结构体宏定义和共用函数*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include<sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>


#define CLIENT "127.0.0.1"
#define LOCAL "127.0.0.2"
#define ROOT "127.0.0.3"
#define NATION "127.0.0.4"
#define OTHER "127.0.0.5"
#define EDU "127.0.0.6"
#define GOV "127.0.0.7"
#define PTRADDR "127.0.0.8"
#define PORT 53

typedef struct DNSHeader
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};

typedef struct DNSQuery
{
    unsigned char name[128];
    unsigned short qtype;
    unsigned short qclass;
};

typedef struct DNSRR    // rescource record
{
    unsigned char name[128];
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char rdata[128];
};
//以下函数在dns.c里定义了
unsigned char* getMessage(struct DNSHeader* header, 
                        struct DNSQuery* query, 
                        const unsigned char* message, 
                        int *len_header_query);         //将报文中的报头和查询请求部分存到结构体中
unsigned char* getRR(struct DNSRR rr[10],
                    struct DNSHeader* header,  
                    unsigned char* ptr);                //将报文中的资源记录存到结构体中
void getAddRR(struct DNSRR* addrr, 
            struct DNSHeader* header, 
            unsigned char* ptr);//将报文中的附加资源记录存到结构体中

#endif// DNS_H_INCLUDED

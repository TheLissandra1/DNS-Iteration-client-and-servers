#include "DNS.h"


 //将报文中的报头和查询请求部分存到结构体中，并返回指针
unsigned char* getMessage(struct DNSHeader* header, struct DNSQuery* query, const unsigned char* message, int* len_header_query)
{
    char* ptr = message;
    int i, flag, num = 0;//num记录name的长度
    len_header_query = 0;
    //把报文的header部分放进header结构体，指针ptr指向query开头
    header->id = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    header->tag = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    header->queryNum = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    header->answerNum = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    header->authorNum = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    header->addNum = ntohs(*((unsigned short*)ptr));
    ptr += 2;
    len_header_query += 12;
    //把报文的query部分放进query结构体，指针ptr指向RR的开头
    for(i = 0; i < header->queryNum; i++)
    {
        int k = 0;
        for(;;)//拆name
        {
            flag = (int)ptr[0];
            k++;
            num += flag;
            ptr += (flag + 1);
            if(flag == 0)
                break;
        }
        ptr -= (num + k);
        memset(query->name, 0, sizeof(query->name));
        memcpy(query->name, ptr, num + k - 1);
        ptr += (num + k);
        len_header_query += (num + k);
        query->qtype = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        query->qclass = ntohs(*((unsigned short*)ptr));
        len_header_query += 4;
    }
    return (ptr + 2);//返回指针，此时指针指向RR部分开头
}
//将报文中的RR部分存到RR结构体中
unsigned char* getRR(struct DNSRR rr[10], struct DNSHeader* header, unsigned char* ptr)
{
    int i, flag, num;
    int n;
    n = header->answerNum + header->authorNum;
    for(i = 0; i < n; i++)
    {
        num = 0;
        for(;;)
        {
            flag = (int)ptr[0];
            num += (flag + 1);
            ptr += (flag + 1);
            if(flag == 0)
                break;
        }
        ptr -= num;
        memset(rr[i].name, 0, sizeof(rr[i].name));
        memcpy(rr[i].name, ptr, num - 1);
        ptr += num;
        rr[i].type = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        rr[i]._class = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        rr[i].ttl = ntohl(*((unsigned short*)ptr));
        ptr += 4;
        rr[i].data_len = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        if(rr[i].type == 2 || rr[i].type == 5)//NS,CNAME
            ptr++;
        else if(rr[i].type == 15)//MX
            ptr += 3;
        else if(rr[i].type == 12)//MX
            ptr += 1;
      
        memset(rr[i].rdata, 0, sizeof(rr[i].rdata));
        if(rr[i].type == 1)//A
        {
            char *ip;
            struct in_addr addr;
            unsigned long l;
            l = *((unsigned long*)ptr);
            memcpy(&addr, &l, 4);
            ip = inet_ntoa(addr);
            memcpy(rr[i].rdata, ip, strlen(ip));
        }
        
        else
        {
            
            memcpy(rr[i].rdata, ptr, rr[i].data_len);
            printf("%s\n",rr[i].rdata);
        }
        ptr += rr[i].data_len;
    }
    return ptr;
}

void getAddRR(struct DNSRR* addrr, struct DNSHeader* header, unsigned char* ptr)
{
    ptr++;
    int i, flag, num;
    for(i = 0; i < header->addNum; i++)
    {
        num = 0;
        for(;;)
        {
            flag = (int)ptr[0];
            num += (flag + 1);
            ptr += (flag + 1);
            if(flag == 0)
                break;
        }
        ptr -= num;
        memset(addrr->name, 0, sizeof(addrr->name));
        memcpy(addrr->name, ptr, num - 1);
        ptr += num;
        addrr->type = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        addrr->_class = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        addrr->ttl = ntohl(*((unsigned short*)ptr));
        ptr += 4;
        addrr->data_len = ntohs(*((unsigned short*)ptr));
        ptr += 2;
        memset(addrr->rdata, 0, sizeof(addrr->rdata));
        char *ip;
        struct in_addr addr;
        unsigned long l;
        l = *((unsigned long*)ptr);
        memcpy(&addr, &l, 4);
        ip = inet_ntoa(addr);
        memcpy(addrr->rdata, ip, strlen(ip));
        ptr += addrr->data_len;
    }
}

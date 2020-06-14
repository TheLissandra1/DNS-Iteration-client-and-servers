#include "othersvr.h"
#include "DNS.h"

struct DNSHeader header;
struct DNSQuery query;
struct DNSRR rr[10];			
struct sockaddr_in clientAddr;	
unsigned char dnsmessage[1024];
unsigned char* rr_ptr;			
unsigned char* get_rr_ptr;		
char* filename;					
int socketudp;					
int err;						
int len_header_query = 0;   	

void initSocket(const char* svr, const char* _filename)
{
	filename = _filename;
    socketudp = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(svr);
    err = bind(socketudp, (struct sockaddr*)&addr, sizeof(struct sockaddr));
    if(err < 0)
    {
        printf("UDP %s:%dbind failed: %d\n",svr,PORT,errno);
        exit(0);
    }
}

int containString(const unsigned char* dname, const unsigned char* rname, const unsigned char type)
{
    int len1 = strlen(dname);
    int len2 = strlen(rname);
    int i = len1 - 1, j = len2 - 1;
    if(type == 'N'||type=='P'){
        for(;; i--,j--)
        {
            if(j < 0)
            {
                return 1;
            }
            if(dname[i] != rname[j])
                return -1;
        }
    }
    else
    {
        if(strcmp(dname, rname) == 0)
        {
            return 1;
        }
        return -1;
    }
}

void setRR()
{
    unsigned char temp_rr[256];
    rr_ptr = getMessage(&header, &query, dnsmessage, &len_header_query);
    get_rr_ptr = rr_ptr;
    memset(rr_ptr, 0, sizeof(dnsmessage) - len_header_query);
    unsigned char* ptr = dnsmessage;
    ptr += 6;
    *((unsigned short*)ptr) = 0;
    ptr += 2;
    *((unsigned short*)ptr) = 0;
    FILE *fp;
    fp = fopen(filename, "r");
    if(fp == NULL)
    {
        printf("the file cannot be opened: %d\n", errno);
        exit(0);
    }
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char* temp_ptr = query.name;
    int flag, i, num = 0;
    for(;;)
    {
        flag = (int)temp_ptr[0];
        for(i = 0; i < flag; i++)
        {
            dname[i + num] = temp_ptr[i + 1];
        }
        temp_ptr += (flag + 1);
        if((int)temp_ptr[0] == 0)
            break;
        dname[flag + num] = '.';
        num += (flag + 1);
    }
    while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)
    {
        unsigned char rname[128];
        unsigned char type;
        memset(rname, 0, sizeof(rname));
        int len = strlen(temp_rr);
        for(i = 0; i < len; i++)
        {
            if(temp_rr[i] == ' ')
                break;
        }
        memcpy(rname, temp_rr, i);

        int numofspace = 0;
        for(i = 0; i < len; i++)
        {
            if(temp_rr[i] == ' ')
                numofspace++;
            if(temp_rr[i] == ' ' && numofspace == 2)
                break;
        }
        type = temp_rr[i + 1];
        if(containString(dname, rname, type) == 1)
        {   
            addRR(temp_rr, rname);
        }
        memset(temp_rr, 0, sizeof(temp_rr));
    }
    err = fclose(fp);
    if(err == EOF)
    {
        printf("The file close failed: %d\n", errno);
        exit(0);
    }
}

void addRR(const unsigned char* str, const unsigned char* rname)
{
    unsigned char buf[128];
    unsigned char* ptr = dnsmessage;
    ptr += 6;
    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);
    ptr = buf;
    char *pos;
    int n, len = 0;
    pos = (char*)rname;
   
    for(;;)
    {
        n = strlen(pos) - (strstr(pos , ".") ? strlen(strstr(pos , ".")) : 0);
        *ptr ++ = (unsigned char)n;
        memcpy(ptr , pos , n);
        len += n + 1;
        ptr += n;
        if(!strstr(pos , "."))
        {
            *ptr = (unsigned char)0;
            ptr ++;
            len += 1;
            break;
        }
        pos += n + 1;
    }
    memcpy(rr_ptr, buf, len);
    rr_ptr += len;
    pos = (char*)str;
    pos += (len + 2);
    int flag = 0;
    
    switch(pos[0])
    {
    case'A':
    {
        *((unsigned short*)rr_ptr) = htons(1);
        rr_ptr += 2;
        pos += 2;
        flag = 1;
        break;
    }
    case'N':
    {
    	unsigned char* _ptr = dnsmessage;
        _ptr += 6;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) - 1);
        _ptr += 2;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) + 1);
        *((unsigned short*)rr_ptr) = htons(2);
        rr_ptr += 2;
        pos += 3;
        break;
    }
    case'C':
    {
        *((unsigned short*)rr_ptr) = htons(5);
        rr_ptr += 2;
        pos += 6;
        break;
    }
    case'M':
    {
        *((unsigned short*)rr_ptr) = htons(15);
        rr_ptr += 2;
        pos += 3;
        flag = 2;
        break;
    }
    case'P':
    {
        *((unsigned short*)rr_ptr) = htons(12);
        rr_ptr += 2;
        pos += 4;
        break;
    }
    }
    *((unsigned short*)rr_ptr) = htons(1);
    rr_ptr += 2;
    *((unsigned short*)rr_ptr) = htonl(0);
    rr_ptr += 4;
    len = strlen(pos);
    len = len - 2;
    if (flag == 1)
    {
        *((unsigned short*)rr_ptr) = htons(4);
        rr_ptr += 2;
        struct in_addr addr;
        char ip[32];
        memset(ip, 0, sizeof(ip));
        memcpy(ip, pos, len);
        inet_aton(ip, &addr);
        *((unsigned long*)rr_ptr) = addr.s_addr;
        rr_ptr += 4;
    }
    else if(flag == 2)
    {
    	*((unsigned short*)rr_ptr) = htons(len);
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 3, 2);
        rr_ptr += 2;
        *rr_ptr = (unsigned char)len;
        rr_ptr += 1;
        memcpy(rr_ptr, pos, len);
        rr_ptr += len;
        memset(rr_ptr, 0, 1);
        rr_ptr++;
    }
    else
    {
        *((unsigned short*)rr_ptr) = htons(len);
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 1, len + 1);
        rr_ptr += (len + 1);
    }
}

void setAddtionalRR()
{
    rr_ptr = getMessage(&header, &query, dnsmessage, &len_header_query);
    rr_ptr = getRR(rr, &header, rr_ptr);
    rr_ptr++;
    int i, j;
    for(j = 0; j < header.answerNum; j++)
    {
        if(rr[i].type == 15)
        {
            unsigned char temp_rr[256];
            unsigned char type;
            FILE *fp;
            fp = fopen(filename, "r");
            if(fp == NULL)
            {
                printf("the file cannot be opened: %d", errno);
                exit(0);
            }
            while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)
            {
                unsigned char rname[128];
                memset(rname, 0, sizeof(rname));
                int len = strlen(temp_rr);
                for(i = 0; i < len; i++)
                {
                    if(temp_rr[i] == ' ')
                        break;
                }
                memcpy(rname, temp_rr, i);
                int numofspace = 0;
                for(i = 0; i < len; i++)
                {
                    if(temp_rr[i] == ' ')
                        numofspace++;
                    if(temp_rr[i] == ' ' && numofspace == 2)
                        break;
                }
                type = temp_rr[i + 1];
                if(containString(rr[j].rdata, rname, type) == 1)
                {
                    addRR(temp_rr, rname);
                    unsigned char* ptr = dnsmessage;
                    ptr += 6;
                    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) - 1);
                    ptr += 4;
                    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);
                }
                memset(temp_rr, 0, sizeof(temp_rr));
            }
            err = fclose(fp);
            if(err == EOF)
            {
                printf("The file close failed: %d", errno);
                exit(0);
            }
            break;
        }
    }
}

void receivefromServer(int flag)
{
	memset(dnsmessage, 0, sizeof(dnsmessage));
	switch(flag)
	{
		case 1:
		{
			int len = sizeof(clientAddr);
    		err = recvfrom(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, &len);
			break;
		}
	}
    if(err <= 0)
    {
        printf("UDP socket receive failed: %d\n", errno);
        exit(0);
    }
    
}

void sendtoSvr(int flag)
{
	switch(flag)
	{
		case 1:
		{
            unsigned char* ptr = dnsmessage;
            ptr += 2;
            if (*((unsigned short*)ptr) == htons(0x0080))
            {
                *((unsigned short*)ptr) = htons(0x8080);
            }

			err = sendto(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, sizeof(struct sockaddr));
		}
	}
	if(err <= 0)
    {
        printf("send question to next dns failed: %d\n", errno);
        exit(0);
    }
}

void process()
{   
	while(1)
    {
        receivefromServer(1);                      
        setRR();	
        setAddtionalRR(); 
        if(header.tag == 0x0080)
        {
            printf("\nIteration is working\n");
            sendtoSvr(1);
        }

    }
}

#include "DNS.h"

struct DNSHeader header;                    //报头
struct DNSQuery query;                      //查询部分
struct DNSRR rr[10];                        //资源记录
struct DNSRR cache[100];                    //缓存
struct DNSRR addrr;                         //附加资源记录
struct timeval start;                       //记录向其他服务器发送消息的时间
struct timeval end;                         //记录从其他服务器接收消息的时间
unsigned char dnsmessage[1024];             //保存报文内容
unsigned char* rr_ptr;                      //记录报文中资源记录部分的位置
int sockettcp, socketudp, socketclient;     //套接字标识符
int err;                                    //用来接受返回值
int cachenum = 0;                           //当前缓存的序号
int len_header_query = 0;

int str_length = 0;

void initSocket()
{
	
    sockettcp = socket(AF_INET , SOCK_STREAM , 0);
    if(sockettcp < 0)
    {
        printf("create TCP socket failed: %d\n", errno);
        exit(0);
    }
    struct sockaddr_in addr, clientAddr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(LOCAL);
    
 
    err = bind(sockettcp, (struct sockaddr*)&addr, sizeof(struct sockaddr));//绑定自己的地址和端口号
    if(err < 0)
    {
        printf("TCP %s:%d bind failed: %d\n",LOCAL,PORT,errno);
        exit(0);
    }
    err = listen(sockettcp, SOMAXCONN);//监听并等待连接
    if(err < 0)
    {
        printf("listen socket failed: %d\n", errno);
        exit(0);
    }
    int len = sizeof(clientAddr);
    socketclient = accept(sockettcp, (struct sockaddr*)&clientAddr, &len);
    if(socketclient < 0)
    {
        printf("TCP socket accept failed: %d", errno);
        exit(0);
    }
    
    //初始化UDP套接字
    socketudp = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    struct sockaddr_in localSvr;
    memset(&localSvr, 0, sizeof(localSvr));
    localSvr.sin_family = AF_INET;
    localSvr.sin_port = htons(0);
    localSvr.sin_addr.s_addr = inet_addr("127.0.0.2");

    if((bind(socketudp,(struct sockaddr*)&localSvr,sizeof(localSvr)))<0){
        printf("udp bind failed,use another\n");
        exit(1);
    }
    else{
        printf("udp bind succeed.\n");}
}

void addRR(const unsigned char* str, const unsigned char* rname)//temp 和 dname
{
    unsigned char buf[128];
    unsigned char* ptr = dnsmessage;
    ptr += 6;//改answer count
    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);//报头的资源记录数加1
    ptr = buf;
    char *pos;
    int n, len = 0;//len记录域名的长度
    pos = (char*)rname;
    /*将域名存到buf中，buf中存储每个域的长度和内容
    比如当前域是edu.cn，存到buf中就变成了3edu2cn0
    ,0表示结尾*/
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
    pos += (len + 2);//过IN到A前面
    /*因为只考虑A,MX,CNAME,PTR四种查询类型
    ，所以只做了匹配第一个字母的简单处理*/
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
    case'N'://NS
    {
        unsigned char* _ptr = dnsmessage;
        _ptr += 6;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) - 1);
        _ptr += 2;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) + 1);//authority count
        *((unsigned short*)rr_ptr) = htons(2);//加type NS
        rr_ptr += 2;
        pos += 3;//A两位，NS三位
        break;
    }
    case'C'://CNAME
    {
        *((unsigned short*)rr_ptr) = htons(5);//type
        rr_ptr += 2;
        pos += 6;
        break;
    }
    case'M'://MX
    {
        *((unsigned short*)rr_ptr) = htons(15);//type
        rr_ptr += 2;
        pos += 3;
        flag = 2;
        break;
    }
    }
    *((unsigned short*)rr_ptr) = htons(1);//class
    rr_ptr += 2;
    *((unsigned short*)rr_ptr) = htonl(0);//TTL
    rr_ptr += 4;
    len = strlen(pos);
    len = len - 1;//len - 2是因为从文件中读取的字符串最后两位是回车加换行
    if (flag == 1)//A type
    {
        *((unsigned short*)rr_ptr) = htons(4);
        rr_ptr += 2;//resource data length
        struct in_addr addr;
        char ip[32];
        memset(ip, 0, sizeof(ip));
        memcpy(ip, pos, len + 1);///存cache里的ip
        inet_aton(ip, &addr);
        *((unsigned long*)rr_ptr) = addr.s_addr;
        rr_ptr += 4;//IP占4字节--resource data
    }
    else if(flag == 2)//MX
    {
        int i;
        for(i = 0; i < strlen(pos); i++)
        {
            if(pos[i] == ' ')
                break;
        }
        *((unsigned short*)rr_ptr) = htons(i);//把域名的长度压到rr_ptr里，两字节
        rr_ptr += 2;//resource data length
        memcpy(rr_ptr, pos - 3, 2);//type
        rr_ptr += 2;
        *rr_ptr = (unsigned char)len;
        rr_ptr += 1;
        memcpy(rr_ptr, pos, len);
        rr_ptr += i;
        unsigned char* temp[128];
        memset(temp, 0, sizeof(temp));
        memcpy(temp, pos, i);
        strcat((char*)temp, " IN A ");//拼成A type
        pos += (i + 1);
        len = strlen(pos) - 1;
        unsigned char ipaddr[128];
        memset(ipaddr, 0, sizeof(ipaddr));
        memcpy(ipaddr, pos, len);
        strcat((char*)temp, ipaddr);
        rr_ptr = getRR(rr, &header, rr_ptr);//
        unsigned char* _ptr = dnsmessage;
        _ptr += 6;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) - 1);//answer count +1
        _ptr += 4;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) + 1);//addtional count +1
        addRR(temp, rr[0].rdata);//进A
    }
    else//NS,CNAME
    {
        *((unsigned short*)rr_ptr) = htons(len);//resource data length
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 1, len + 1);//压下一级服务器地址IP
        rr_ptr += (len + 1);
    }
}

int checkCache(const unsigned char* name)//checkCache(query.name) == 1
{
    FILE* fp;
    fp = fopen("cache.txt", "r");
    if(fp == NULL)
    {
        printf("file open failed\n");
    }
    unsigned char temp[128];
    while(fgets(temp, sizeof(temp), fp) != NULL)//逐行读文件
    {
        unsigned char rname[128];//存储第一个空格前的部分
        int i;
        memset(rname, 0, sizeof(rname));
        int len = strlen(temp);
        for(i = 0; i < len; i++)
        {
            if(temp[i] == ' ')
                break;
        }
        memcpy(rname, temp, i);
        unsigned char* temp_ptr = name;
        unsigned char dname[128];
        memset(dname, 0, sizeof(dname));
        int flag, j, num = 0;
        for(;;)//换成带.的域名
        {
            flag = (int)temp_ptr[0];
            for(j = 0; j < flag; j++)
            {
                dname[j + num] = temp_ptr[j + 1];
            }
            temp_ptr += (flag + 1);
            if((int)temp_ptr[0] == 0)
                break;
            dname[flag + num] = '.';
            num += (flag + 1);
        }
        if(strcmp(dname, rname) == 0)//相等
        {
            addRR(temp, dname);//temp是一行，dname是query报文里的域名，rname是缓存里的域名
            sendtoClient();
            return 1;
        }
        memset(temp, 0, sizeof(temp));
    }
    int f_err = fclose(fp);
    if(f_err == EOF)
    {
        printf("The file close failed");
        exit(-1);
    }
    return -1;
}

void addCache(int index)
{
    FILE* fp;
    fp = fopen("cache.txt", "a+");
    if(fp == NULL)
    {
        printf("file open failed\n");
    }
    unsigned char* str[128];
    memset(str, 0, sizeof(str));
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char* temp_ptr = rr[index].name;
    int flag, i, num = 0;
    for(;;)//将域名转换成标准格式
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
    strcat((char*)str, dname);
    strcat((char*)str, " IN ");
    switch(rr[index].type)
    {
        case 1:
        {
            strcat(str, "A ");
            break;
        }
        case 5:
        {
            strcat(str, "CNAME ");
            break;
        }
        case 15:
        {
            strcat(str, "MX ");
            break;
        }
        case 12:
        {
            strcat(str, "PTR ");
            break;
        }
    }
    strcat((char*)str, rr[index].rdata);
    if(rr[index].type == 15)
    {
        strcat(str, " ");
        getAddRR(&addrr, &header, rr_ptr);
        strcat(str, addrr.rdata);
    }
    strcat(str, "\n");
    fwrite(str, strlen(str), 1, fp);
    int f_err = fclose(fp);
    if(f_err == EOF)
    {
        printf("The file close failed");
        exit(-1);
    }
}

void receivefromClient()
{
    unsigned char temp[1024];
    memset(temp, 0, sizeof(temp));
    err = recv(socketclient, temp, sizeof(temp), 0);  // TCP 从client 接受信息
    if(err <= 0)
    {
        printf("TCP socket receive failed: %d\n",errno);
        exit(0);
    }
    memcpy(dnsmessage, temp + 2, err);

   str_length = err;
}

void sendtoClient()
{
    unsigned char* ptr = dnsmessage;
    ptr += 2;
    if (*((unsigned short*)ptr) == htons(0x0080))//iteration
    {
        *((unsigned short*)ptr) = htons(0x8080);
    }
    unsigned char temp[1024];
    memset(temp, 0, sizeof(temp));
    *((unsigned short*)temp) = htons(512);
    memcpy(temp + 2, dnsmessage, sizeof(dnsmessage) - 2);
    err = send(socketclient, temp, 514, 0);
    if(err < 0)
    {
        printf("send answer message failed: %d\n", errno);
        exit(0);
    }
}

void sendtoOther(unsigned char* svr)
{
    unsigned char* ptr = dnsmessage;
    ptr += 2;
    if (*((unsigned short*)ptr) == htons(0x8080))
    {
        *((unsigned short*)ptr) = htons(0x0080);
    }

    struct sockaddr_in destSvr;
    memset(&destSvr, 0, sizeof(destSvr));
    destSvr.sin_family = AF_INET;
    destSvr.sin_port = htons(PORT);
    destSvr.sin_addr.s_addr = inet_addr(svr);

    int len = sizeof(dnsmessage);
    gettimeofday(&start, NULL);
    err = sendto(socketudp, dnsmessage, len, 0, (struct sockaddr*)&destSvr, sizeof(struct sockaddr));
    if(err <= 0)
    {
        printf("UDP send failed: %d\n", errno);
        exit(0);
    }
    printf("send to %s\n", svr);
}

int receivefromOther()
{
    memset(dnsmessage, 0, sizeof(dnsmessage));//清空
    struct sockaddr_in clientAddr;
    int len = sizeof(clientAddr);
    int i;
    err = recvfrom(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, &len);
    printf("%d",err);
    if(err <= 0)
    {
        printf("UDP socket receive failed: %d\n", errno);
        exit(0);
    }
    gettimeofday(&end, NULL);
    unsigned long time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    rr_ptr = getMessage(&header, &query, dnsmessage, &i);
    rr_ptr = getRR(rr, &header, rr_ptr);
    printTrace(time);
    
    for(i = 0; i < header.answerNum; i++)
    {
      
        if(rr[i].type == query.qtype)//选择和查询类型相匹配的资源记录
        {
            return i;
        }           
    }   
    return -1;
}

void printTrace(unsigned long time)
{
    int i;
    int n = header.answerNum + header.authorNum;

    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char* temp_ptr = query.name;
    int flag, j, num = 0;
    for(;;)//将query.name转换成标准的域名格式
    {
        flag = (int)temp_ptr[0];
        for(j = 0; j < flag; j++)
        {
            dname[j + num] = temp_ptr[j + 1];
        }
        temp_ptr += (flag + 1);
        if((int)temp_ptr[0] == 0)
            break;
        dname[flag + num] = '.';
        num += (flag + 1);
    }

    for(i = 0; i < n; i++)
    {

        printf("\nQuery:\nDomain name: %s\nType: %d\nClass: %d\n"
                , dname, query.qtype, query.qclass);

        unsigned char dname2[128];
        memset(dname2, 0, sizeof(dname2));
        unsigned char* temp_ptr2 = rr[i].name;
        int flag, j, num = 0;
        for(;;)//将query.name转换成标准的域名格式
        {
            flag = (int)temp_ptr2[0];
            for(j = 0; j < flag; j++)
            {
                dname2[j + num] = temp_ptr2[j + 1];
            }
            temp_ptr2 += (flag + 1);
            if((int)temp_ptr2[0] == 0)
                break;
            dname2[flag + num] = '.';
            num += (flag + 1);
        }
        printf("RR:\nName: %s\nType: %d\nClass: %d\nTTL: %d\nDataLen: %d\nData: %s\nTime: %d us\n\n"
            , dname2, rr[i].type, rr[i]._class, rr[i].ttl, rr[i].data_len, rr[i].rdata, time);
    }
    
}

void checkSvr()
{
    printf("Ask Root Domain Name Server for answer.\n");
    sendtoOther(ROOT);//向根服务器发送查询报文
    int result = receivefromOther();
    printf("Get Response from Root Server: ");
    printf("%d\n",result);
    if((header.tag == 0x8180) && (result == -1))//正常回复且为-1，root告诉你找不到
    {
        result = -2;
        printf("%s",header.tag);
        sendtoClient(dnsmessage);
    }
    while(result == -1)//不是最终结果
    {
        int i, flag = 0;
        int n = header.answerNum + header.authorNum+ header.addNum;
        for(i = 0; i < n; i++)
        {
            if(rr[i].type == 2)//如果资源记录类型是NS
            {
                flag = 1;
                sendtoOther(rr[i].rdata);
                result = receivefromOther();//迭代查询 直到result不为-1时
            }
        }
        if(flag == 0)//表示没有找到NS类型的RR
        {
            rr_ptr = getMessage(&header, &query, dnsmessage, &len_header_query);//将报文中的报头和查询请求部分存到结构体中
            memset(rr_ptr, 0, sizeof(dnsmessage) - len_header_query);//清空报文中的rr部分
            unsigned char* ptr = dnsmessage;
            ptr += 6;//移到AnswerNum 置0
            *((unsigned short*)ptr) = 0;//报头的资源记录数置零
            sendtoClient(dnsmessage);//去掉RR，AnswerNum置0
            return;
        }
    }
    if(result != -2)
    {
        addCache(result);
        sendtoClient(dnsmessage);
    }
    
}

void process()
{
    while(1)
    {
        receivefromClient();
        int j = 0;
        rr_ptr = getMessage(&header, &query, dnsmessage, &j);
       
        if(checkCache(query.name) == 1)//可在缓存中找到结果
        {
            printf("Get from cache\n");
            continue;
        }
        else
        {
            printf("Can't get from cache, ask domain name servers.\n");
            checkSvr();
        }
    }
}

int main()
{
    FILE* fp;
    fp = fopen("cache.txt", "w+");//清空缓存
    if(fp == NULL)
    {
        printf("file open failed\n");
    }
    char* str = "Cache\n";
    fwrite(str, strlen(str), 1, fp);
    int f_err = fclose(fp);
    if(f_err == EOF)
    {
        printf("The file close failed");
        exit(-1);
    }
    initSocket();
    process();
    return 0;
}


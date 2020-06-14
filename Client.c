#include "DNS.h"

struct DNSHeader header;        //报头
struct DNSQuery query;          //查询部分
struct DNSRR rr[10];            //资源记录
struct DNSRR addrr;             //附加资源记录
unsigned char* rr_ptr;          //记录报文中资源记录位置的指针
int socketfd;                   //客户端套接字标识符
int err;                        //用于接收返回值
int indexID = 0;                //用于决定报文ID
int querytype, parsetype;   //记查询类型和解析类型

void initSocket()
{
    socketfd = socket(AF_INET , SOCK_STREAM , 0);//TCP连接
    if(socketfd < 0)
    {
        printf("create socket failed: %d", errno);
        exit(0);
    }
    struct sockaddr_in addr;//需要绑定的地址
    /*memset的作用是给一段内存赋值，
    第一个参数是需要赋值的内存地址，
    第二个参数是值，0可以理解为清空，
    第三个参数是给赋值内存的大小*/
    memset(&addr, 0, sizeof(addr));//清空内存
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(LOCAL);//绑定Local
    int len = sizeof(addr);
    err = connect(socketfd, (struct sockaddr*)&addr, len);//绑定地址和端口
    if(err < 0)
    {
        printf("connect failed: %d\n", errno);
        exit(0);
    }
}

void createHeader(struct DNSHeader* header,
                  unsigned short id,
                  unsigned short tag,
                  unsigned short queryNum,
                  unsigned short answerNum,
                  unsigned short authorNum,
                  unsigned short addNum)
{
    header->id = id;
    if (parsetype == 0)
    {
        header->tag = htons(0x0080);//iteration
    }

    header->queryNum = queryNum;
    header->answerNum = answerNum;
    header->authorNum = authorNum;
    header->addNum = addNum;
}

void createQuery(const char *name, unsigned char *ptr , int *len)
{
    char *pos;
    int n;
    pos = (char*)name;
    for(;;)//转换域名格式
    {
        n = strlen(pos) - (strstr(pos , ".") ? strlen(strstr(pos , ".")) : 0);
        *ptr ++ = (unsigned char)n;
        memcpy(ptr , pos , n);
        *len += n + 1;
        ptr += n;
        if(!strstr(pos , "."))
        {
            *ptr = (unsigned char)0;
            ptr ++;
            *len += 1;
            break;
        }
        pos += n + 1;
    }
    *((unsigned short*)ptr) = htons(querytype);
    *len += 2;
    ptr += 2;
    *((unsigned short*)ptr) = htons(1);
    *len += 2;
}

int createMessage(const unsigned char* question, unsigned char *ptr)
{
    ++indexID;
    unsigned char query[1024];
    int i, num = 0;//queryNum记录查询数量
    int len = 0;
    char* delim = " ";
    unsigned char* name;
    unsigned char* q_ptr = query;
    name = strtok(question, delim);//按空格分割请求，取第一个空格前的部分
    num++;
    createQuery(name , q_ptr, &len);//报文请求构建
    while(name = strtok(NULL, delim))//按空格分割剩余部分
    {
        num++;
        createQuery(name , q_ptr, &len);
    }

    createHeader(&header, htons(indexID), htons(parsetype), htons(num), 0, 0, 0);//报文头部构建

    /*将报头添加到字符串中*/
    *((unsigned short*)ptr) = htons(len + 12);//tcp协议下DNS报头前多两位
    ptr += 2;
    *((unsigned short*)ptr) = header.id;
    ptr += 2;
    *((unsigned short*)ptr) = header.tag;
    ptr += 2;
    *((unsigned short*)ptr) = header.queryNum;
    ptr += 2;
    *((unsigned short*)ptr) = header.answerNum;
    ptr += 2;
    *((unsigned short*)ptr) = header.authorNum;
    ptr += 2;
    *((unsigned short*)ptr) = header.addNum;
    ptr += 2;
    memcpy(ptr ,query ,len);//将生成的query部分添加到字符串中
    ptr += len;
    return len;
}

void sendtoLocal(const unsigned char* name)
{
    unsigned char message[1024];
    unsigned char *ptr = message;
    int len = createMessage(name, ptr);//报文构建
    err = send(socketfd, message, len + 14, 0);//给localDNSserver发报文了
    if(err < 0)
    {
        printf("send message failed: %d", errno);
        exit(0);
    }
}

void receiveFromLocal()
{
    unsigned char answer[1024];
    unsigned char temp[1024];
    memset(answer, 0, sizeof(answer));
    memset(temp, 0, sizeof(temp));
    err = recv(socketfd, temp, sizeof(temp), 0);
    if(err <= 0)
    {
        printf("TCP socket receive failed: %d\n",errno);
        exit(0);
    }
    memcpy(answer, temp + 2, sizeof(temp) - 2);
    printResult(answer);
}

void printResult(unsigned char* answer)
{
    int i;
    rr_ptr = getMessage(&header, &query, answer, &i);
    rr_ptr = getRR(rr, &header, rr_ptr);
    if(header.answerNum == 0)
    {
        printf("Sorry, no result was found\n");
        return;
    }
    for(i = 0; i < header.answerNum; i++)
    {
        if(rr[i].type == query.qtype)
        {
            if(query.qtype == 1)//如果RR类型是A,则直接打印IP地址
            {
                printf("Get IP address, the IP address is: %s\n", rr[i].rdata);
            }
            else if(query.qtype == 5)
            {
                //如果类型是CNAME则输出别名后再根据别名查询一次IP地址
                printf("Get canme name , the canonical name is: %s\n", rr[i].rdata);
                querytype = 1;
                sendtoLocal(rr[i].rdata);
                receiveFromLocal();
                querytype = 5;
                return;
            }
            else if(query.qtype == 15)//MX类型
            {
                printf("Get mail server, the mail server name is: %s\n", rr[i].rdata);
                printf("The ip address is:%s", rr[i].rdata);
                getAddRR(&addrr, &header, rr_ptr);
                printf("And addtion IP address is %s\n", addrr.rdata);
            }
            else if(query.qtype == 12)//PTR查询结果打印
            {
                printf("Get domain name, the domain name is: %s \n",rr[i].rdata);
            }
            else
            {
                printf("Sorry, no result was found\n");
            }
        }
    }
}


int main()
{
   int selection;
    unsigned char dname[1024];
    initSocket();
    printf("Hello! This is a DNS query system.\n\n");
    printf("Welcome uesr!!\n\n");
    printf("To use this, you can type a number as query type and a string as query name.\n");
    printf("----------------------------------------------------------------------------------\n\n");
    while(1)
    {
        printf("Please choose a query type:\n  1.A \n  2.CNAME \n  3.MX \n  4.PTR\n");//加PTR
        while(1)
        {
            scanf("%d", &selection);
            while (getchar() != '\n');//避免读入回车
            if(selection == 1)
                querytype = 1;
            else if(selection == 2)
                querytype = 5;
            else if(selection == 3)
                querytype = 15;
            else if(selection == 4)
                querytype = 12;//000c
            else
            {
                printf("Wrong choice, please choose again\n");
                continue;
            }
            break;
        }
        printf("Please enter the domain name:(if you want to change type,please type CHANGE)\n");
        scanf("%s", dname);
        if(querytype==12){//1.0.0.127
            strcat(dname,".in-addr.arpa");
                    
        }
        while (getchar() != '\n');
        while(strcmp(dname, "CHANGE") != 0)//输出BACK会重新选择类型
        {
            sendtoLocal(dname);
            receiveFromLocal();
            scanf("%s", dname);
        }
       
        system("clear");
    }
    close(socketfd);
    return 0;
    
}


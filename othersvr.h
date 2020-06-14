#ifndef OTHERSVR_H_INCLUDED
#define OTHERSVR_H_INCLUDED

void initSocket(const char* svr, const char* _filename);					
int containString(const unsigned char* dname, const unsigned char* rname, const unsigned char type);				
void setRR();										
void addRR(const unsigned char* str, const unsigned char* rname);				
void setaddRR();									
void receivefromServer(int flag);																				
void sendtoSvr( int flag);																					
void process();									
#endif 
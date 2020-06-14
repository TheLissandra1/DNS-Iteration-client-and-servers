#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(PTRADDR, "PTR.txt");
    process();
    return 0;
}
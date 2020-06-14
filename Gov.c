#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(GOV, "Gov.txt");
    process();
    return 0;
}
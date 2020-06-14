#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(EDU, "Edu.txt");
    process();
    return 0;
}
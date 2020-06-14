#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(OTHER, "Other.txt");
    process();
    return 0;
}
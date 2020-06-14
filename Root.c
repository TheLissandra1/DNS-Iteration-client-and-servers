#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(ROOT, "Root.txt");
    process();
    return 0;
}

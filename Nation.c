#include "DNS.h"
#include "othersvr.h"

int main()
{
    initSocket(NATION, "Nation.txt");
    process();
    return 0;
}
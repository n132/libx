#include "libx.h"
#include <stdio.h>
int main(){
    char *ptr =0xdeadbeef000;
    froze();
    puts(ptr);
    puts("Done");
}
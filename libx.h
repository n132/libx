#ifndef LIBX
#define LIBX
#define PAGE_SIZE 0x1000
#define TTYMAGIC 0x5401
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/mman.h>
#include <stddef.h>

void panic(char *s);
void shell();
void info(size_t val);
void* userfaultfd_leak_handler(void* arg);
size_t * forze();
// void save_status();

#endif

#define _GNU_SOURCE
/*
  For net submodule in linux kernel, got the code while reproducing CVES on kernelCTF  
*/
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>

#define err_exit(s) do { perror(s); exit(EXIT_FAILURE); } while(0)
typedef __u32 u32;
typedef struct tf_msg {
    struct nlmsghdr nlh;
    struct tcmsg tcm;
#define TC_DATA_LEN 512
    char attrbuf[TC_DATA_LEN];
} TM;
// TM == Trafic Message

struct if_msg {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
};

enum hfsc_class_flags {
	HFSC_RSC = 0x1,
	HFSC_FSC = 0x2,
	HFSC_USC = 0x4
};

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
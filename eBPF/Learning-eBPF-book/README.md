# Learning-eBPF-book-笔记



## 0x01 What Is eBPF, and Why Is It Important?

第一章主要介绍了一些概念作为入门。

![image-20231129143325854](README.assets/image-20231129143325854.png)

eBPF 是一项革命性的技术，起源于 Linux 内核，可以在操作系统的内核中运行沙盒程序。它被用来安全和有效地扩展内核的功能，而不需要改变内核的源代码或加载内核模块。eBPF 通过允许在操作系统内运行沙盒程序，应用程序开发人员可以在运行时，可编程地向操作系统动态添加额外的功能。然后，操作系统保证安全和执行效率，就像在即时编译（JIT）编译器和验证引擎的帮助下进行本地编译一样。eBPF 程序在内核版本之间是可移植的，并且可以自动更新，从而避免了工作负载中断和节点重启。



总的来说eBPF程序可以动态的加载到Kernel中，通过eBPF验证器来确保只有在安全的情况下才加载eBPF程序。它可以实现很多的功能，最初是过滤网络包，现在可以附件到各种事件中，实现各种各样的功能。



## 0x02 eBPF’s “Hello World“

第二章主要拿BCC框架举了几个"hello world"的例子。开发的话打算还是拿go来发现，因此就简单的看看文中的BCC框架的例子来了解一下eBPF以及一些常见的概念。

![image-20231129144010595](README.assets/image-20231129144010595.png)

![image-20231129144038119](README.assets/image-20231129144038119.png)



**eBPF Map：**Map是一种可以从eBPF程序和用户空间访问的数据结构，可以用于在多个eBPF程序中共享数据，或者在用户空间应用程序和内核中运行eBPF代码之间通信。

Map有很多种，一般来说都是键值存储。常见的有哈希表、perf buffer、ring buffer和eBPF程序的array。



下面是hash table的map：

```c
BPF_HASH(counter_table);

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}
```

下面是perf buffer的map：

```c
BPF_PERF_OUTPUT(output); 
 
struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
```



**Ring Buffer的概念：**视为逻辑上是环形的内存，有单独读和写指针，数据被写入到写指针所在的位置，长度信息包含在数据的头部。写完后写入指针移动到数据的末尾。读取操作从读指针所在的位置开始读取，从头部的长度信息来读取相应长度的数据，然后移动到数据的默认。读指针和写指针沿相同的方向移动。

![image-20231129144935027](README.assets/image-20231129144935027.png)



## 0x03 Anatomy of an eBPF Program

第三章主要举了两个c代码编写的eBPF程序的示例，来讲解了eBPF程序的一些细节。

![image-20231129145219007](README.assets/image-20231129145219007.png)

eBPF虚拟机是采用eBPF字节码指定形式的程序，这些指定作用于虚拟的eBPF寄存器。eBPF寄存器使用10个通用寄存器，编号为0到9，寄存器10被用作堆栈指针且只能读取不能写入。





eBPF的指令的结构：

![image-20231129152045536](README.assets/image-20231129152045536.png)

从上到下分别是opcode、目标寄存器、源寄存器、带符号的偏移、带符号的立即数。

eBPF程序加载到Kernel的时候，eBPF程序的字节码由一系列这样的bpf_insn结构表示，验证器会对此信息进行多次检查，以确保代码可以安全运行。



**map  semantics  can  be  repurposed  for  use  as  globalvariables**

## 0x04 The bpf() System Call

第四章主要介绍了`bpf() system call`。

![image-20231129153040745](README.assets/image-20231129153040745.png)

```c
int bpf(int cmd, unionbpf_attr *attr, unsignedint size);
```

第一个参数是要执行的命令，第二个参数是相关的属性，第三个参数是attr中有多少字节的数据。返回值是文件描述符。

有不同的cmd可以用来操作eBPF程序和map：

![image-20231129155410182](README.assets/image-20231129155410182.png)

通过strace看到具体的`bpf()`

```bash
sudo strace -e bpf,perf_event_open,ioctl,ppoll ./hello-ring-buffer-config.py



#将BTF数据块加载进Kernel。BTF允许eBPF程序在不同的Kernel版本之间移植。
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0P\5\0\0P\5\0\0\10\4\0\0\1\0\0\0\0\0\0\10"..., btf_log_buf=NULL, btf_size=2416, btf_log_size=0, btf_log_level=0}, 32) = 3


bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=2, insns=0x7fff4bbeee50, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="libbpf_nametest"}, 64) = 4


#创建map。这里是创建perf buffer
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4, value_size=4, max_entries=2, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0}, 72) = 4
#下面是创建Ring Buffer
bpf(BPF_MAP_CREATE, {map_type=0x1b /* BPF_MAP_TYPE_??? */, key_size=0, value_size=0, max_entries=4096, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0}, 72) = 4

#创建Hash Map
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=12, max_entries=10240, map_flags=0, inner_map_fd=0, map_name="config", map_ifindex=0, btf_fd=3, btf_key_type_id=1, btf_value_type_id=4}, 72) = 5

#初始化Hash Map
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7f7c3407e810, value=0x7f7c33cd3310, flags=BPF_ANY}, 32) = 0


#将eBPF程序加载进Kernel
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=41, insns=0x7f7c34991000, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(5, 15, 122), prog_flags=0, prog_name="hello", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0x1d53090, func_info_cnt=1, line_info_rec_size=16, line_info=0x1c188d0, line_info_cnt=21, attach_btf_id=0, attach_prog_fd=0}, 144) = 6

#这个命令有点没理解懂。
#创建一个允许测量性能信息的文件描述符，返回值7表示kprobe的perf event的文件描述符。通过这个perf_event_open，将eBPF的文件描述符6写入了/sys/bus/event_source/devices/kprobe/type 
perf_event_open({type=0x6 /* PERF_TYPE_??? */, size=0x88 /* PERF_ATTR_SIZE_??? */, config=0, ...}, -1, 0, -1, PERF_FLAG_FD_CLOEXEC) = 7



```

下面的命令可以查看bfftool在读取map的时候进行的`bpf()`系统调用：

```bash
sudo strace -e bpf bpftool map dump name config
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=24949, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=24950, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
bpf(BPF_MAP_GET_NEXT_ID, {start_id=0, next_id=0, open_flags=0}, 128) = 0
bpf(BPF_MAP_GET_FD_BY_ID, {map_id=8, next_id=0, open_flags=0}, 128) = 3
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93cce70}}, 128) = 0
bpf(BPF_MAP_GET_NEXT_ID, {start_id=8, next_id=0, open_flags=0}, 128) = 0
bpf(BPF_MAP_GET_FD_BY_ID, {map_id=34, next_id=0, open_flags=0}, 128) = 3
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93cce70}}, 128) = 0
bpf(BPF_MAP_GET_NEXT_ID, {start_id=34, next_id=0, open_flags=0}, 128) = 0
bpf(BPF_MAP_GET_FD_BY_ID, {map_id=35, next_id=0, open_flags=0}, 128) = 3
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93cce70}}, 128) = 0
bpf(BPF_MAP_GET_NEXT_ID, {start_id=35, next_id=0, open_flags=0}, 128) = -1 ENOENT (No such file or directory)
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93cd000}}, 128) = 0
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93ccfb0}}, 128) = 0
bpf(BPF_BTF_GET_FD_BY_ID, {btf_id=78}, 128) = 4
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=4, info_len=32, info=0x7ffea93cce60}}, 128) = 0
bpf(BPF_MAP_GET_NEXT_KEY, {map_fd=3, key=NULL, next_key=0x5648302d62e0}, 128) = 0
bpf(BPF_MAP_LOOKUP_ELEM, {map_fd=3, key=0x5648302d62e0, value=0x5648302d6300, flags=BPF_ANY}, 128) = 0
[{
        "key": 1000,
        "value": {
            "message": [72,105,32,117,115,101,114,32,53,48,49,33
            ]
        }
bpf(BPF_MAP_GET_NEXT_KEY, {map_fd=3, key=0x5648302d62e0, next_key=0x5648302d62e0}, 128) = 0
bpf(BPF_MAP_LOOKUP_ELEM, {map_fd=3, key=0x5648302d62e0, value=0x5648302d6300, flags=BPF_ANY}, 128) = 0
    },{
        "key": 0,
        "value": {
            "message": "Hey root!"
        }
bpf(BPF_MAP_GET_NEXT_KEY, {map_fd=3, key=0x5648302d62e0, next_key=0x5648302d62e0}, 128) = -1 ENOENT (No such file or directory)
    }
]
+++ exited with 0 +++
```

主要逻辑就是遍历所有的map，找到名为config的map就遍历map中的元素。

```bash
#获取指定值start_id之后的下一个map的id
bpf(BPF_MAP_GET_NEXT_ID, {start_id=0, next_id=0, open_flags=0}, 128) = 0
#返回指定Map ID的文件描述符
bpf(BPF_MAP_GET_FD_BY_ID, {map_id=8, next_id=0, open_flags=0}, 128) = 3
#检索文件描述符引用的对象
bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=3, info_len=80, info=0x7ffea93cce70}}, 128) = 0
```

然后就是从找到的map中读取key和value：

```bash
#返回指定key之后的下一个有效key，第一次查用NULL
bpf(BPF_MAP_GET_NEXT_KEY, {map_fd=3, key=NULL, next_key=0x5648302d62e0}, 128) = 0
#读取指定key的值，写入value指定的内存地址中
bpf(BPF_MAP_LOOKUP_ELEM, {map_fd=3, key=0x5648302d62e0, value=0x5648302d6300, flags=BPF_ANY}, 128) = 0
```

## 0x05 CO-RE, BTF, and Libbpf



```bash
sudo bpftool btf list
1: name [vmlinux]  size 4979133B
2: name [autofs4]  size 6872B
3: name [x_tables]  size 8259B
4: name [ip_tables]  size 6173B
5: name [efi_pstore]  size 586B
6: name [i2c_core]  size 14489B
7: name [drm]  size 106007B
8: name [msr]  size 580B
9: name [sch_fq_codel]  size 3221B
10: name [hid]  size 12233B
11: name [hyperv_keyboard]  size 1166B
12: name [rc_core]  size 10086B
13: name [hid_hyperv]  size 6762B
14: name [cec]  size 27562B
15: name [fb_sys_fops]  size 281B
16: name [hv_netvsc]  size 26695B
17: name [cryptd]  size 3369B
18: name [sysimgblt]  size 170B
19: name [sysfillrect]  size 325B
20: name [syscopyarea]  size 169B
21: name [crypto_simd]  size 1611B
22: name [aesni_intel]  size 2054B
23: name [drm_kms_helper]  size 88297B
24: name [hyperv_drm]  size 35959B
25: name [hid_generic]  size 4602B
26: name [joydev]  size 1686B
27: name [serio_raw]  size 783B
28: name [ghash_clmulni_intel]  size 626B
29: name [crc32_pclmul]  size 438B
30: name [crct10dif_pclmul]  size 265B
31: name [binfmt_misc]  size 936B
32: name [bpfilter]  size 428B
33: name [xt_tcpudp]  size 2210B
34: name [iptable_security]  size 1265B
35: name [xt_owner]  size 2143B
36: name [libcrc32c]  size 261B
37: name [nf_defrag_ipv4]  size 53098B
38: name [nf_defrag_ipv6]  size 91397B
39: name [nf_conntrack]  size 338542B
40: name [xt_conntrack]  size 88908B
41: name [scsi_dh_alua]  size 1420B
42: name [scsi_dh_emc]  size 757B
43: name [scsi_dh_rdac]  size 2848B
44: name [dm_multipath]  size 4308B
45: name [nls_iso8859_1]  size 182B
52: name [xfs]  size 306562B
53: name [msdos]  size 782B
54: name [ufs]  size 13325B
55: name [raid6_pq]  size 2736B
56: name [zstd_compress]  size 12773B
57: name [xor]  size 1385B
58: name [blake2b_generic]  size 1231B
59: name [btrfs]  size 222015B
65: name <anon>  size 689B  prog_ids 99  map_ids 8
80: name <anon>  size 2416B  prog_ids 145  map_ids 39
```



```bash
sudo bpftool prog show name hello
99: raw_tracepoint  name hello  tag 3d9eb0c23d4ab186  gpl
	loaded_at 2023-11-28T06:59:30+0000  uid 0
	xlated 80B  jited 60B  memlock 4096B  map_ids 8
	btf_id 65
145: kprobe  name hello  tag cbd8e84610183e77  gpl
	loaded_at 2023-11-29T11:27:47+0000  uid 0
	xlated 344B  jited 190B  memlock 4096B  map_ids 39,38
	btf_id 80
```



```bash
sudo bpftool btf dump id 80
[1] TYPEDEF 'u32' type_id=2
[2] TYPEDEF '__u32' type_id=3
[3] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[4] STRUCT 'user_msg_t' size=12 vlen=1
	'message' type_id=6 bits_offset=0
[5] INT 'char' size=1 bits_offset=0 nr_bits=8 encoding=SIGNED
[6] ARRAY '(anon)' type_id=5 index_type_id=7 nr_elems=12
[7] INT '__ARRAY_SIZE_TYPE__' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[8] STRUCT '____btf_map_config' size=16 vlen=2
	'key' type_id=1 bits_offset=0
	'value' type_id=4 bits_offset=32
[9] INT '(anon)' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[10] PTR '(anon)' type_id=0
[11] FUNC_PROTO '(anon)' ret_type_id=12 vlen=1
	'ctx' type_id=10
[12] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[13] FUNC 'hello' type_id=11 linkage=static
[14] INT '(anon)' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[15] STRUCT 'config_table_t' size=152 vlen=20
	'key' type_id=1 bits_offset=0
	'leaf' type_id=4 bits_offset=32
	'lookup' type_id=16 bits_offset=128
	'lookup_or_init' type_id=20 bits_offset=192
	'lookup_or_try_init' type_id=20 bits_offset=256
	'update' type_id=22 bits_offset=320
	'insert' type_id=22 bits_offset=384
	'delete' type_id=24 bits_offset=448
	'call' type_id=26 bits_offset=512
	'increment' type_id=28 bits_offset=576
	'atomic_increment' type_id=28 bits_offset=640
	'get_stackid' type_id=30 bits_offset=704
	'sk_storage_get' type_id=35 bits_offset=768
	'sk_storage_delete' type_id=37 bits_offset=832
	'inode_storage_get' type_id=35 bits_offset=896
	'inode_storage_delete' type_id=37 bits_offset=960
	'task_storage_get' type_id=35 bits_offset=1024
	'task_storage_delete' type_id=37 bits_offset=1088
	'max_entries' type_id=1 bits_offset=1152
	'flags' type_id=12 bits_offset=1184
[16] PTR '(anon)' type_id=17
[17] FUNC_PROTO '(anon)' ret_type_id=18 vlen=1
	'(anon)' type_id=19
[18] PTR '(anon)' type_id=4
[19] PTR '(anon)' type_id=1
[20] PTR '(anon)' type_id=21
[21] FUNC_PROTO '(anon)' ret_type_id=18 vlen=2
	'(anon)' type_id=19
	'(anon)' type_id=18
[22] PTR '(anon)' type_id=23
[23] FUNC_PROTO '(anon)' ret_type_id=12 vlen=2
	'(anon)' type_id=19
	'(anon)' type_id=18
[24] PTR '(anon)' type_id=25
[25] FUNC_PROTO '(anon)' ret_type_id=12 vlen=1
	'(anon)' type_id=19
[26] PTR '(anon)' type_id=27
[27] FUNC_PROTO '(anon)' ret_type_id=0 vlen=2
	'(anon)' type_id=10
	'(anon)' type_id=12
[28] PTR '(anon)' type_id=29
[29] FUNC_PROTO '(anon)' ret_type_id=0 vlen=2
	'(anon)' type_id=1
	'(anon)' type_id=0
[30] PTR '(anon)' type_id=31
[31] FUNC_PROTO '(anon)' ret_type_id=12 vlen=2
	'(anon)' type_id=10
	'(anon)' type_id=32
[32] TYPEDEF 'u64' type_id=33
[33] TYPEDEF '__u64' type_id=34
[34] INT 'long long unsigned int' size=8 bits_offset=0 nr_bits=64 encoding=(none)
[35] PTR '(anon)' type_id=36
[36] FUNC_PROTO '(anon)' ret_type_id=10 vlen=3
	'(anon)' type_id=10
	'(anon)' type_id=10
	'(anon)' type_id=12
[37] PTR '(anon)' type_id=38
[38] FUNC_PROTO '(anon)' ret_type_id=12 vlen=1
	'(anon)' type_id=10
[39] INT '(anon)' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[40] STRUCT 'output_table_t' size=56 vlen=8
	'key' type_id=12 bits_offset=0
	'leaf' type_id=1 bits_offset=32
	'ringbuf_output' type_id=41 bits_offset=64
	'ringbuf_reserve' type_id=43 bits_offset=128
	'ringbuf_discard' type_id=45 bits_offset=192
	'ringbuf_submit' type_id=45 bits_offset=256
	'ringbuf_query' type_id=47 bits_offset=320
	'max_entries' type_id=1 bits_offset=384
[41] PTR '(anon)' type_id=42
[42] FUNC_PROTO '(anon)' ret_type_id=12 vlen=3
	'(anon)' type_id=10
	'(anon)' type_id=32
	'(anon)' type_id=32
[43] PTR '(anon)' type_id=44
[44] FUNC_PROTO '(anon)' ret_type_id=10 vlen=1
	'(anon)' type_id=32
[45] PTR '(anon)' type_id=46
[46] FUNC_PROTO '(anon)' ret_type_id=0 vlen=2
	'(anon)' type_id=10
	'(anon)' type_id=32
[47] PTR '(anon)' type_id=48
[48] FUNC_PROTO '(anon)' ret_type_id=32 vlen=1
	'(anon)' type_id=32
[49] INT '(anon)' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[50] ARRAY '(anon)' type_id=5 index_type_id=7 nr_elems=4
[51] INT '(anon)' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[52] PTR '(anon)' type_id=0
[53] PTR '(anon)' type_id=0
[54] PTR '(anon)' type_id=0
[55] PTR '(anon)' type_id=0
[56] PTR '(anon)' type_id=0
[57] PTR '(anon)' type_id=0
[58] PTR '(anon)' type_id=0
[59] PTR '(anon)' type_id=0
[60] PTR '(anon)' type_id=0
[61] PTR '(anon)' type_id=0
```



```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```


# Learning-eBPF-develop

开始学习eBPF的开发，感觉主要分两部分，一部分是内核的eBPF程序，一部分是用户态的程序，用户态选择使用`cilium/ebpf`进行开发，参考[Getting Started with eBPF in Go](https://ebpf-go.dev/guides/getting-started)学习。内核参考[bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)进行学习，打算的顺序是先简单的搭建好用户态的go开发程序和最简单的例子，然后学习内核的开发，把Kernel的eBPF教程过一遍后再继续把eBPF-go的剩余教程走完。





## cilium-ebpf-learn

### Getting Started

主要是搭建好基本的环境。一些环境在学Learning-eBPF-book的时候已经装好了，这里，基本就是装一下go。装go没啥好说的。

教程里有个坑就是要执行下面的命令，不然找不到`<asm/types.h>`。

```bash
ln -sf /usr/include/asm-generic/ /usr/include/asm
```



开发的话一开始想着goland远程ssh去运行项目，查了一下发现jetbrains有这么个功能：

![image-20231205141324827](README.assets/image-20231205141324827.png)

网上查一下配置一下就可以很简单的弄好了：

![image-20231205141535382](README.assets/image-20231205141535382.png)

非常的舒服，相当于直接linux里运行goland就行写代码和调试，远程配置的所有坑都不用踩。不过要把goland都升级到最新版，老版本的这个功能可能有bug。

这里提一句科技进步带来的生产力飞升。记得两年前刚换mac的时候要跑一个只能在linxu里的程序，当时废了很大的劲才弄了个有bug的远程debug，现在很轻松就可以很舒服的远程编程，

之后就是教程中的那个简单的例子，这里不分析代码了。首先写一个eBPF c程序：

```c

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

// count_packets atomically increases a packet counter on every invocation.
SEC("xdp") 
int count_packets() {
    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }

    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL"; 

```

执行`go generate`，这一步是让bpf2go将`counter.c` 编译成 `counter_bpf*.o`，bpf2go底层用的其实还是clang和llvm。这一步其实就是生成`BPF skeleton`，类似于Learning-eBPF-book第5章中提到的，只不过那里的用户态是用c编写的，skeleton是通过`bpftool gen skeleton hello-buffer-config.bpf.o > hello-buffer-config.skel.h`这个命令产生的。

```bash
go generate
Compiled /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfeb.o
Stripped /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfeb.o
Wrote /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfeb.go
Compiled /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfel.o
Stripped /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfel.o
Wrote /home/parallels/Desktop/gopath/src/ebpf-go-test/counter_bpfel.go
```

之所以是两个go文件，教程也说了：

- `*_bpfel.o` and `*_bpfel.go` for little-endian architectures like amd64, arm64, riscv64 and loong64（为了小端架构）
- `*_bpfeb.o` and `*_bpfeb.go` for big-endian architectures like s390(x), mips and sparc（大端架构）

然后写`main.go`：

```go
package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "time"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs counterObjects 
    if err := loadCounterObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    ifname := "lo" // Change this to an interface on your machine.
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.CountPackets,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close() 

    log.Printf("Counting incoming packets on %s..", ifname)

    // Periodically fetch the packet counter from PktCount,
    // exit the program when interrupted.
    tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)
    for {
        select {
        case <-tick:
            var count uint64
            err := objs.PktCount.Lookup(uint32(0), &count) 
            if err != nil {
                log.Fatal("Map lookup:", err)
            }
            log.Printf("Received %d packets", count)
        case <-stop:
            log.Print("Received signal, exiting..")
            return
        }
    }
}

```

我这边的linux可能是因为虚拟机，用别的网口会报没权限，所以用lo

执行：

```bash
go build && sudo ./ebpf-go-test
2023/12/04 18:12:00 Counting incoming packets on lo..

```

修改了c代码的话需要重走一遍流程，让bpf2go重新编译：

```bash
go generate && go build && sudo ./ebpf-test
```

### Portable eBPF



`//go:embed`主要是编译时将对应的`.o`文件插入到字节切片中，这样编出来的可执行文件就不需要包含`.o`文件。还可以加上`CGO_ENABLED=0`，当开启CGO的时候会将文件中引用libc的库（比如常用的net包），以动态链接的方式生成目标文件，因此设置为0就不会依赖libc，进行静态编译。



```bash
#CGO_ENABLED=1
file ./main
./main: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, Go BuildID=CGJl0VvZM18eVkZDq6-D/xNigdfAoPoOcFTI-QFjd/5iFbmB7fcWS8fdc1BP7h/qHV6eRjQotFE200fvarv, with debug_info, not stripped
#CGO_ENABLED=0
file ./main
./main: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=bPcG_mrpYFDA2rinsWaE/ix3vWY-iYyOorijQap23/uYKcCj5isNvGzjZ3AYUj/tO1xWr1jU76-MFqS_ZuP, with debug_info, not stripped

```



交叉编译的话就直接下面的命令就可以指定架构了：

```bash
CGO_ENABLED=0 GOARCH=arm64 go build
```



### Loading eBPF Programs

这一节主要就是在讲`go generate`产生的eBPF ELF文件是怎么被加载进内核中的。其实就是在讲我们调用的那些库函数到底都做了什么，这些跟着教程然后去跟进库里看一下都可以看到。

`CollectionSpec`代表了从ELF文件中提取的ebpf对象，包括map和program，通过`ebpf.LoadCollectionSpec("bpf_prog.o")`这样的形式获得。

获得了ebpf对象后就可以读取相应的map和program，下一步就是将`CollectionSpec`装载进kernel中，形式如下：

```go
// Instantiate a Collection from a CollectionSpec.
coll, err := ebpf.NewCollection(spec)
if err != nil {
    panic(err)
}
```

其实就是从`CollectionSpec`变成了`Collection`。

可以通过`LoadAndAssign`这么一个封装的函数来代替`NewCollection`，它的优点就是可以选择性的装载map和program，类似于这样的例子：

```go
spec, err := ebpf.LoadCollectionSpec("bpf_prog.o")
if err != nil {
    panic(err)
}

// Insert only the resources specified in 'obj' into the kernel and assign
// them to their respective fields. If any requested resources are not found
// in the ELF, this will fail. Any errors encountered while loading Maps or
// Programs will also be returned here.
var objs myObjs
if err := spec.LoadAndAssign(&objs, nil); err != nil {
    panic(err)
}
defer objs.Close()

// Interact with MyMap through the custom struct.
if err := objs.MyMap.Put(uint32(1), uint64(2)); err != nil {
    panic(err)
}
```

这也是实际会用的，跟进一下例子生成的骨架就知道了：

```go
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadCounterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadCounter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}
```



`clang -g`可以将BTF信息包含进eBPF ELF，这些信息可以通过`CollectionSpec.Types`获得，在例子中可以这样：

```go
	spec, err := loadCounter()
	if err != nil {
		log.Fatalf("%s", err)
	}
	fmt.Println(spec.Types.AnyTypeByName("__u64"))
```



### Resource Limits

主要是讲了linux的kernel内存的限制，后面没看太懂是讲什么。

主要是创建eBPF对象需要在内核分配内存，Kernel Version 5.11之前被`RLIMIT_MEMLOCK`限制，5.11之后从rlimits变成了memory cgroup(memcg)。

`rlimit`包就是为了解决5.11之前的限制问题，它有两种行为：

- 引入这个包默认会执行一个副作用的操作，设置当前的`rlimit`为0来使一个map创建失败，然后恢复这个`rlimit`。
- 使用`RemoveMemlock`来移除`RLIMIT_MEMLOCK`的限制，增加`RLIMIT_MEMLOCK`的值到无限大。如果内核支持memcg则不会进行处理。

```go
import "github.com/cilium/ebpf/rlimit"

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        panic(err)
    }
}
```

第一个行为还有别的副作用，感觉会很难遇到，遇到了感觉也不知道怎么去debug，我的内核版本大于5.11应该遇不到问题。

### Section Naming

主要介绍了eBPF里的`SEC`宏，具体的一些东西之前也了解了，杂项宏就是`license`这样的：

```bash
char __license[] SEC("license") = "Dual MIT/GPL";
```

除此之外还有map宏和program宏，map宏除了`.maps`还是别的几个没见过的宏，关于全局变量、常量啥的，这些等到具体写代码的时候再学习了。

### Feature Detection

功能检测主要就是检测对应的内核是否支持相应的功能，使用的是`features`包，它有统一的返回值

- `nil`意味着功能支持
- `ErrNotSupported`意味着功能不支持。
- 其他的错误并不一定能说明功能不支持。

例子：

```go
	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}
	if err != nil {
		// Feature detection was inconclusive.
		//
		// Note: always log and investigate these errors! These can be caused
		// by a lack of permissions, verifier errors, etc. Unless stated
		// otherwise, probes are expected to be conclusive. Please file
		// an issue if this is not the case in your environment.
		panic(err)
	}

	fmt.Println("XDP program type is supported")
```

除此之外还有个`HaveProgramHelper`，不过又说了一些限制，感觉这个包平常也不会用，遇到了再说了。

最后就是`bpftool`也实现了这样的功能检测：

```bash
bpftool feature probe
```

### Object Lifecycle

主要讲eBPF对象的生命周期。对于eBPF对象来说，一般都是一些文件描述符。考虑到这是go语言，因此当go中的对象被垃圾回收器回收的时候，相应的文件描述符也会被关闭。

想要延长eBPF对象的生命周期一种是通过`pin`的方式，其实就类似于这样：

```bash
bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

实际是一个虚拟的文件系统，要删除就是`rm`，在go里是调用`Unpin()`方法。

另外一种就是attach，将program attach hook也可以增加引用计数器，这里说的link我不是很懂，问了newbing是这样回答的：

> 一个Link对象是一个表示BPF程序和钩子之间绑定关系的抽象，它可以让你在Go应用程序中管理这个绑定。你可以通过调用Link对象的Close()方法来解除绑定，或者通过调用Link对象的Pin()方法来将绑定保存到文件系统中，以便在其他应用程序中使用。

看了一下link对象的`Close()`方法的注释，也是说了如果程序中没有明确的调用`Close()`的话，即使go程序停止了，这个link可能仍会继续存在（go中需要调用`Close()`的资源一般好像也是不用明确`Close()`的，因为程序结束自己就会`Close`，写出来只有一种习惯和起警示作用？）

> Close frees resources.
> The link will be broken unless it has been successfully pinned. A link may continue past the lifetime of the process if Close is not called.



最后又讲了一个很抽象的 概念`ProgramArray`，这是一种特殊的类型的array map，它的值是其他程序的文件描述符的引用，可以实现尾调用和允许`ProgramArray`和程序之间创建循环依赖的关系。且有一个硬性规定：

> **Program Arrays require at least one open file descriptor or bpffs pin**.

下面是一些tips，比较有用的就是如果eBPF代码在go程序结束后运行，那么需要`pin ProgramArray`。



官方的教程非常的短，到这里基本就算结束了，剩下的就是去[eBPF Examples](https://github.com/cilium/ebpf/tree/main/examples)去看各种例子还学习用户态的代码，这部分学习完kernel的代码编写再学习了。

### eBPF Examples

TODO

## bpf-developer-tutorial

这部分猜测主要还是在写c，因为对c不熟悉所以非常需要打一个字母出来许多匹配的函数这样的功能，所以肯定不能vim而要用clion了。clion的话配置一下远程：

![image-20231204195836434](README.assets/image-20231204195836434.png)

![image-20231204195852156](README.assets/image-20231204195852156.png)



怎么编译后续就无所谓了，主要是这样改完至少clion会加载远程linux的各种依赖文件，这样敲代码至少不会红，而且也有关键字的提示了。

（后续不用这样了，按照配置goland的那样配一个remove development就行）

### lesson 1-helloworld

一个简单的例子和讲了一个eBPF程序的基本框架和流程：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
 pid_t pid = bpf_get_current_pid_tgid() >> 32;
 if (pid_filter && pid != pid_filter)
  return 0;
 bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
 return 0;
}
```



使用`eunomia-bpf`编译和运行，一行命令即可，比较方便，不用编写userspace的代码。

```bash
ecc minimal.bpf.c&&ecli run package.json
```



进行eBPF开发也基本都是按照这个流程。

- 定义 eBPF 程序的接口和类型：这包括定义 eBPF 程序的接口函数，定义和实现 eBPF 内核映射（maps）和共享内存（perf events），以及定义和使用 eBPF 内核帮助函数（helpers）。
- 编写 eBPF 程序的代码：这包括编写 eBPF 程序的主要逻辑，实现 eBPF 内核映射的读写操作，以及使用 eBPF 内核帮助函数。
- 编译 eBPF 程序：这包括使用 eBPF 编译器（例如 clang）将 eBPF 程序代码编译为 eBPF 字节码，并生成可执行的 eBPF 内核模块。ecc 本质上也是调用 clang 编译器来编译 eBPF 程序。
- 加载 eBPF 程序到内核：这包括将编译好的 eBPF 内核模块加载到 Linux 内核中，并将 eBPF 程序附加到指定的内核事件上。
- 使用 eBPF 程序：这包括监测 eBPF 程序的运行情况，并使用 eBPF 内核映射和共享内存进行数据交换和共享。
- 在实际开发中，还可能需要进行其他的步骤，例如配置编译和加载参数，管理 eBPF 内核模块和内核映射，以及使用其他高级功能等。



### lesson 2-kprobe-unlink

利用kprobe(内核探针)技术，用户可以自己定义回调函数并在内核几乎的所有函数中**动态**的插入探测点。当内核执行流程执行到指定的探测函数时，会调用该回调函数。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

分别用`kprobe`和`kretprobe`在`do_unlinkat`函数的入口和出口处进行hook。

`BPF_KPROBE`和`BPF_KRETPROBE`是宏，被用来挂载到kprobe的eBPFF程序使用。相应的还有`BPF_KPROBE_SYSCALL`，它是专门用于kprobe_syscall的。

宏的参数的第一个是这个eBPF程序的name，剩余的args对应挂载的内核函数的函数参数和函数的返回值。例如`do_unlinkat`的函数参数如下，因此宏中就这样写。

```c
int do_unlinkat(int dfd, struct filename *name)
```



`BPF_CORE_READ`是一种宏，这里首先要提到`bpf_probe_read_kernel`这个辅助函数，在一般的eBPF程序中，这个辅助函数用于从内核的某个结构中读取字段的值，而在CO-RE中，使用`bpf_core_read`来读取，因为它记录了目标内核上重定位的字段的信息，它将 `src` 引用的字段读取 `sz` 字节到 `dst` 指向的内存中。

```c
#define bpf_core_read(dst, sz, src)					    \
	bpf_probe_read_kernel(dst, sz, (const void *)__builtin_preserve_access_index(src))
```

而`BPF_CORE_READ`宏是为了解决大量使用`bpf_core_read`的问题，例如要读取`d = a->b->c->d`，下面一行代码就可以，而用`bpf_core_read`则会很复杂。

```c
d = BPF_CORE_READ(a, b, c, d);

struct b_t *b; struct c_t *c;
    bpf_core_read(&b, 8, &a->b);
    bpf_core_read(&c, 8, &b->c);
    bpf_core_read(&d, 8, &c->d);
```

所以感觉一般用`BPF_CORE_READ()`就比较方便了。

更多的需要阅读[BPF CO-RE reference guide](https://nakryiko.com/posts/bpf-core-reference-guide/)。

`bpf_printk()`辅助函数用来打印debug信息，具体信息可以`cat /sys/kernel/debug/tracing/trace_pipe`查看（如果没有用户态程序的话），其实就类似于`printf`，相关的还有一个`bpf_trace_printk()`，这是Kervel5.2以前用的，有很多缺点不方便，5.2以后基本都用`bpf_printk()`。



头文件中的`vmlinux.h`包含了Linux内核源码中所有的类型定义，用于支持CO-RE。`vmlinux.h`头部有下面的代码：

```c
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif
```

将`preserve_access_index`属性应用于这个文件中所有的数据结构，这个属性的作用是在编译eBPF程序时，记录每个字段访问的相对位置，然后在加载eBPF程序时，根据当前内核的BTF信息，重定位这些字段访问的绝对位置。这个属性是clang-11版本引入的一个专门针对eBPF后端的特性，从而实现一次编译，到处运行。

### lesson 3-fentry-unlink

fentry（function entry）和 fexit（function exit）是 eBPF（扩展的伯克利包过滤器）中的两种探针类型，用于在 Linux 内核函数的入口和退出处进行跟踪，比kprobe更加先进，在x86的处理器上从Kernel 5.5开始支持，在arm处理器上从Kernel 6.0开始支持。

最大的区别就是fexit 程序可以访问函数的输入参数和返回值，而 kretprobe 只能访问返回值。



```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}
```



使用了`BPF_PROG`宏，是一个用于`tp_btf`、`fentry`和`fexit`的宏，可以帮助我们自动做了解析ctx数组与实际参数类型的转化, 并隐藏了ctx指针。

### lesson 4-opensnoop

这一节主要是一个tracepoint和全局变量的例子：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;
    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
```

`pid_target`是一个全局变量，用于在eBPF程序和用户态程序之间进行数据交互。在以前eBPF必须用map。

> 使用全局变量的原理是，全局变量在 eBPF 程序的数据段（data section）中定义并存储。当 eBPF 程序加载到内核并执行时，这些全局变量会保持在内核中，可以通过 BPF 系统调用进行访问。用户态程序可以使用 BPF 系统调用中的某些特性，如 `bpf_obj_get_info_by_fd` 和 `bpf_obj_get_info`，获取 eBPF 对象的信息，包括全局变量的位置和值。





`struct trace_event_raw_sys_enter* ctx`是BTF支持的tracepoint使用的数据结构，来自`<vmlinux.h>`：

```c

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};
```

`tracepoint`支持的事件可以通过`cat /sys/kernel/debug/tracing/available_events`来查看

`tracepoint`挂载点的参数可以通过命令`cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format`来读取：

```bash
name: sys_enter_openat
ID: 565
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

```

`struct trace_entry ent`就是从`common_type`到`common_pid`的部分，id表示tracepoint事件ID，args存储了事件了参数，最多六个。`__data`用于存储额外的数据，如字符串或结构体。例子中没有用`ctx`，我查了下资料学习了一下，比如想获取filename，可以这样：

```c
char *filename = (char *)BPF_CORE_READ(ctx,args[1]);
```





文章中用`ecli`可以控制全局变量但是我本地并没有那个选项，因此必须代码中设置，这个值一般也是用户态程序设置的。

### lesson 5-uprobe-bashreadline

使用uprobe的例子：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

/* Format of u[ret]probe section definition supporting auto-attach:
 * u[ret]probe/binary:function[+offset]
 *
 * binary can be an absolute/relative path or a filename; the latter is resolved to a
 * full binary path via bpf_program__attach_uprobe_opts.
 *
 * Specifying uprobe+ ensures we carry out strict matching; either "uprobe" must be
 * specified (and auto-attach is not possible) or the above format is specified for
 * auto-attach.
 */
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
 char str[MAX_LINE_SIZE];
 char comm[TASK_COMM_LEN];
 u32 pid;

 if (!ret)
  return 0;

 bpf_get_current_comm(&comm, sizeof(comm));

 pid = bpf_get_current_pid_tgid() >> 32;
 bpf_probe_read_user_str(str, sizeof(str), ret);

 bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

 return 0;
};

char LICENSE[] SEC("license") = "GPL";
```

这个和之前那本书中关于`uprobe`的例子不太一样，这么看来`uprobe`其实并不一定只能hook到`.so`中，还可以hook到二进制文件中的函数，格式为：

```c
//binary
SEC("u[ret]probe/binary:function[+offset]")
//.so
SEC("uprobe/usr/lib/aarch64-linux-gnu/libssl.so.3/SSL_write")
```

另外一个点就是`bpf_probe_read_user_str()`，这涉及到读取str，用户态和内核态的原理都差不多。



对于下面的结构体，`name`指向字符串存储的位置，但 `type` 字段实际上是包含字符串的内存

```c
struct my_kernel_type {
    const char *name;
    char type[32];
};
```

有两种读取方式，`bpf_probe_read_kernel_str()`是读取str的辅助函数。这两种方式最好不要混淆。

```c
struct my_kernel_type *t = ...;
const char *p;
char str[32];

//1.
/*通过重定位的方式拿到指针*/
bpf_core_read(&p, sizeof(p), &t->name);
/*读取字符串的值*/
bpf_probe_read_kernel_str(str, sizeof(str), p);

//2.
bpf_core_read_str(str, sizeof(str), &t->type);

```





因此lesson-4里如果想读取filename的话，需要这样：

```c
    char *filename = (char *)BPF_CORE_READ(ctx,args[1]);
    char str[90];
    bpf_probe_read_user_str(str,sizeof(str),filename);
//不是用bpf_probe_read_kernel_str
```



遇到了这么多的函数，终于对CO-RE读取内存有点理清了。

### lesson 6-sigsnoop







## eBPF-Kernel-Code-Tips

这部分主要是记录eBPF程序内核代码编写记得笔记的整理。

`bpftrace`可以列出所有的kprobe和tracepoint。

```bash
sudo bpftrace -l
bpftrace -l 'kprobe:*unlink*'
```









## References

[bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

[Getting Started with eBPF in Go](https://ebpf-go.dev/guides/getting-started)

[What is vmlinux.h?](https://www.grant.pizza/blog/vmlinux-header/)

[BPF CO-RE reference guide](https://nakryiko.com/posts/bpf-core-reference-guide/)，译文参考[[译] BPF CO-RE 参考指南](https://zhuanlan.zhihu.com/p/494293133)
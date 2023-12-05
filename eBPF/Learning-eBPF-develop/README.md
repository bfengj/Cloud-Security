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















## References

[bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

[Getting Started with eBPF in Go](https://ebpf-go.dev/guides/getting-started)

[](https://eunomia.dev/tutorials/0-introduce/)
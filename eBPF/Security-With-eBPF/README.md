# Security-With-eBPF

学习eBPF在安全中的运行，涉及的代码放到了code文件夹。

## execve-hack

拦截 `tp/syscalls/sys_enter_execve`调用并修改成执行`/a`。

此外学习到了go代码设置用户态全局变量的方式：

```go

	spec, err := loadExechijack()
	if err != nil {
		log.Fatal("loadExechijack error", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"target_ppid": int32(11701),
	})
	if err != nil {
		log.Fatal("rewrite constants error,", err)
	}

	objs := exechijackObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatal("LoadAndAssign error,", err)
	}

	defer objs.Close()
```

先获取`spec`然后用`RewriteConstants`函数设置全局变量。

但是有奇怪的bug，经常许多命令读不到filename，或者能读到的情况下修改会失败，执行同一条命令多次会成功至少一次。发现也有别人遇到这种问题：[bpf_probe_read_str return error(-14) sometimes](https://github.com/cilium/ebpf/issues/419) ，[bpf_probe_read_user returns error (-14) on Android 11, Kernel 4.14, ARM64](https://github.com/iovisor/bcc/issues/3175) ，似乎arm64会有这样奇怪的问题，没有成功解决，用`kprobe`似乎可以解决，懒得重构了。





## References

[bpf_probe_read_str return error(-14) sometimes](https://github.com/cilium/ebpf/issues/419)

[bpf_probe_read_user returns error (-14) on Android 11, Kernel 4.14, ARM64](https://github.com/iovisor/bcc/issues/3175)
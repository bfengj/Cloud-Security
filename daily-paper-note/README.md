## 云原生

- 2023.11.02-[k8s环境下etcd利用探索](https://lonmar.cn/2023/02/03/hack-etcd-in-kubernetes/)，除了可以从etcd中读高权限token，还可以写入etcd。

- 2023.11.06-[Malicious code analysis: Abusing SAST (mis)configurations to hack CI systems](https://www.cidersecurity.io/blog/research/malicious-code-analysis-abusing-sast-misconfigurations-to-hack-ci-systems/?utm_source=github&utm_medium=github_page&utm_campaign=ci%2fcd%20goat_060422)，使用SAST静态扫描工具的配置文件去攻击CI系统。

- 2023.11.16-[如何通过捡漏获取价值2600$的Kubernetes组件CVE](https://mp.weixin.qq.com/s/JNzhLPoAMev2okT4LdQxIA)，在可以创建ingress的的权限下通过注入nginx.conf来实现ingress-nginx-controller这个Pod的rce。

- 2023.11.18-[如何从 Kubernetes 节点权限提升至集群管理员权限？](https://github.com/neargle/my-re0-k8s-security/blob/main/paper/1.%E5%A6%82%E4%BD%95%E4%BB%8EKubernetes%E8%8A%82%E7%82%B9%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87%E8%87%B3%E9%9B%86%E7%BE%A4%E7%AE%A1%E7%90%86%E5%91%98%E6%9D%83%E9%99%90.md)，利用DaemonSet配置的高权限ServiceAccount实现提权。

- 2023.12.25-[一个未公开的容器逃逸方式-安全客 - 安全资讯平台](https://www.anquanke.com/post/id/290540)，利用`/proc/xxx/root`来实现容器逃逸。

- 2023.12.26-[KCon/2023/从 0 到 1 打造云原生容器沙箱 vArmor_2023.08.17.pdf at master · knownsec/KCon](https://github.com/knownsec/KCon/blob/master/2023/%E4%BB%8E%200%20%E5%88%B0%201%20%E6%89%93%E9%80%A0%E4%BA%91%E5%8E%9F%E7%94%9F%E5%AE%B9%E5%99%A8%E6%B2%99%E7%AE%B1%20vArmor_2023.08.17.pdf)

- 2023.12.30-[Escaping containers using the Dirty Pipe vulnerability | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/dirty-pipe-container-escape-poc/#breaking-out-from-containers)

- 2024.2.4-[CVE-2024-21626 容器逃逸漏洞分析](https://bestwing.me/CVE-2024-21626-container-escape.html)

- 2024.5.15-[Docker 逃逸中被忽略的 pid namespace | 破壳漏洞挖掘平台](https://tiangonglab.github.io/blog/tiangongarticle030)，提到了通过内核漏洞进行docker逃逸的一些介绍，以及exp中pid ns的问题，作者提到了改`task_struct->thread_pid`的`level`就可以逃pid ns，将`current->thread_info.syscall_work`设置为0就可以绕`seccomp`，感觉偏内核pwn了，web狗看不太懂捏，但是内容很不错。

- 2024.6.4-[Container security fundamentals: Exploring containers as processes | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-1/)，理解一个概念：容器其实是一个进程。

- 2024.6.4-[Container security fundamentals part 2: Isolation & namespaces | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/)，主要介绍了容器的namespace。

- 2024.6.5-[Container security fundamentals part 3: Capabilities | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-3/)，介绍了Capabilities。

- 2024.6.11-[Container security fundamentals part 4: Cgroups | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-4/)

- 2024.6.11-[Container security fundamentals part 5: AppArmor and SELinux | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-5/)

- 2024.6.12-[Container security fundamentals part 6: seccomp | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-6/)

  



## 云服务

- 2023.10.25-[《了解云攻击向量》](https://c-csa.cn/research/results-detail/i-1911/)
- 2023.10.26-[红队视角下的AWS横向移动](https://lonmar.cn/2022/10/01/public-cloud-redteam-attack-surface-summary/)
- 2023.11.16-微信群聊，学习到阿里云CloudShell提权到root的方式。
- 2023.11.21-[Terraform 使用入门以及在云上攻防中的作用](https://wiki.teamssix.com/cloudnative/terraform/terraform-introductory.html)，使用terraform进行云上信息收集。
- 2023.11.22-[阿里云手动接管云控制台](https://forum.butian.net/share/2545)
- 2024.5.10-[(The) Postman Carries Lots of Secrets ◆ Truffle Security Co.](https://trufflesecurity.com/blog/postman-carries-lots-of-secrets)
- 2024.5.31-[AWS CloudQuarry: Digging for Secrets in Public AMIs – Security Café](https://securitycafe.ro/2024/05/08/aws-cloudquarry-digging-for-secrets-in-public-amis/)，一个很大的研究，从AWS的AMI中挖掘secret，非常棒的研究。
- 2024.5.31-[Holes in Your Bitbucket: Why Your CI/CD Pipeline Is Leaking Secrets | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/bitbucket-pipeline-leaking-secrets)，bitbucket的artifact指定的文件中如果有secret会导致泄漏。
- 2024.6.12-[你宁愿不知道的 S3 那些事 --- Things you wish you didn't need to know about S3](https://blog.plerion.com/things-you-wish-you-didnt-need-to-know-about-s3/)，文中介绍了关于aws s3的很多不为人知的小trick，非常有意思。



## CICD

- 2023.11.22-[KCon2023-CICD攻击场景](https://github.com/knownsec/KCon/blob/master/2023/CICD%E6%94%BB%E5%87%BB%E5%9C%BA%E6%99%AF.pdf)，主要列举了CICD的一些攻击场景和攻击思路。
- 2023.11.23-[How we Abused Repository Webhooks to Access Internal CI Systems at Scale](https://www.cidersecurity.io/blog/research/how-we-abused-repository-webhooks-to-access-internal-ci-systems-at-scale/)，通过gitlab的webhook去攻击内网的Jenkins。
- 2024.5.10-[谷歌Flank潜藏3年的Github Action供应链攻击](https://mp.weixin.qq.com/s/-fO-ElGSt6bCXC2nEHVInQ)
- 2024.5.15-[GHSL-2024-041_GHSL-2024-042: GitHub Actions expression injection in KubeBlocks | GitHub Security Lab](https://securitylab.github.com/advisories/GHSL-2024-041_GHSL-2024-042_KubeBlocks/)

## eBPF

- 2023.12.30-[With Friends Like eBPF, Who Needs Enemies? - Black Hat USA 2021 | Briefings Schedule](https://www.blackhat.com/us-21/briefings/schedule/#with-friends-like-ebpf-who-needs-enemies-23619)，pdf太简单了没看太懂，但稍微理解了部分功能。
- 2024.1.7-[使用 eBPF 逃逸容器技术分析与实践](https://paper.seebug.org/1750/)，在CAP_SYS_ADMIN权限的容器里，ebpf程序不会考虑被hook的进程是处于哪个namespace，又处于哪个cgroup，换句话说即使处在容器内，也依旧可以hook容器外的进程。因此利用ebpf程序hook cron和kubelet利用静态Pod来实现容器逃逸。很棒的思路。

## 综合

- 2023.11.14-[Java SpringCloud Heapdump 泄漏到集群接管](https://github.com/Esonhugh/SpringCloudHeapdump/blob/Skyworship/springcloud-java-heapdump-security-Zh.md)，学习Java的Heapdump中读取关键的service account的token，进行后续的攻击，以及后续的攻击思路。
- 2023.12.26-[#BrokenSesame: Accidental ‘write’ permissions to private registry allowed potential RCE to Alibaba Cloud Database Services | Wiz Blog](https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r#appendix-technical-details-50)，非常精彩的一篇文章，非常棒的攻击思路。
- 2024.3.8-[Cross Container Attacks: The Bewildered eBPF on Clouds | USENIX](https://www.usenix.org/conference/usenixsecurity23/presentation/he)，一篇文章USENIX2023的论文，主要讲了用eBPF进行容器逃逸的一些方法，并提出了CapBits模型，用于控制进程的eBPF 特性和保护受害进程免受其他进程 eBPF 攻击特性的侵害

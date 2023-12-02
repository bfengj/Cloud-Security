# Cloud-Security

## About

记录自己关于云安全领域的学习文章、笔记、靶场记录、附件等。



## 项目目录

### AWS

- [aws的相关知识和常见的攻击方式](./AWS/README.md)
- [WIZ-IAM挑战赛的wp](./AWS/WIZ-IAM-Writeup.md)
- [pwnedlabs的writeup](./AWS/pwnedlabs/pwnedlabs.md)

### Azure

TODO

### CI-CD

- [CICD的简单介绍](./CI-CD/)
- [top-10-cicd-security-risks](./CI-CD/top-10-cicd-security-risks)
- [cicd-goat的writeup](./CI-CD/cicd-goat/)
- [gitlab的一些攻击姿势，待补充](./CI-CD/gitlab)
- [Jenkins的一些攻击姿势，待补充](./CI-CD/Jenkins)

### CloudShell

- [遇到的CloudShell的一些知识点](./CloudShell)

  

### CTF

- [Hack.lu-Qualifier-2023](./CTF/2023-Hack.lu/README.md)



### daily-paper-note

这个目录里面放了平常看到的知识文章和议题等的原文和笔记，具体查看此[目录](./daily-paper-note)

### eBPF

- [Learning-eBPF这部分书的学习笔记](./eBPF/Learning-eBPF-book/)



### Kubernetes

- [Kubernetes基础知识学习](./Kubernetes/基础知识.md)
- [Kubernetes中安全相关的知识和攻击](./Kubernetes/Kubernetes安全问题.md)
- [Kubernetes-Goat的笔记](./Kubernetes/Kubernetes-Goat.md)
- [EKSClusterGame的Writeup](./Kubernetes/EKSClusterGame/)

### terraform

- [terraform学习笔记](./terraform)

### tools

- [LocalStack](./tools/LocalStack/)

## 靶场

只记录我刷过的靶场

- [pwnedlabs](https://pwnedlabs.io/)：一个关于aws的靶场，大部分是红队，小部分是蓝队，比较推荐。
- [The Big IAM Challenge](https://bigiamchallenge.com/challenge/1)：一个关于aws iam的ctf比赛，刷完会给一个比较好看的证书，知识点也还不错，推荐入门的时候刷了。
- [cicd-goat](https://github.com/cider-security-research/cicd-goat)：一个关于CI/CD的靶场，目前在刷。
-  [EKSClusterGame](https://eksclustergames.com/challenge/1)，关于 k8s 云原生利用以及集群AWS攻击的靶场。

## 资源

- [TWiki](https://wiki.teamssix.com/CloudSecurityResources/)：有很多的云安全资源。
- [从零开始的Kubernetes攻防](https://github.com/neargle/my-re0-k8s-security#从零开始的kubernetes攻防)：一个关于Kubernetes攻防的文章，知识点很多值得学习。
- [云安全攻防入门](https://lzcloudsecurity.gitbook.io/)
- [eBPF 开发者教程与知识库：eBPF Tutorial by Example](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main)

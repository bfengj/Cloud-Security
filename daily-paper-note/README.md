## 云原生

- 2023.11.02-[k8s环境下etcd利用探索](https://lonmar.cn/2023/02/03/hack-etcd-in-kubernetes/)，除了可以从etcd中读高权限token，还可以写入etcd。
- 2023.11.06-[Malicious code analysis: Abusing SAST (mis)configurations to hack CI systems](https://www.cidersecurity.io/blog/research/malicious-code-analysis-abusing-sast-misconfigurations-to-hack-ci-systems/?utm_source=github&utm_medium=github_page&utm_campaign=ci%2fcd%20goat_060422)，使用SAST静态扫描工具的配置文件去攻击CI系统。
- 2023.11.16-[如何通过捡漏获取价值2600$的Kubernetes组件CVE](https://mp.weixin.qq.com/s/JNzhLPoAMev2okT4LdQxIA)，在可以创建ingress的的权限下通过注入nginx.conf来实现ingress-nginx-controller这个Pod的rce。
- 2023.11.18-[如何从 Kubernetes 节点权限提升至集群管理员权限？](https://github.com/neargle/my-re0-k8s-security/blob/main/paper/1.%E5%A6%82%E4%BD%95%E4%BB%8EKubernetes%E8%8A%82%E7%82%B9%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87%E8%87%B3%E9%9B%86%E7%BE%A4%E7%AE%A1%E7%90%86%E5%91%98%E6%9D%83%E9%99%90.md)，利用DaemonSet配置的高权限ServiceAccount实现提权。



## 云服务

- 2023.10.25-[《了解云攻击向量》](https://c-csa.cn/research/results-detail/i-1911/)
- 2023.10.26-[红队视角下的AWS横向移动](https://lonmar.cn/2022/10/01/public-cloud-redteam-attack-surface-summary/)
- 2023.11.16-微信群聊，学习到阿里云CloudShell提权到root的方式。
- 2023.11.21-[Terraform 使用入门以及在云上攻防中的作用](https://wiki.teamssix.com/cloudnative/terraform/terraform-introductory.html)，使用terraform进行云上信息收集。

## 综合

- 2023.11.14-[Java SpringCloud Heapdump 泄漏到集群接管](https://github.com/Esonhugh/SpringCloudHeapdump/blob/Skyworship/springcloud-java-heapdump-security-Zh.md)，学习Java的Heapdump中读取关键的service account的token，进行后续的攻击，以及后续的攻击思路。

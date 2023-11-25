# 为Gitlab配置Jenkins

## 安装Jenkins

```bash
docker run   -u root   --rm   -d    -p 32080:8080   -p 50002:50000    -v jenkins-data:/var/jenkins_home    -v /var/run/docker.sock:/var/run/docker.sock    jenkinsci/blueocean
```


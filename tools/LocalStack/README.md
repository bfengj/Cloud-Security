# LocalStack

## 安装

```bash
brew install localstack/tap/localstack-cli
localstack start -d
localstack status services
```

## s3

```bash
aws --endpoint-url=http://localhost:4566 s3api create-bucket --bucket sample-bucket
```

## 参考

https://docs.localstack.cloud/overview/

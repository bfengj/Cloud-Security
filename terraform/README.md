# Terraform

中文的翻译文档是https://lonegunmanb.github.io/introduction-terraform/，但是感觉有一些老了；官方的文档中有两部分，一部分是https://developer.hashicorp.com/terraform/tutorials/configuration-language/，另外一部分是https://developer.hashicorp.com/terraform/language，后者的内容更加丰富更加像学习一门新的语言，但是前者知识点较少且例子较多。个人偏向于学习前者，而且官方文档直接浏览器翻译也是比较能看懂的。

## 0x01 初步体验

```
terraform {
  required_providers {
    aws = {
          source  = "hashicorp/aws"
          version = "= 5.25.0"
        }
  }
}
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    acm            = "http://localhost:4566"
    apigateway     = "http://localhost:4566"
    cloudformation = "http://localhost:4566"
    cloudwatch     = "http://localhost:4566"
    dynamodb       = "http://localhost:4566"
    ec2            = "http://localhost:4566"
    es             = "http://localhost:4566"
    firehose       = "http://localhost:4566"
    iam            = "http://localhost:4566"
    kinesis        = "http://localhost:4566"
    lambda         = "http://localhost:4566"
    rds            = "http://localhost:4566"
    redshift       = "http://localhost:4566"
    route53        = "http://localhost:4566"
    s3             = "http://localhost:4566"
    secretsmanager = "http://localhost:4566"
    ses            = "http://localhost:4566"
    sns            = "http://localhost:4566"
    sqs            = "http://localhost:4566"
    ssm            = "http://localhost:4566"
    stepfunctions  = "http://localhost:4566"
    sts            = "http://localhost:4566"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  tags = {
    Name = "XGIT.SJL"
  }
}

```





## 0x02 基础概念

### 2.1 Provier

Terraform被设计成一个多云基础设施编排工具。实现多云编排的方法就是Provider插件机制。Terraform通过RPC调用插件，插件代码通过调用SDK操作远程资源。

声明：

```
terraform {
  required_providers {
    ucloud    = {
      source  = "ucloud/ucloud"
      version = ">=1.24.1"
    }
  }
}

provider "ucloud" {
  public_key  = "your_public_key"
  private_key = "your_private_key"
  project_id  = "your_project_id"
  region      = "cn-bj2"
}
```

source指明了插件的源地址：`[<HOSTNAME>/]<NAMESPACE>/<TYPE>`

`HostName`是选填的，默认是官方的 `registry.terraform.io`，读者也可以构建自己私有的Terraform仓库。`Namespace`是在Terraform仓库内得到组织名，这代表了发布和维护插件的组织或是个人。`Type`是代表插件的一个短名，在特定的`HostName`/`Namespace`下`Type`必须唯一。



多Provier的例子，通过alias来实现：

```
terraform {
  required_version = ">=0.13.5"
  required_providers {
    ucloud    = {
      source  = "ucloud/ucloud"
      version = ">=1.24.1"
    }
  }
}

provider "ucloud" {
  public_key  = "your_public_key"
  private_key = "your_private_key"
  project_id  = "your_project_id"
  region      = "cn-bj2"
}

provider "ucloud" {
  alias       = "ucloudsh"
  public_key  = "your_public_key"
  private_key = "your_private_key"
  project_id  = "your_project_id"
  region      = "cn-sh2"
}

data "ucloud_security_groups" "default" {
  type = "recommend_web"
}

data "ucloud_images" "default" {
  provider          = ucloud.ucloudsh
  availability_zone = "cn-sh2-01"
  name_regex        = "^CentOS 6.5 64"
  image_type        = "base"
}
```

不指明provider则使用默认的provider

### 2.2 状态管理

Terraform将每次执行基础设施变更操作时的状态信息保存在一个状态文件中，默认情况下会保存在当前工作目录下的`terraform.tfstate`文件里。

因为tfstate的明文存储，可能会导致一些安全问题。

为了解决状态文件的存储和共享问题，Terraform引入了远程状态存储机制，也就是Backend。Backend是一种抽象的远程存储接口，如同Provider一样，Backend也支持多种不同的远程存储服务。状态锁是指，当针对一个tfstate进行变更操作时，可以针对该状态文件添加一把全局锁，确保同一时间只能有一个变更被执行。不同的Backend对状态锁的支持不尽相同，实现状态锁的机制也不尽相同。下面以consul为例：

```
terraform {
  required_providers {
    aws = {
          source  = "hashicorp/aws"
          version = "= 5.25.0"
        }

  }
  backend "consul" {
    address = "localhost:8500"
    scheme  = "http"
    path    = "my-aws-project"
  }
}
```



对于多环境的部署，要做到不同的部署，彼此状态文件隔离存储和管理呢，可以使用workspace：

```bash
#创建feature1 workspace
terraform workspace new feature1
#列出所有workspace
terraform workspace list
#选择workspace
terraform workspace select default
#查看当前的workspace
terraform workspace show
#删除workspace
terraform workspace delete feature1
```

workspace的缺点是，由于所有工作区的Backend配置是一样的，所以有权读写某一个Workspace的人可以读取同一个Backend路径下所有其他Workspace；另外Workspace是隐式配置的(调用命令行)，所以有时人们会忘记自己工作在哪个Workspace下。

## 0x03 Terraform代码的书写



### 3.1 资源

资源块声明资源类型和名称。`resource_type.resource_name`

**资源类型始终以提供者名称开头，后跟下划线。资源`random_pet`类型属于`random`提供者。**

资源具有参数、属性和元参数。

- **参数**。配置特定资源；因此，许多参数都是特定于资源的。参数可以是`required`或`optional`，由提供者指定。如果您不提供必需的参数，Terraform 将给出错误并且不应用配置。
- **属性**。是现有资源公开的值。对资源属性的引用采用以下格式`resource_type.resource_name.attribute_name`。与指定基础设施对象配置的参数不同，资源的属性通常由底层云提供商或 API 分配给它。
- **元参数**。更改资源的行为，例如使用`count`元参数创建多个资源。元参数是 Terraform 本身的函数，不是特定于资源或提供者的。



### 3.2 变量

simple类型有boole、string、number，集合类型包括list、map、set：

- **List：**相同类型的值的序列。
- **Map：**一个查找表，将键与值进行匹配，所有类型都相同。
- **Set：**唯一值的无序集合，全部具有相同类型。

变量块具有三个可选参数。

- **描述**：记录变量用途的简短描述。
- **类型**：变量中包含的数据类型。
- **默认值**：默认值。



建议将它们放入一个名为`variables.tf`的单独文件中

```python
variable "instance_count" {
  description = "Number of instances to provision."
  type        = number
  default     = 2
}
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
variable "enable_vpn_gateway" {
  description = "Enable a VPN gateway in your VPC."
  type        = bool
  default     = false
}
variable "public_subnet_cidr_blocks" {
  description = "Available cidr blocks for public subnets."
  type        = list(string)
  default     = [
    "10.0.1.0/24",
    "10.0.2.0/24",
    "10.0.3.0/24",
    "10.0.4.0/24",
  ]
}
#通过slice获得list的子集
slice(var.private_subnet_cidr_blocks, 0, 3)

variable "resource_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = {
    project     = "project-alpha",
    environment = "dev"
  }
}
```



此外还支持两种结构类型：

- **元组：**指定类型的值的固定长度序列。
- **对象：**一个查找表，将一组固定的键与指定类型的值进行匹配。





当变量没有包含默认值的时候，可以通过两种方式赋值。一种是通过命令行：

```bash
terraform apply -var ec2_instance_type=t2.micro
```

另外一种是通过文件赋值：

创建一个`terraform.tfvars`（Terraform 自动加载当前目录中具有确切名称`terraform.tfvars`或与`*.auto.tfvars`匹配的所有文件。还可以通过`-var-file`指定）：

```python
resource_tags = {
  project     = "project-alpha",
  environment = "dev",
  owner       = "me@example.com"
}

ec2_instance_type = "t3.micro"

instance_count = 3
```



terraform支持字符串插值 。允许您使用变量、本地值和函数的输出插入字符串：

```python
name        = "web-sg-${var.resource_tags["project"]}-${var.resource_tags["environment"]}"

name        = "lb-sg-${var.resource_tags["project"]}-${var.resource_tags["environment"]}"

name = "lb-${random_string.lb_id.result}-${var.resource_tags["project"]}-${var.resource_tags["environment"]}"
```



变量还可以添加`validation`来限制变量的可能值：

```python
variable "resource_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = {
    project     = "my-project",
    environment = "dev"
  }

  validation {
    condition     = length(var.resource_tags["project"]) <= 16 && length(regexall("[^a-zA-Z0-9-]", var.resource_tags["project"])) == 0
    error_message = "The project tag must be no more than 16 characters, and only contain letters, numbers, and hyphens."
  }

  validation {
    condition     = length(var.resource_tags["environment"]) <= 8 && length(regexall("[^a-zA-Z0-9-]", var.resource_tags["environment"])) == 0
    error_message = "The environment tag must be no more than 8 characters, and only contain letters, numbers, and hyphens."
  }
}
```





### 3.3 敏感变量

变量中加上`sensitive   = true`声明为敏感变量。通过此操作可以确保不会意外在 CLI 输出、日志输出或源代码管理中公开此数据

```python
variable "db_username" {
  description = "Database administrator username"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Database administrator password"
  type        = string
  sensitive   = true
}

```

为敏感变量设置值有两种方式，一种是使用`.tfvars`。例如创建`secret.tfvars`：

```python
db_username = "admin"
db_password = "insecurepassword"
```

使用的时候指定这个文件：

```bash
terraform apply -var-file="secret.tfvars"
```



还可以使用环境变量设置。当 Terraform 运行时，它会在环境中查找与模式匹配的变量`TF_VAR_<VARIABLE_NAME>`，并将这些值分配给配置中相应的 Terraform 变量：

```bash
export TF_VAR_db_username=admin TF_VAR_db_password=adifferentpassword
```



如果输出中涉及到敏感变量会报错：

```python
output "db_connect_string" {
  description = "MySQL database connection string"
  value       = "Server=${aws_db_instance.database.address}; Database=ExampleDB; Uid=${var.db_username}; Pwd=${var.db_password}"
}
```

将`db_connect_string`设置为敏感可以解决，但是输出的仍然会是`db_connect_string = <sensitive>`：

```python
output "db_connect_string" {
  description = "MySQL database connection string"
  value       = "Server=${aws_db_instance.database.address}; Database=ExampleDB; Uid=${var.db_username}; Pwd=${var.db_password}"
  sensitive   = true
}
```



但是状态文件`terraform.tfstate`中存储的仍然是明文。



### 3.4 Local Values

```python
locals {
  name_suffix = "${var.resource_tags["project"]}-${var.resource_tags["environment"]}"
}

name = "vpc-${local.name_suffix}"
```

Terraform 本地值（或“本地变量”）为表达式或值分配名称。使用本地变量可以简化您的 Terraform 配置。由于可以多次引用本地变量，因此可以减少代码中的重复。本地变量还可以通过使用有意义的名称而不是硬编码值来帮助您编写更可读的配置。



## 参考

https://lonegunmanb.github.io/introduction-terraform/

https://wiki.teamssix.com/cloudnative/terraform/terraform-introductory.html
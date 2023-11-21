# Terraform

中文的翻译文档是https://lonegunmanb.github.io/introduction-terraform/，但是感觉有一些老了；官方的文档中有两部分，一部分是https://developer.hashicorp.com/terraform/tutorials/configuration-language/，另外一部分是https://developer.hashicorp.com/terraform/language，后者的内容更加丰富更加像学习一门新的语言，但是前者知识点较少且例子较多。个人偏向于学习前者，而且官方文档直接浏览器翻译也是比较能看懂的。且只简单的学习，做基本的笔记，复杂的情况以后要开发terraform的时候再学习。

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

### 3.5 输出

[可以使用任何 Terraform表达式](https://developer.hashicorp.com/terraform/tutorials/configuration-language/expressions)的结果作为输出的值。

```python
output "lb_url" {
  description = "URL of load balancer"
  value       = "http://${module.elb_http.elb_dns_name}/"
}

output "web_server_count" {
  description = "Number of web servers provisioned"
  value       = length(module.ec2_instances.instance_ids)
}
```





`terraform output`命令可以查询所有的输出，`terraform output lb_url`可以按名称单个查询。`terraform output -raw lb_url`可以去除引号的包括。

可以设置输出为敏感输出：

```python
output "db_username" {
  description = "Database administrator username"
  value       = aws_db_instance.database.username
  sensitive   = true
}

output "db_password" {
  description = "Database administrator password"
  value       = aws_db_instance.database.password
  sensitive   = true
}


####
Outputs:

db_password = <sensitive>
db_username = <sensitive>
```

在plan、apply或destory配置时，或者在您查询所有输出时，Terraform 将编辑敏感输出。其他情况下，将不会编辑敏感输出，例如按名称查询的时候：

```bash
terraform output db_password

"notasecurepassword"
```

指定`-json`可以生成机器可读的json形式：

```bash
terraform output -json
```

### 3.6 数据源

数据源允许查询或计算一些数据以供其他地方使用。使用数据源可以使得Terraform代码使用在Terraform管理范围之外的一些信息，或者是读取其他Terraform代码保存的状态。

每一种Provider都可以在定义一些资源类型的同时定义一些数据源。



在data块体(花括号中间的内容)是传给数据源的查询条件。查询条件参数的种类取决于数据源的类型。

引用数据源数据的语法是`data.<TYPE>.<NAME>.<ATTRIBUTE>`。

```python
# Find the latest available AMI that is tagged with Component = web
data "aws_ami" "web" {
  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "tag:Component"
    values = ["web"]
  }

  most_recent = true
}

#data.<TYPE>.<NAME>.<ATTRIBUTE>
resource "aws_instance" "web" {
  ami           = data.aws_ami.web.id
  instance_type = "t1.micro"
}
```

### 3.7 依赖

大多数时候，Terraform 会根据给定的配置推断资源之间的依赖关系，以便以正确的顺序创建和销毁资源。然而，有时，Terraform 无法推断基础设施不同部分之间的依赖关系，您需要使用`depends_on`参数创建显式依赖关系

例如下面的例子就是隐式依赖。弹性ip`aws_eip`关联于`aws_instance.example_a`，因此terraform必须先创建`aws_instance.example_a`再创建`aws_eip`，且可以并行的创建`aws_instance.example_b`。Terraform会自动推断一种资源是否依赖另一种资源，这是隐式依赖。

```python
provider "aws" {
  region = var.aws_region
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "example_a" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"
}

resource "aws_instance" "example_b" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"
}

resource "aws_eip" "ip" {
  vpc      = true
  instance = aws_instance.example_a.id
}
```



如果ec2的应用程序需要依赖s3存储桶，这就是显式依赖，但是Terraform无法推断出，就需要显式声明：

```python
resource "aws_s3_bucket" "example" { }

resource "aws_instance" "example_c" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"

  depends_on = [aws_s3_bucket.example]
}

module "example_sqs_queue" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "3.3.0"

  depends_on = [aws_s3_bucket.example, aws_instance.example_c]
}
```

### 3.8 count

想要创建和管理一系列similar的对象的时候，可以使用`count`或者`for_each`。count可以用于Module和resource类型

```python
resource "aws_instance" "server" {
  count = 4 # create four similar EC2 instances

  ami           = "ami-a1b2c3d4"
  instance_type = "t2.micro"

  tags = {
    Name = "Server ${count.index}"
  }
}
```

但是count必须接受一个在Terraform执行任何远程资源操作之前就已经的值。

- `<type>.<name>`or `module.<NAME>` (for example, `aws_instance.server`) refers to the resource block.
- `<type>.<name>[<index>]`or `module.<NAME>[<INDEX>]` (for example, `aws_instance.server[0]`, `aws_instance.server[1]`, etc.) refers to individual instances.



可以使用count来实现获取list中的元素来设置：

```python
variable "subnet_ids" {
  type = list(string)
}

resource "aws_instance" "server" {
  # Create one instance for each subnet
  count = length(var.subnet_ids)

  ami           = "ami-a1b2c3d4"
  instance_type = "t2.micro"
  subnet_id     = var.subnet_ids[count.index]

  tags = {
    Name = "Server ${count.index}"
  }
}
```

但是更好的方法是使用`for_each`。



### 3.9 for_each

`for_each`和count的区别在于`for_each`用于设置相似的对象中区别的地方并不是简单的数字的情况。`for_each`参数接受一个map或者一个字符串`set`

例如：

```python
resource "azurerm_resource_group" "rg" {
  for_each = {
    a_group = "eastus"
    another_group = "westus2"
  }
  name     = each.key
  location = each.value
}

resource "aws_iam_user" "the-accounts" {
  for_each = toset( ["Todd", "James", "Alice", "Dottie"] )
  name     = each.key
}
```



- [`each.key`](https://developer.hashicorp.com/terraform/language/meta-arguments/for_each#each-key) — The map key (or set member) corresponding to this instance.
- [`each.value`](https://developer.hashicorp.com/terraform/language/meta-arguments/for_each#each-value) — The map value corresponding to this instance. (If a set was provided, this is the same as `each.key`.)

`for_each`中同count一样也必须是执行远程资源操纵之前就已知的值。



用`for_each`关联资源：

```python
variable "vpcs" {
  type = map(object({
    cidr_block = string
  }))
}

resource "aws_vpc" "example" {
  # One VPC for each element of var.vpcs
  for_each = var.vpcs

  # each.value here is a value from var.vpcs
  cidr_block = each.value.cidr_block
}

resource "aws_internet_gateway" "example" {
  # One Internet Gateway per VPC
  for_each = aws_vpc.example

  # each.value here is a full aws_vpc object
  vpc_id = each.value.id
}

output "vpc_ids" {
  value = {
    for k, v in aws_vpc.example : k => v.id
  }

  # The VPCs aren't fully functional until their
  # internet gateways are running.
  depends_on = [aws_internet_gateway.example]
}
```



### 3.10 functions

可以用函数来执行动态的操作。



ec2的`user_data`。创建`user_data.tftpl`：

```sh
#!/bin/bash

# Install necessary dependencies
sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade
sudo apt-get -y -qq install curl wget git vim apt-transport-https ca-certificates
sudo add-apt-repository ppa:longsleep/golang-backports -y
sudo apt -y -qq install golang-go

# Setup sudo to allow no-password sudo for your group and adding your user
sudo groupadd -r ${department}
sudo useradd -m -s /bin/bash ${name}
sudo usermod -a -G ${department} ${name}
sudo cp /etc/sudoers /etc/sudoers.orig
echo "${name} ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/${name}

# Create GOPATH for your user & download the webapp from github
sudo -H -i -u ${name} -- env bash << EOF
cd /home/${name}
export GOROOT=/usr/lib/go
export GOPATH=/home/${name}/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
go get -d github.com/hashicorp/learn-go-webapp-demo
cd go/src/github.com/hashicorp/learn-go-webapp-demo
go run webapp.go
EOF
```

创建变量：

```python
variable "user_name" {
  description = "The user creating this infrastructure"
  default     = "terraform"
}

variable "user_department" {
  description = "The organization the user belongs to: dev, prod, qa"
  default     = "learn"
}
```

在`aws_instance`中指定`user_data`：

```python
resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.subnet_public.id
  vpc_security_group_ids      = [aws_security_group.sg_8080.id]
  associate_public_ip_address = true
  user_data                   = templatefile("user_data.tftpl", { department = var.user_department, name = var.user_name })
}
```





`lookup`函数用于根据指定的key从映射中获取value：

```python
lookup(map, key, default)
lookup({a="ay", b="bee"}, "a", "what?")
```

`file`函数读取给定路径文件的内容并将其作为字符串返回：

```python
resource "aws_key_pair" "ssh_key" {
  key_name = "ssh_key"
  public_key = file("ssh_key.pub")
}
resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.subnet_public.id
  vpc_security_group_ids      = [aws_security_group.sg_22.id, aws_security_group.sg_8080.id]
  associate_public_ip_address = true
  user_data                   = templatefile("user_data.tftpl", { department = var.user_department, name = var.user_name })
  key_name                    = aws_key_pair.ssh_key.key_name
}
```

### 3.11 expressions

条件表达式：

```python
resource "random_id" "id" {
  byte_length = 8
}

locals {
  name  = (var.name != "" ? var.name : random_id.id.hex)
  owner = var.team
  common_tags = {
    Owner = local.owner
    Name  = local.name
  }
}

```



`splat`表达式：

```python
resource "aws_instance" "ubuntu" {
  count                       = (var.high_availability == true ? 3 : 1)
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  associate_public_ip_address = (count.index == 0 ? true : false)
  subnet_id                   = aws_subnet.subnet_public.id
  tags                        = merge(local.common_tags)
}


output "private_addresses" {
  description = "Private DNS for AWS instances"
  value       = aws_instance.ubuntu[*].private_dns
}
```

## 0x04 Terraform模块

## 4.1 创建模块

实际上所有包含Terraform代码文件的文件夹都是一个Terraform模块。我们如果直接在一个文件夹内执行`terraform apply`或者`terraform plan`命令，那么当前所在的文件夹就被称为根模块(root module)。我们也可以在执行Terraform命令时通过命令行参数指定根模块的路径。

一般来讲，在一个模块中，会有：

- 一个`README`文件，用来描述模块的用途。文件名可以是`README`或者`README.md`，后者应采用Markdown语法编写。可以考虑在`README`中用可视化的图形来描绘创建的基础设施资源以及它们之间的关系。`README`中不需要描述模块的输入输出，因为工具会自动收集相关信息。如果在`README`中引用了外部文件或图片，请确保使用的是带有特定版本号的绝对URL路径以防止未来指向错误的版本
- 一个`LICENSE`描述模块使用的许可协议。如果你想要公开发布一个模块，最好考虑包含一个明确的许可证协议文件，许多组织不会使用没有明确许可证协议的模块
- 一个[examples文件夹](https://github.com/hashicorp/terraform-aws-consul/tree/master/examples)用来给出一个调用样例(可选)
- 一个`variables.tf`文件，包含模块所有的输入变量。输入变量应该有明确的描述说明用途
- 一个`outputs.tf`文件，包含模块所有的输出值。输出值应该有明确的描述说明用途
- 嵌入模块文件夹，出于封装复杂性或是复用代码的目的，我们可以在modules子目录下建立一些嵌入模块。所有包含README文件的嵌入模块都可以被外部用户使用；不含`README`文件的模块被认为是仅在当前模块内使用的(可选)
- 一个`main.tf`，它是模块主要的入口点。对于一个简单的模块来说，可以把所有资源都定义在里面；如果是一个比较复杂的模块，我们可以把创建的资源分布到不同的代码文件中，但引用嵌入模块的代码还是应保留在`main.tf`里
- 其他定义了各种基础设施对象的代码文件(可选)

### 4.2 使用模块

在 Terraform 代码中引用一个模块，使用的是 `module` 块。

每当在代码中新增、删除或者修改一个 `module` 块之后，都要执行 `terraform init` 或是 `terraform get` 命令来获取模块代码并安装到本地磁盘上。



module中可以使用许多元参数，例如`source`、`version`、`providers`、`count`、`for_each`、`depends_on`。



对于source，Terraform 目前支持如下模块源：

- 本地路径
- Terraform Registry
- GitHub
- Bitbucket
- 通用Git、Mercurial仓库
- HTTP地址
- S3 buckets
- GCS buckets



```python
provider "aws" {
  region = "us-west-2"

  default_tags {
    tags = {
      hashicorp-learn = "module-use"
    }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.18.1"

  name = var.vpc_name
  cidr = var.vpc_cidr

  azs             = var.vpc_azs
  private_subnets = var.vpc_private_subnets
  public_subnets  = var.vpc_public_subnets

  enable_nat_gateway = var.vpc_enable_nat_gateway

  tags = var.vpc_tags
}

module "ec2_instances" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "4.3.0"

  count = 2
  name  = "my-ec2-cluster-${count.index}"

  ami                    = "ami-0c5204531f799e0c6"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [module.vpc.default_security_group_id]
  subnet_id              = module.vpc.public_subnets[0]

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
```





## 参考

https://lonegunmanb.github.io/introduction-terraform/

https://wiki.teamssix.com/cloudnative/terraform/terraform-introductory.html
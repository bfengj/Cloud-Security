

```
provider "tencentcloud" {
  secret_id  = var.tencentcloud_secret_id
  secret_key = var.tencentcloud_secret_key
  region     = "ap-beijing"
}

data "tencentcloud_cos_buckets" "cos_buckets" {
}

data "tencentcloud_instances" "cvm_instances" {
}

data "tencentcloud_cam_users" "cam_users" {
}


```



```
output "tencent_cloud_cos_bucket_list" {
  value = data.tencentcloud_cos_buckets.cos_buckets.bucket_list
}

output "tencent_cloud_cvm_instances_list" {
  value = data.tencentcloud_instances.cvm_instances.instance_list
}

output "tencent_cloud_cam_users_list" {
  value = data.tencentcloud_cam_users.cam_users.user_list
}

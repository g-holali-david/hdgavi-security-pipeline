output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "The ID of the public subnet"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "The ID of the web security group"
  value       = aws_security_group.web.id
}

output "s3_bucket_name" {
  description = "The name of the logs S3 bucket"
  value       = aws_s3_bucket.logs.id
}

# Output important values for the infrastructure

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "load_balancer_dns" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "load_balancer_url" {
  description = "Full URL of the Application Load Balancer"
  value       = "http://${aws_lb.main.dns_name}"
}

output "database_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "database_name" {
  description = "RDS PostgreSQL database name"
  value       = aws_db_instance.main.db_name
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = aws_elasticache_replication_group.session_store.primary_endpoint_address
  sensitive   = true
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.main.id
}

output "cognito_client_secret" {
  description = "Cognito User Pool Client Secret"
  value       = aws_cognito_user_pool_client.main.client_secret
  sensitive   = true
}

output "s3_bucket_name" {
  description = "S3 bucket name for application storage"
  value       = aws_s3_bucket.app_storage.bucket
}

output "deployment_bucket_name" {
  description = "S3 bucket name for deployment artifacts"
  value       = aws_s3_bucket.deployment_bucket.bucket
}

output "cloudwatch_dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "auto_scaling_group_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.app.name
}

output "database_password" {
  description = "Database password (randomly generated)"
  value       = random_password.db_password.result
  sensitive   = true
}

# Environment Variables for Application Configuration
output "environment_variables" {
  description = "Environment variables needed for the Flask application"
  value = {
    DATABASE_URL    = "postgresql://${var.db_username}:${random_password.db_password.result}@${aws_db_instance.main.endpoint}/${var.db_name}"
    REDIS_URL       = "redis://${aws_elasticache_replication_group.session_store.primary_endpoint_address}:6379"
    AWS_REGION      = var.aws_region
    COGNITO_USER_POOL_ID = aws_cognito_user_pool.main.id
    COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.main.id
    COGNITO_CLIENT_SECRET = aws_cognito_user_pool_client.main.client_secret
    S3_BUCKET_NAME       = aws_s3_bucket.app_storage.bucket
    DEPLOYMENT_BUCKET    = aws_s3_bucket.deployment_bucket.bucket
  }
  sensitive = true
}
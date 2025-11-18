#!/bin/bash

# Terraform Deployment Script for Storage Manager Infrastructure
# This script automates the deployment of AWS infrastructure using Terraform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    printf "${1}${2}${NC}\n"
}

print_color $BLUE "🚀 Storage Manager Infrastructure Deployment"
print_color $BLUE "============================================="

# Check if terraform is installed
if ! command -v terraform &> /dev/null; then
    print_color $RED "❌ Terraform is not installed. Please install Terraform first."
    exit 1
fi

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    print_color $RED "❌ AWS CLI is not configured. Please run 'aws configure' first."
    exit 1
fi

print_color $GREEN "✅ Prerequisites check passed"

# Check if terraform.tfvars exists
if [ ! -f "terraform.tfvars" ]; then
    print_color $YELLOW "⚠️  terraform.tfvars not found. Creating from example..."
    cp terraform.tfvars.example terraform.tfvars
    print_color $YELLOW "📝 Please edit terraform.tfvars with your specific values"
    print_color $YELLOW "Press Enter to continue when ready..."
    read
fi

# Initialize Terraform
print_color $BLUE "📦 Initializing Terraform..."
terraform init

# Validate configuration
print_color $BLUE "🔍 Validating Terraform configuration..."
terraform validate

if [ $? -eq 0 ]; then
    print_color $GREEN "✅ Configuration is valid"
else
    print_color $RED "❌ Configuration validation failed"
    exit 1
fi

# Plan the deployment
print_color $BLUE "📋 Planning deployment..."
terraform plan -var-file="terraform.tfvars" -out=tfplan

# Ask for confirmation
print_color $YELLOW "🤔 Do you want to apply this plan? (y/N): "
read -r confirmation

if [[ $confirmation =~ ^[Yy]$ ]]; then
    # Apply the plan
    print_color $BLUE "🚀 Applying infrastructure changes..."
    terraform apply tfplan
    
    if [ $? -eq 0 ]; then
        print_color $GREEN "✅ Infrastructure deployed successfully!"
        
        # Show important outputs
        print_color $BLUE "\n📊 Infrastructure Information:"
        print_color $BLUE "=============================="
        
        echo "Load Balancer URL:"
        terraform output load_balancer_url
        
        echo -e "\nCloudWatch Dashboard:"
        terraform output cloudwatch_dashboard_url
        
        echo -e "\nAuto Scaling Group:"
        terraform output auto_scaling_group_name
        
        print_color $YELLOW "\n🔒 Sensitive outputs (use 'terraform output <name>' to view):"
        print_color $YELLOW "- database_endpoint"
        print_color $YELLOW "- redis_endpoint"
        print_color $YELLOW "- database_password"
        print_color $YELLOW "- cognito_client_secret"
        print_color $YELLOW "- environment_variables"
        
        print_color $GREEN "\n🎉 Deployment completed successfully!"
        print_color $BLUE "📖 Check the README.md for next steps and configuration details."
    else
        print_color $RED "❌ Deployment failed"
        exit 1
    fi
else
    print_color $YELLOW "⏸️  Deployment cancelled"
    # Clean up plan file
    rm -f tfplan
fi

# Clean up plan file
rm -f tfplan
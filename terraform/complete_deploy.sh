#!/bin/bash

# Complete Infrastructure and Application Deployment Orchestrator
# This script handles the entire deployment process

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║           🚀 Storage Manager Deployment System 🚀           ║"
    echo "║                                                              ║"
    echo "║     Complete AWS Infrastructure + Flask App Deployment      ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

print_color() {
    printf "${1}${2}${NC}\n"
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "${BLUE}🔸 $1${NC}\n"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

check_prerequisites() {
    print_step "Checking Prerequisites"
    
    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        print_color $RED "❌ Terraform is not installed. Please install Terraform first."
        echo "   Download from: https://www.terraform.io/downloads.html"
        exit 1
    fi
    print_color $GREEN "✅ Terraform found: $(terraform version | head -1)"
    
    # Check if AWS CLI is configured
    if ! aws sts get-caller-identity &> /dev/null; then
        print_color $RED "❌ AWS CLI is not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    AWS_REGION=$(aws configure get region)
    print_color $GREEN "✅ AWS CLI configured"
    print_color $BLUE "   Account: $AWS_ACCOUNT"
    print_color $BLUE "   Region: $AWS_REGION"
    
    # Check if git is available
    if ! command -v git &> /dev/null; then
        print_color $RED "❌ Git is not installed."
        exit 1
    fi
    print_color $GREEN "✅ Git found: $(git --version)"
}

configure_terraform() {
    print_step "Configuring Terraform Variables"
    
    if [ ! -f "terraform.tfvars" ]; then
        print_color $YELLOW "📝 Creating terraform.tfvars from template..."
        cp terraform.tfvars.example terraform.tfvars
        
        print_color $YELLOW "⚡ Auto-configuring basic settings..."
        
        # Auto-configure with defaults
        sed -i.bak "s/us-west-2/$(aws configure get region || echo 'us-west-2')/g" terraform.tfvars
        
        print_color $BLUE "📋 Configuration file created: terraform.tfvars"
        print_color $YELLOW "🔧 You can edit terraform.tfvars to customize settings"
        
        echo -e "\n${YELLOW}Current configuration:${NC}"
        cat terraform.tfvars
        
        echo -e "\n${YELLOW}Continue with these settings? (y/N):${NC}"
        read -r confirmation
        if [[ ! $confirmation =~ ^[Yy]$ ]]; then
            print_color $BLUE "📝 Please edit terraform.tfvars and run this script again"
            exit 0
        fi
    else
        print_color $GREEN "✅ terraform.tfvars already exists"
    fi
}

deploy_infrastructure() {
    print_step "Deploying AWS Infrastructure"
    
    print_color $BLUE "🔧 Initializing Terraform..."
    terraform init
    
    print_color $BLUE "🔍 Validating configuration..."
    terraform validate
    
    if [ $? -ne 0 ]; then
        print_color $RED "❌ Terraform validation failed"
        exit 1
    fi
    
    print_color $BLUE "📋 Planning infrastructure deployment..."
    terraform plan -var-file="terraform.tfvars" -out=tfplan
    
    echo -e "\n${YELLOW}Deploy this infrastructure? (y/N):${NC}"
    read -r confirmation
    if [[ $confirmation =~ ^[Yy]$ ]]; then
        print_color $BLUE "🚀 Deploying infrastructure..."
        terraform apply tfplan
        
        if [ $? -eq 0 ]; then
            print_color $GREEN "✅ Infrastructure deployed successfully!"
        else
            print_color $RED "❌ Infrastructure deployment failed"
            exit 1
        fi
    else
        print_color $YELLOW "⏸️  Infrastructure deployment cancelled"
        rm -f tfplan
        exit 0
    fi
    
    # Clean up plan file
    rm -f tfplan
}

show_deployment_info() {
    print_step "Deployment Information"
    
    print_color $GREEN "🎉 Deployment completed successfully!"
    
    echo -e "\n${BLUE}📊 Infrastructure Information:${NC}"
    echo "=============================="
    
    ALB_URL=$(terraform output -raw load_balancer_url 2>/dev/null || echo "Not available")
    DASHBOARD_URL=$(terraform output -raw cloudwatch_dashboard_url 2>/dev/null || echo "Not available")
    ASG_NAME=$(terraform output -raw auto_scaling_group_name 2>/dev/null || echo "Not available")
    
    print_color $GREEN "🌐 Application URL: $ALB_URL"
    print_color $BLUE "📊 CloudWatch Dashboard: $DASHBOARD_URL"
    print_color $BLUE "⚖️  Auto Scaling Group: $ASG_NAME"
    
    echo -e "\n${BLUE}🔒 Sensitive Information:${NC}"
    echo "========================="
    print_color $YELLOW "Use these commands to view sensitive outputs:"
    echo "  terraform output database_endpoint"
    echo "  terraform output redis_endpoint"
    echo "  terraform output database_password"
    echo "  terraform output cognito_client_secret"
    echo "  terraform output -json environment_variables"
    
    echo -e "\n${BLUE}⏳ Application Startup:${NC}"
    echo "======================"
    print_color $YELLOW "The Flask application is being deployed automatically on EC2 instances."
    print_color $YELLOW "This process takes 5-10 minutes. You can monitor progress by:"
    echo "1. SSH to EC2 instances (use AWS Console or Session Manager)"
    echo "2. Check deployment logs: tail -f /var/log/user-data.log"
    echo "3. Monitor health: curl $ALB_URL/health"
    
    echo -e "\n${BLUE}🔧 Manual Health Check:${NC}"
    echo "======================"
    print_color $BLUE "Once deployment is complete, test the application:"
    echo "curl $ALB_URL/health"
    echo "curl $ALB_URL/"
    
    echo -e "\n${BLUE}📚 Next Steps:${NC}"
    echo "=============="
    print_color $YELLOW "1. Wait 5-10 minutes for application deployment to complete"
    print_color $YELLOW "2. Test application health: curl $ALB_URL/health"
    print_color $YELLOW "3. Access application: $ALB_URL"
    print_color $YELLOW "4. Login as admin: admin@storagemanager.com / AdminPass123!"
    print_color $YELLOW "5. CHANGE THE DEFAULT PASSWORD immediately"
    print_color $YELLOW "6. Configure your storage providers"
    print_color $YELLOW "7. Set up domain and SSL certificate"
}

check_application_health() {
    print_step "Application Health Check"
    
    ALB_URL=$(terraform output -raw load_balancer_url 2>/dev/null)
    
    if [ -z "$ALB_URL" ]; then
        print_color $RED "❌ Cannot get load balancer URL"
        return 1
    fi
    
    print_color $BLUE "🏥 Checking application health..."
    print_color $BLUE "URL: $ALB_URL"
    
    # Wait for application to start
    print_color $YELLOW "⏳ Waiting for application to start (this may take 5-10 minutes)..."
    
    for i in {1..60}; do
        if curl -f -s "$ALB_URL/health" >/dev/null 2>&1; then
            print_color $GREEN "✅ Application is healthy!"
            print_color $GREEN "🌐 Application URL: $ALB_URL"
            
            # Test main endpoint
            if curl -f -s "$ALB_URL/" >/dev/null 2>&1; then
                print_color $GREEN "✅ Main application endpoint is responding"
            else
                print_color $YELLOW "⚠️  Health endpoint OK, but main app may still be starting"
            fi
            return 0
        else
            if [ $((i % 10)) -eq 0 ]; then
                print_color $YELLOW "⏳ Still waiting... ($i/60 checks)"
            fi
            sleep 10
        fi
    done
    
    print_color $RED "❌ Application health check failed after 10 minutes"
    print_color $YELLOW "📋 Troubleshooting tips:"
    echo "1. Check EC2 instances in AWS Console"
    echo "2. SSH to instances and check: sudo tail -f /var/log/user-data.log"
    echo "3. Check application logs: sudo journalctl -u storagemanager"
    echo "4. Verify database connectivity"
    return 1
}

cleanup() {
    print_step "Cleanup Options"
    
    echo -e "\n${YELLOW}Do you want to destroy the infrastructure? (y/N):${NC}"
    read -r confirmation
    if [[ $confirmation =~ ^[Yy]$ ]]; then
        print_color $RED "🗑️  Destroying infrastructure..."
        terraform destroy -var-file="terraform.tfvars"
    else
        print_color $BLUE "💾 Infrastructure preserved"
    fi
}

main() {
    clear
    print_banner
    
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            configure_terraform
            deploy_infrastructure
            show_deployment_info
            
            echo -e "\n${YELLOW}Check application health now? (y/N):${NC}"
            read -r confirmation
            if [[ $confirmation =~ ^[Yy]$ ]]; then
                check_application_health
            fi
            ;;
            
        "health")
            check_application_health
            ;;
            
        "destroy")
            cleanup
            ;;
            
        "info")
            show_deployment_info
            ;;
            
        *)
            echo "Usage: $0 [deploy|health|destroy|info]"
            echo ""
            echo "Commands:"
            echo "  deploy  - Complete infrastructure and application deployment (default)"
            echo "  health  - Check application health status"
            echo "  destroy - Destroy all infrastructure"
            echo "  info    - Show deployment information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
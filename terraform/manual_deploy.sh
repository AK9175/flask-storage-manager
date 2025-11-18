#!/bin/bash

# Manual Application Deployment Script for Your Local StorageManager
# This script deploys your current StorageManager application to running EC2 instances

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_color() {
    printf "${1}${2}${NC}\n"
}

print_color $BLUE "🚀 Manual StorageManager Application Deployment"
print_color $BLUE "=============================================="

# Check if we're in the right directory
if [ ! -f "app_new.py" ] && [ ! -f "backend/app_new.py" ]; then
    print_color $RED "❌ This script must be run from your StorageManager root directory"
    print_color $YELLOW "Current directory: $(pwd)"
    print_color $YELLOW "Expected files: app_new.py or backend/app_new.py"
    exit 1
fi

# Check if terraform outputs are available
if [ ! -d "terraform" ]; then
    print_color $RED "❌ Terraform directory not found"
    exit 1
fi

cd terraform

# Get the Auto Scaling Group name and other info
ASG_NAME=$(terraform output -raw auto_scaling_group_name 2>/dev/null)
REGION=$(terraform output -raw aws_region 2>/dev/null || echo "us-west-2")
DEPLOYMENT_BUCKET=$(terraform output -raw deployment_bucket_name 2>/dev/null)

if [ -z "$ASG_NAME" ]; then
    print_color $RED "❌ Could not get Auto Scaling Group name from terraform output"
    print_color $YELLOW "Make sure your terraform infrastructure is deployed"
    exit 1
fi

print_color $GREEN "✅ Found infrastructure:"
print_color $BLUE "   Auto Scaling Group: $ASG_NAME"
print_color $BLUE "   Region: $REGION"
print_color $BLUE "   Deployment Bucket: $DEPLOYMENT_BUCKET"

# Go back to app root
cd ..

# Create deployment package
print_color $BLUE "📦 Creating deployment package..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PACKAGE_NAME="storagemanager_${TIMESTAMP}.zip"

# Create temporary directory for packaging
TEMP_DIR="/tmp/storagemanager_deploy"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

# Copy application files (excluding unnecessary files)
print_color $BLUE "📄 Copying application files..."
rsync -av --exclude='terraform/' \
          --exclude='.git/' \
          --exclude='__pycache__/' \
          --exclude='*.pyc' \
          --exclude='.env' \
          --exclude='venv/' \
          --exclude='.venv/' \
          --exclude='instance/' \
          --exclude='flask_session/' \
          --exclude='emails/' \
          --exclude='.DS_Store' \
          --exclude='*.log' \
          ./ "$TEMP_DIR/"

# Create zip package
cd "$TEMP_DIR"
zip -r "/tmp/$PACKAGE_NAME" . > /dev/null
cd - > /dev/null

print_color $GREEN "✅ Created deployment package: /tmp/$PACKAGE_NAME"

# Upload to S3 deployment bucket
print_color $BLUE "☁️  Uploading to S3 deployment bucket..."
aws s3 cp "/tmp/$PACKAGE_NAME" "s3://$DEPLOYMENT_BUCKET/app.zip" --region "$REGION"

if [ $? -eq 0 ]; then
    print_color $GREEN "✅ Application uploaded to S3 successfully"
else
    print_color $RED "❌ Failed to upload to S3"
    exit 1
fi

# Get EC2 instance IDs from the Auto Scaling Group
print_color $BLUE "🔍 Finding EC2 instances..."
INSTANCE_IDS=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --region "$REGION" \
    --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId" \
    --output text)

if [ -z "$INSTANCE_IDS" ]; then
    print_color $RED "❌ No running instances found in Auto Scaling Group"
    exit 1
fi

print_color $GREEN "✅ Found instances: $INSTANCE_IDS"

# Create deployment script for instances
DEPLOY_SCRIPT="/tmp/deploy_to_instance.sh"
cat > "$DEPLOY_SCRIPT" << 'EOF'
#!/bin/bash
set -e

echo "🚀 Deploying StorageManager application..."

# Stop the application service
sudo systemctl stop storagemanager || true

# Backup current application (if exists)
if [ -d "/opt/storagemanager/app" ]; then
    sudo mv /opt/storagemanager/app "/opt/storagemanager/app_backup_$(date +%Y%m%d_%H%M%S)"
fi

# Create new app directory
sudo mkdir -p /opt/storagemanager/app
cd /opt/storagemanager/app

# Download and extract new application code
echo "📥 Downloading application from S3..."
aws s3 cp s3://DEPLOYMENT_BUCKET/app.zip /tmp/app.zip
sudo unzip -q /tmp/app.zip -d /opt/storagemanager/app/
rm /tmp/app.zip

# Set ownership
sudo chown -R storageapp:storageapp /opt/storagemanager/app

# Install/update dependencies if requirements.txt exists
if [ -f "/opt/storagemanager/app/requirements.txt" ]; then
    echo "📦 Installing dependencies..."
    source /opt/storagemanager/venv/bin/activate
    pip install -r /opt/storagemanager/app/requirements.txt
    pip install gunicorn psycopg2-binary redis boto3
fi

# Restart the application service
echo "🔄 Restarting application..."
sudo systemctl start storagemanager

# Wait a moment and check status
sleep 5
if sudo systemctl is-active storagemanager > /dev/null; then
    echo "✅ Application restarted successfully"
    
    # Test health endpoint
    for i in {1..10}; do
        if curl -f -s http://localhost/health > /dev/null; then
            echo "✅ Application health check passed"
            break
        elif [ $i -eq 10 ]; then
            echo "⚠️  Health check failed, but service is running"
        else
            echo "⏳ Waiting for application to start... ($i/10)"
            sleep 3
        fi
    done
else
    echo "❌ Application failed to start"
    echo "📋 Service status:"
    sudo systemctl status storagemanager --no-pager -l
    exit 1
fi

echo "🎉 Deployment completed successfully"
EOF

# Replace the placeholder in the script
sed -i "s/DEPLOYMENT_BUCKET/$DEPLOYMENT_BUCKET/g" "$DEPLOY_SCRIPT"

# Deploy to each instance using SSM (Session Manager)
print_color $BLUE "🚀 Deploying to EC2 instances..."

for INSTANCE_ID in $INSTANCE_IDS; do
    print_color $BLUE "📤 Deploying to instance: $INSTANCE_ID"
    
    # Copy deployment script to instance
    aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"$(cat $DEPLOY_SCRIPT | base64 -w 0 | base64 -d)\"]" \
        --region "$REGION" \
        --output table || {
        
        print_color $YELLOW "⚠️  SSM command failed, trying alternative method..."
        
        # Alternative: upload script and run
        aws ssm send-command \
            --instance-ids "$INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=[
                "aws s3 cp s3://'$DEPLOYMENT_BUCKET'/app.zip /tmp/app.zip",
                "sudo systemctl stop storagemanager || true",
                "sudo rm -rf /opt/storagemanager/app_old",
                "sudo mv /opt/storagemanager/app /opt/storagemanager/app_old || true",
                "sudo mkdir -p /opt/storagemanager/app",
                "cd /opt/storagemanager/app",
                "sudo unzip -q /tmp/app.zip -d /opt/storagemanager/app/",
                "sudo chown -R storageapp:storageapp /opt/storagemanager/app",
                "source /opt/storagemanager/venv/bin/activate && pip install -r /opt/storagemanager/app/requirements.txt",
                "sudo systemctl start storagemanager",
                "sleep 5",
                "curl -f http://localhost/health && echo \"Health check passed\" || echo \"Health check failed\""
            ]' \
            --region "$REGION" \
            --output table
    }
    
    sleep 2
done

# Clean up
rm -f "$DEPLOY_SCRIPT"
rm -rf "$TEMP_DIR"
rm -f "/tmp/$PACKAGE_NAME"

print_color $GREEN "🎉 Deployment initiated on all instances!"
print_color $BLUE "📊 You can check the deployment status in AWS Console:"
print_color $BLUE "   Systems Manager > Run Command"
print_color $BLUE ""
print_color $BLUE "🌐 Test your application:"
ALB_URL=$(terraform output -raw load_balancer_url 2>/dev/null)
print_color $BLUE "   Health Check: $ALB_URL/health"
print_color $BLUE "   Application: $ALB_URL/"
print_color $BLUE ""
print_color $YELLOW "⏳ Allow 2-3 minutes for deployment to complete on all instances"
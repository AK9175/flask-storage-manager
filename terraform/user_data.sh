#!/bin/bash

# Storage Manager Flask Application Deployment Script
# This script runs on EC2 instance startup to deploy the application

set -e

# Log everything
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting Storage Manager deployment at $(date)"

# Update system and install dependencies
yum update -y
yum install -y git python3 python3-pip python3-devel gcc postgresql-devel nginx
yum install -y amazon-cloudwatch-agent

# Install latest Python packages
pip3 install --upgrade pip
pip3 install virtualenv

# Create application user
useradd -r -s /bin/false storageapp
mkdir -p /opt/storagemanager
chown storageapp:storageapp /opt/storagemanager

# Create application directory structure
cd /opt/storagemanager
mkdir -p app
cd app

# Download application code from S3 deployment bucket
echo "Downloading application code from S3..."
aws s3 cp s3://${deployment_bucket}/app.zip /tmp/app.zip

if [ -f "/tmp/app.zip" ]; then
    echo "Extracting application code..."
    unzip -q /tmp/app.zip -d /opt/storagemanager/app/
    rm /tmp/app.zip
    echo "Application code extracted successfully"
else
    echo "Warning: Could not download application from S3"
    exit 1
fi

chown -R storageapp:storageapp /opt/storagemanager
# Create virtual environment and install dependencies
sudo -u storageapp python3 -m venv /opt/storagemanager/venv
source /opt/storagemanager/venv/bin/activate
pip install -r requirements.txt

# Create production environment file
cat > /opt/storagemanager/app/.env.production << EOF
FLASK_ENV=production
FLASK_APP=app_new.py
DATABASE_URL=postgresql://${db_username}:${db_password}@${db_host}/${db_name}
REDIS_URL=redis://${redis_host}:6379
AWS_DEFAULT_REGION=${aws_region}
SECRET_KEY=$(openssl rand -base64 32)
JWT_SECRET_KEY=$(openssl rand -base64 32)
SESSION_TYPE=redis
SESS_REDIS_URL=redis://${redis_host}:6379
EOF

# Wait for database to be ready
echo "Waiting for database to be ready..."
while ! pg_isready -h ${db_host} -p 5432 -U ${db_username}; do
    echo "Database not ready, waiting..."
    sleep 10
done

# Initialize database
echo "Initializing database..."
cd /opt/storagemanager/app
export $(cat .env.production | xargs)
python3 -c "
from backend.app import create_app
from backend.app import db
app = create_app()
with app.app_context():
    db.create_all()
    print('Database tables created successfully')
"

# Create systemd service
cat > /etc/systemd/system/storagemanager.service << EOF
[Unit]
Description=Storage Manager Flask Application
After=network.target

[Service]
Type=simple
User=storageapp
WorkingDirectory=/opt/storagemanager/app
Environment=PATH=/opt/storagemanager/venv/bin
EnvironmentFile=/opt/storagemanager/app/.env.production
ExecStart=/opt/storagemanager/venv/bin/python -m gunicorn --bind 0.0.0.0:5000 --workers 3 --timeout 120 backend.app_new:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx as reverse proxy
cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    upstream app {
        server 127.0.0.1:5000;
    }

    server {
        listen 80;
        server_name _;

        location /health {
            access_log off;
            return 200 "healthy\n";
        }

        location / {
            proxy_pass http://app;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_connect_timeout 30;
            proxy_send_timeout 30;
            proxy_read_timeout 30;
        }

        location /static {
            alias /opt/storagemanager/app/frontend/static;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }
    }
}
EOF

# Install Gunicorn in virtual environment
source /opt/storagemanager/venv/bin/activate
pip install gunicorn psycopg2-binary redis

# Set permissions
chown -R storageapp:storageapp /opt/storagemanager
chmod 644 /opt/storagemanager/app/.env.production

# Enable and start services
systemctl daemon-reload
systemctl enable storagemanager
systemctl enable nginx
systemctl start nginx
systemctl start storagemanager

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "metrics": {
    "namespace": "${project_name}",
    "metrics_collected": {
      "cpu": {
        "measurement": [
          "cpu_usage_idle",
          "cpu_usage_iowait",
          "cpu_usage_user",
          "cpu_usage_system"
        ],
        "metrics_collection_interval": 60,
        "totalcpu": false
      },
      "disk": {
        "measurement": [
          "used_percent"
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "*"
        ]
      },
      "diskio": {
        "measurement": [
          "io_time"
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "*"
        ]
      },
      "mem": {
        "measurement": [
          "mem_used_percent"
        ],
        "metrics_collection_interval": 60
      },
      "netstat": {
        "measurement": [
          "tcp_established",
          "tcp_time_wait"
        ],
        "metrics_collection_interval": 60
      },
      "swap": {
        "measurement": [
          "swap_used_percent"
        ],
        "metrics_collection_interval": 60
      }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/${project_name}",
            "log_stream_name": "{instance_id}/var/log/messages"
          }
        ]
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
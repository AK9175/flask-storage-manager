# Storage Manager - Multi-Tenant Cloud Storage Platform

A modern web application for managing files across multiple cloud storage providers with a clean and intuitive interface. This platform enables admins to provide cost-effective cloud storage access to users through various providers like AWS S3, Google Cloud Storage, Cloudflare R2, and more.

![Storage Manager Architecture](static/img/screenshot.png)

## 🚀 Features

- 📁 **Multi-Cloud Support** - AWS S3, Google Cloud, Cloudflare R2, Wasabi, Backblaze B2, and more
- 👥 **Multi-Tenant Architecture** - Admins manage isolated user groups
- 🔒 **AWS Cognito Authentication** - Secure JWT-based authentication
- 📋 **Bucket Request Management** - User-requested access with admin approval
- 🔑 **Fine-Grained Permissions** - IAM policy generation for secure access
- 💰 **Cost Optimization** - Access cheaper storage providers through admin accounts
- 📱 **Responsive Design** - Works on desktop and mobile devices

## 🏗️ Architecture

### **Application Flow**
1. **Admins** sign up and configure cloud storage providers
2. **Admins** invite users via email
3. **Users** sign up through invitation links
4. **Users** request access to specific buckets
5. **Admins** approve requests and set permissions
6. **Users** access cloud storage through the platform

### **Tech Stack**
- **Backend**: Python Flask with SQLAlchemy
- **Authentication**: AWS Cognito with JWT
- **Database**: SQLite (development), PostgreSQL-ready (production)
- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript
- **Containerization**: Docker & Docker Compose
- **Cloud Integration**: Multi-provider SDK support

---

## 📦 Deployment Guide

### Prerequisites

Before you begin, ensure you have:
- **Docker** installed on your system
- **Docker Compose** installed (usually comes with Docker Desktop)
- **AWS Account** with Cognito User Pool configured
- **Git** for cloning the repository

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone <repository-url>

# Navigate to the project directory
cd StorageManager
```

### Step 2: Environment Configuration

#### 📋 Create Environment File

Copy the example environment file and configure it with your settings:

```bash
cp .env.example .env
```

#### ⚙️ Configure Environment Variables

Edit the `.env` file with your configuration. Here's what each section contains:

```bash
# Flask Configuration
FLASK_ENV=development
FLASK_SECRET_KEY=your-super-secret-key-change-in-production

# Database Configuration
DATABASE_PATH=/app/instance/storage_manager.db

# Encryption Key for Provider Credentials
# Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=your-generated-fernet-key-here

# AWS Cognito Configuration (REQUIRED)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-west-1
COGNITO_USER_POOL_ID=us-west-1_XXXXXXXXX
COGNITO_USER_POOL_CLIENT_ID=your_client_id
COGNITO_USER_POOL_CLIENT_SECRET=your_client_secret
COGNITO_DOMAIN=your-cognito-domain.auth.us-west-1.amazoncognito.com
COGNITO_CALLBACK_URL=http://localhost:5001/auth/callback  # Change to production URL
COGNITO_LOGOUT_URL=http://localhost:5001/auth/user/login  # Change to production URL

# Email Configuration (Optional - for user invitations)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
MAIL_USE_TLS=True

# Application Configuration
APP_URL=http://localhost:5001  # Change to your production domain in production
LOG_LEVEL=INFO
SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
MAX_UPLOAD_SIZE=1073741824
```

#### 🔑 AWS Cognito Setup

1. **Create User Pool:**
   - Go to AWS Console → Cognito → User Pools
   - Create a new User Pool
   - Configure email as username
   - Note down the User Pool ID

2. **Create App Client:**
   - In your User Pool → App integration → App clients
   - Create a new app client
   - Note down the Client ID and Client Secret (if using confidential client)

3. **Configure Domain:**
   - In your User Pool → App integration → Domain
   - Create a Cognito domain or use custom domain
   - Note down the domain URL

#### 🔐 Generate Encryption Key

Generate a secure encryption key for storing provider credentials:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output and set it as your `ENCRYPTION_KEY` in the `.env` file.

---

### Step 3: Docker Installation

#### 🐳 Install Docker

**Windows:**
1. Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
2. Run the installer and follow the setup wizard
3. Start Docker Desktop
4. Open PowerShell/Command Prompt and verify: `docker --version`

**macOS:**
1. Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
2. Drag Docker.app to Applications folder
3. Start Docker Desktop from Applications
4. Open Terminal and verify: `docker --version`

**Linux (Ubuntu/Debian):**
```bash
# Update package index
sudo apt update

# Install Docker
sudo apt install docker.io docker-compose

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to docker group (optional, avoids sudo)
sudo usermod -aG docker $USER

# Verify installation
docker --version
docker-compose --version
```

**Linux (CentOS/RHEL):**
```bash
# Install Docker
sudo yum install docker docker-compose

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Verify installation
docker --version
```

---

### Step 4: Deploy with Docker

#### 🚀 One-Command Deployment

```bash
# Build and start the application
docker-compose up --build
```

#### 🔧 Alternative: Step-by-Step Deployment

```bash
# Build the Docker image
docker-compose build

# Start the application
docker-compose up

# Run in background (detached mode)
docker-compose up -d
```

#### 📋 Deployment Commands Reference

```bash
# View application logs
docker-compose logs storage-manager

# Stop the application
docker-compose down

# Restart the application
docker-compose restart

# Rebuild and restart
docker-compose up --build

# View running containers
docker ps

# Access container shell (for debugging)
docker exec -it storage-manager-app bash
```

---

### Step 5: Access the Application

Once deployed, your application will be available at:

🌐 **Development URL**: http://localhost:5001  
🌐 **Production URL**: https://yourdomain.com (configure in .env)

#### 📱 Available Interfaces

- **Landing Page**: http://localhost:5001 (or your production domain)
- **Admin Signup**: http://localhost:5001/auth/admin/signup
- **Admin Login**: http://localhost:5001/auth/admin/login
- **User Login**: http://localhost:5001/auth/user/login

> **Note**: In production, replace `localhost:5001` with your actual domain name and use HTTPS.

---

## 🔧 Configuration Details

### 🗄️ Database

- **Development**: SQLite (automatically created)
- **Production**: PostgreSQL-ready (update DATABASE_URL in environment)
- **Persistence**: Data persists between container restarts via Docker volumes

### 🔐 Security

- **Authentication**: AWS Cognito with JWT tokens
- **Authorization**: Role-based access (Admin/User)
- **Encryption**: Provider credentials encrypted with Fernet
- **Sessions**: Server-side session storage

### 📁 File Storage

- **Volume Mounts**: Database, sessions, and email files persist on host
- **Uploads**: Configurable max upload size (default: 1GB)
- **Providers**: Multi-cloud support with admin-configured credentials

---

## 🚀 Usage Guide

### For Admins

1. **Sign Up**: Create admin account at `/auth/admin/signup`
2. **Configure Providers**: Add cloud storage credentials in dashboard
3. **Invite Users**: Send email invitations to users
4. **Manage Requests**: Approve/reject user bucket access requests
5. **Set Permissions**: Define fine-grained access policies

### For Users

1. **Sign Up**: Use invitation link from admin
2. **Request Access**: Submit bucket access requests
3. **Access Storage**: Use approved cloud storage through the platform
4. **File Management**: Upload, download, and manage files

---

## 🛠️ Troubleshooting

### Common Issues

**Port 5001 already in use:**
```bash
# Find what's using the port
sudo lsof -i :5001

# Or change port in docker-compose.yml
ports:
  - "5002:5001"
```

**AWS Credentials Error:**
```bash
# Verify your .env file has:
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=your_region
```

**Database Issues:**
```bash
# Reset database
rm -rf instance/storage_manager.db
docker-compose restart
```

**Container Won't Start:**
```bash
# Check logs
docker-compose logs storage-manager

# Rebuild from scratch
docker-compose down
docker system prune -f
docker-compose up --build
```

### 🔍 Health Checks

The application includes health monitoring:
- **Health Endpoint**: http://localhost:5001/ping
- **Docker Health Check**: Automatically monitors container health
- **Application Logs**: Available via `docker-compose logs`

---

## 🔄 Updates & Maintenance

### Updating the Application

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up --build
```

### Backup Data

```bash
# Backup database and files
cp -r instance/ backup/
cp -r flask_session/ backup/
cp -r emails/ backup/
```

### Production Deployment

For production deployment, consider:

1. **Environment Variables**: 
   - Set `FLASK_ENV=production`
   - Update `APP_URL` to your production domain (e.g., `https://yourdomain.com`)
   - Set `SESSION_COOKIE_SECURE=True` for HTTPS
   - Update `COGNITO_CALLBACK_URL` and `COGNITO_LOGOUT_URL` to production URLs
2. **Security**: Use strong secrets and HTTPS
3. **Database**: Use PostgreSQL instead of SQLite
4. **Reverse Proxy**: Use Nginx for SSL termination
5. **Domain Configuration**: 
   - Point your domain to your server
   - Configure SSL certificates
   - Update Cognito app client callback URLs in AWS Console
6. **Monitoring**: Set up application monitoring
7. **Backups**: Implement automated backup strategy

#### Production Environment Variables Example:
```bash
FLASK_ENV=production
APP_URL=https://yourdomain.com
SESSION_COOKIE_SECURE=True
COGNITO_CALLBACK_URL=https://yourdomain.com/auth/callback
COGNITO_LOGOUT_URL=https://yourdomain.com/auth/user/login
```

---

## 📞 Support

For support and questions:
- **Issues**: Open an issue in the repository
- **Documentation**: Check the project documentation
- **Email**: Contact the maintainers

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for efficient cloud storage management**
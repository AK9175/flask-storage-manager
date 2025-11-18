"""
Storage Manager - Main Flask Application
Multi-tenant cloud storage management with admin-controlled access
"""
import os
import logging
from flask import render_template, redirect, url_for, request, g
from dotenv import load_dotenv

# Import the app factory and models
from backend.app import create_app
from backend.app.models import db, Admin, User
from backend.app.utils.cognito_utils import cognito_jwt_required, cognito_admin_required

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app using the factory
app = create_app()

@app.get("/ping")
def ping():
    return "pong", 200
# ============================================================================
# Before/After Request Hooks
# ============================================================================

@app.before_request
def before_request_logging():
    """Log all incoming requests."""
    logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr} - Host: {request.host}")

# ============================================================================
# Routes
# ============================================================================

@app.route('/')
def index():
    """Landing page."""
    token = request.cookies.get('access_token')
    if token:
        # Redirect logged-in users to their dashboards
        user_type = request.cookies.get('user_type')
        if user_type == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index_landing.html')


@app.route('/user/dashboard')
@cognito_jwt_required
def user_dashboard():
    """User dashboard."""
    cognito_sub = g.get('cognito_user_sub', None)
    if cognito_sub:
        admin = db.session.query(Admin).filter_by(cognito_sub=cognito_sub).first()
        if admin:
            return redirect(url_for('admin_dashboard'))
    return render_template('user/dashboard.html')


@app.route('/admin/dashboard')
@cognito_jwt_required
@cognito_admin_required
def admin_dashboard():
    """Admin dashboard."""
    admin = g.get('current_admin', None)
    if not admin:
        return redirect(url_for('auth.admin_login'))
    return render_template('admin/dashboard.html', admin=admin)


@app.route('/admin/providers/ui')
@cognito_jwt_required
@cognito_admin_required
def manage_providers_ui():
    """Render provider management UI page."""
    admin = g.get('current_admin', None)
    if not admin:
        return redirect(url_for('auth.admin_login'))
    return render_template('provider_management.html', admin=admin)


@app.route('/user/bucket-requests-ui')
@cognito_jwt_required
def user_bucket_requests_ui():
    """Render user bucket requests management page."""
    # Check if current user is admin (redirect if so)
    cognito_sub = g.get('cognito_user_sub', None)
    if cognito_sub:
        admin = db.session.query(Admin).filter_by(cognito_sub=cognito_sub).first()
        if admin:
            return redirect(url_for('admin_dashboard'))
    return render_template('user/bucket_requests.html')


@app.route('/admin/bucket-requests-ui')
@cognito_jwt_required
@cognito_admin_required
def admin_bucket_requests_ui():
    """Render admin bucket requests management UI page."""
    admin = g.get('current_admin', None)
    if not admin:
        return redirect(url_for('auth.admin_login'))
    return render_template('admin/bucket_requests_ui.html', admin=admin)


@app.route('/user/bucket-management-ui')
@cognito_jwt_required
def user_bucket_management_ui():
    """Render user bucket management UI page."""
    # Check if current user is admin (redirect if so)
    cognito_sub = g.get('cognito_user_sub', None)
    if cognito_sub:
        admin = db.session.query(Admin).filter_by(cognito_sub=cognito_sub).first()
        if admin:
            return redirect(url_for('admin_dashboard'))
    return render_template('user/bucket_management_ui.html')


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(error)}")
    return render_template('errors/500.html'), 500


# ============================================================================
# CLI Commands
# ============================================================================

@app.cli.command('init-db')
def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully!")


@app.cli.command('create-admin')
def create_admin_user():
    """Create a new admin user (CLI command)."""
    import getpass
    from backend.app.utils.auth_utils import hash_password
    
    with app.app_context():
        email = input('Admin Email: ').strip().lower()
        first_name = input('First Name: ').strip()
        last_name = input('Last Name: ').strip()
        password = getpass.getpass('Password: ')
        confirm_password = getpass.getpass('Confirm Password: ')
        
        if password != confirm_password:
            logger.error('Passwords do not match!')
            return
        
        if Admin.query.filter_by(email=email).first():
            logger.error('Admin with this email already exists!')
            return
        
        # Type: ignore - SQLAlchemy dynamic model attributes
        admin = Admin(  # type: ignore
            email=email, # type: ignore
            first_name=first_name, # type: ignore
            last_name=last_name, # type: ignore
            password_hash=hash_password(password), # type: ignore
            is_active=True # type: ignore
        )
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Admin user created: {email}")


# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

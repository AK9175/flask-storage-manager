"""
Application factory and initialization
"""
import os
import sys
import logging
from datetime import timedelta
from flask import Flask
from flask_login import LoginManager
from flask_session import Session
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)
# Also add backend paths for route imports
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'backend', 'app', 'routes'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'backend', 'app', 'utils'))

# Configure logging
logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config=None):
    """Application factory function"""
    from backend.app.config import get_config
    from backend.app.models import User, Admin, AnonymousUser
    from backend.app.routes import register_blueprints
    
    # Get template and static folders from frontend directory
    template_folder = os.path.join(PROJECT_ROOT, 'frontend', 'templates')
    static_folder = os.path.join(PROJECT_ROOT, 'frontend', 'static')
    
    # Create Flask app with proper template and static paths
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    
    # Disable host matching for better network compatibility
    app.url_map.strict_slashes = False
    
    # Load configuration
    if config is None:
        config = get_config(os.environ.get('FLASK_ENV', 'development'))
    app.config.from_object(config)
    
    # Initialize Flask-Session for server-side session storage
    # Configuration to minimize session creation
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = False  # Disable signer to avoid bytes/string mismatch
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_REFRESH_EACH_REQUEST'] = False  # Don't refresh session on every request
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    Session(app)
    
    # Initialize database AFTER config is set
    from backend.app.models import db
    db.init_app(app)
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.anonymous_user = AnonymousUser
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID"""
        if user_id.startswith('admin_'):
            admin_id = int(user_id.replace('admin_', ''))
            return Admin.query.get(admin_id)
        else:
            return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized():
        """Redirect to login if not authenticated"""
        from flask import redirect, url_for
        return redirect(url_for('auth.user_login'))
    
    # Register blueprints (must be after db init)
    register_blueprints(app)
    
    # Create tables and initialize DB
    with app.app_context():
        db.create_all()
    
    # Register cleanup function to delete session files on shutdown
    def cleanup_sessions():
        """Delete all session files when app shuts down."""
        import shutil
        session_dir = os.path.join(PROJECT_ROOT, 'flask_session')
        if os.path.exists(session_dir):
            try:
                shutil.rmtree(session_dir)
                logger.info("Cleaned up session files")
            except Exception as e:
                logger.error(f"Error cleaning up session files: {str(e)}")
    
    import atexit
    atexit.register(cleanup_sessions)
    
    return app

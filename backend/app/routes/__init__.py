"""
Routes module - contains all application routes
"""
import sys
import os

# Add parent directory to path so routes can import from root level
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def register_blueprints(app):
    """Register all blueprints with the Flask app"""
    # Import blueprints from this directory
    from .auth_routes import auth_bp
    from .admin_routes import admin_bp
    from .admin_bucket_routes import admin_bucket_bp
    from .provider_routes import provider_bp
    from .user_routes import user_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_bucket_bp)
    app.register_blueprint(provider_bp)
    app.register_blueprint(user_bp)

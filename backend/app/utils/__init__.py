"""
Utility functions for the application
"""
import logging
from flask_login import current_user

logger = logging.getLogger(__name__)


def is_admin(user=None):
    """Check if user is an admin"""
    from backend.app.models import Admin
    if user is None:
        user = current_user
    return isinstance(user, Admin)


def is_authenticated_user():
    """Check if current user is authenticated"""
    return current_user.is_authenticated


def get_user_type():
    """Get the type of current user"""
    if not current_user.is_authenticated:
        return 'anonymous'
    return 'admin' if is_admin() else 'user'


def log_action(action, user_id=None, details=None):
    """Log an action"""
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    
    log_msg = f"Action: {action}"
    if user_id:
        log_msg += f" | User: {user_id}"
    if details:
        log_msg += f" | Details: {details}"
    
    logger.info(log_msg)


# Import utility modules for easier access
try:
    from auth_utils import hash_password, verify_password, generate_token, verify_token
except ImportError:
    pass

try:
    from s3_utils import (
        upload_to_s3, download_from_s3, delete_from_s3, 
        list_s3_files, get_s3_file_url
    )
except ImportError:
    pass

try:
    from iam_policy_generator import generate_iam_policy
except ImportError:
    pass

try:
    from email_templates_utils import (
        render_email_template, send_email
    )
except ImportError:
    pass


__all__ = [
    'is_admin',
    'is_authenticated_user', 
    'get_user_type',
    'log_action'
]

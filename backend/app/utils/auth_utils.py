"""
Authentication utilities: password hashing, token validation, email sending.
"""
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
from functools import wraps
from flask import jsonify

logger = logging.getLogger(__name__)

# Password hasher
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its hash."""
    try:
        ph.verify(password_hash, password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def send_email(to_email: str, subject: str, html_body: str, text_body: str = None) -> bool:
    """
    Send an email via SMTP.
    
    Environment variables:
    - MAIL_SERVER: SMTP server (default: smtp.gmail.com)
    - MAIL_PORT: SMTP port (default: 587)
    - MAIL_USERNAME: SMTP username (required)
    - MAIL_PASSWORD: SMTP password (required)
    - MAIL_DEFAULT_SENDER: From address (default: MAIL_USERNAME if not set)
    - MAIL_USE_TLS: Use TLS (default: True)
    """
    try:
        mail_server = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
        mail_port = int(os.environ.get('MAIL_PORT', 587))
        mail_username = os.environ.get('MAIL_USERNAME')
        mail_password = os.environ.get('MAIL_PASSWORD')
        mail_sender = os.environ.get('MAIL_DEFAULT_SENDER', mail_username or 'noreply@storage-manager.local')
        mail_use_tls = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
        
        # Validate SMTP credentials are configured
        if not mail_username or not mail_password:
            logger.error("SMTP credentials not configured. Set MAIL_USERNAME and MAIL_PASSWORD environment variables.")
            return False
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = mail_sender
        msg['To'] = to_email
        
        # Attach text and HTML versions
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send via SMTP
        with smtplib.SMTP(mail_server, mail_port) as server:
            if mail_use_tls:
                server.starttls()
            server.login(mail_username, mail_password)
            server.send_message(msg)
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {str(e)}")
        return False


def send_signup_invitation_email(user_email: str, admin_email: str, signup_token: str, app_url: str) -> bool:
    """Send sign-up invitation email to user."""
    from email_templates_utils import get_signup_invitation_emails
    
    emails = get_signup_invitation_emails(admin_email, signup_token, app_url)
    return send_email(user_email, emails['subject'], emails['html'], emails['text'])


def send_password_reset_email(email: str, reset_token: str, app_url: str, is_admin: bool = False) -> bool:
    """Send password reset email."""
    from email_templates_utils import get_password_reset_emails
    
    emails = get_password_reset_emails(reset_token, app_url, is_admin)
    return send_email(email, emails['subject'], emails['html'], emails['text'])


def generate_invitation_token_for_user(admin_id: int, email: str):
    """Generate and store a signup invitation token."""
    from backend.app.models import db, SignupInvitation
    
    token = SignupInvitation.generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    invitation = SignupInvitation(  # type: ignore
        admin_id=admin_id,
        email=email,
        invitation_token=token,
        expires_at=expires_at
    )
    db.session.add(invitation)
    db.session.commit()
    
    return token


def validate_signup_invitation(token: str):
    """Validate a signup invitation token and return invitation if valid."""
    from backend.app.models import SignupInvitation
    
    invitation = SignupInvitation.query.filter_by(invitation_token=token).first()
    
    if not invitation:
        return None, "Invalid invitation token"
    
    if invitation.is_used:
        return None, "Invitation has already been used"
    
    if invitation.is_expired():
        return None, "Invitation has expired"
    
    return invitation, None


def generate_password_reset_token(user_type: str, user_or_admin_id: int, email: str):
    """Generate and store a password reset token."""
    from backend.app.models import db, PasswordResetToken
    
    # Delete any existing tokens for this email
    PasswordResetToken.query.filter_by(user_type=user_type, email=email).delete()
    
    token = PasswordResetToken.generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    reset_token_obj = PasswordResetToken(  # type: ignore
        user_type=user_type,
        user_or_admin_id=user_or_admin_id,
        email=email,
        reset_token=token,
        expires_at=expires_at
    )
    db.session.add(reset_token_obj)
    db.session.commit()
    
    return token


def validate_password_reset_token(token: str):
    """Validate a password reset token and return token object if valid."""
    from backend.app.models import PasswordResetToken
    
    reset_token_obj = PasswordResetToken.query.filter_by(reset_token=token).first()
    
    if not reset_token_obj:
        return None, "Invalid reset token"
    
    if reset_token_obj.is_expired():
        return None, "Reset token has expired"
    
    return reset_token_obj, None


def admin_required(f):
    """Decorator to require authenticated user to be an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        from backend.app.models import Admin
        
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        # In app_new architecture, Admin objects are users too
        if not isinstance(current_user, Admin):
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def user_required(f):
    """Decorator to require authenticated user to be a regular user (not admin)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        from backend.app.models import User, Admin
        
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Allow regular users but reject admins (unless they're accessing their own user context)
        if isinstance(current_user, Admin):
            return jsonify({'error': 'User privileges required'}), 403
        
        if not isinstance(current_user, User):
            return jsonify({'error': 'Invalid user type'}), 403
        
        return f(*args, **kwargs)
    return decorated_function
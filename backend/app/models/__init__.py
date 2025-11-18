"""
Database models for users, admins, and authentication.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, AnonymousUserMixin
from datetime import datetime, timedelta
import secrets
import string
import json
from cryptography.fernet import Fernet
import os

db = SQLAlchemy()

# Encryption key for storing credentials
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if ENCRYPTION_KEY:
    CIPHER = Fernet(ENCRYPTION_KEY.encode())
else:
    CIPHER = None


class User(UserMixin, db.Model):
    """Regular user model - managed by admins."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    cognito_sub = db.Column(db.String(255), unique=True, nullable=True, index=True)  # Cognito Subject ID
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True, nullable=False) # type: ignore
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    admin_mappings = db.relationship('AdminUserMapping', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def get_id(self):
        return str(self.id)


class Admin(UserMixin, db.Model):
    """Admin user model."""
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    cognito_sub = db.Column(db.String(255), unique=True, nullable=True, index=True)  # Cognito Subject ID
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False) # type: ignore
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user_mappings = db.relationship('AdminUserMapping', backref='admin', lazy=True, cascade='all, delete-orphan')
    invitations = db.relationship('SignupInvitation', backref='admin', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Admin {self.email}>'
    
    def get_id(self):
        return f'admin_{self.id}'
    
    def get_managed_users(self):
        """Get all users managed by this admin."""
        return User.query.join(
            AdminUserMapping,
            AdminUserMapping.user_id == User.id
        ).filter(AdminUserMapping.admin_id == self.id).all()


class AdminUserMapping(db.Model):
    """Junction table: Admin manages Users (many-to-many)."""
    __tablename__ = 'admin_user_mapping'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('admin_id', 'user_id', name='unique_admin_user'),)
    
    def __repr__(self):
        return f'<AdminUserMapping admin_id={self.admin_id}, user_id={self.user_id}>'


class SignupInvitation(db.Model):
    """Sign-up invitation tokens sent by admins to users."""
    __tablename__ = 'signup_invitations'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id', ondelete='CASCADE'), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False)
    invitation_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<SignupInvitation email={self.email}, is_used={self.is_used}>'
    
    @staticmethod
    def generate_token():
        """Generate a secure random token."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    def is_expired(self):
        """Check if invitation token has expired."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        return False


class PasswordResetToken(db.Model):
    """Password reset tokens for users and admins."""
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_type = db.Column(db.String(10), nullable=False)  # 'user' or 'admin'
    user_or_admin_id = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(255), nullable=False, index=True)
    reset_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<PasswordResetToken {self.email}>'
    
    @staticmethod
    def generate_token():
        """Generate a secure random token."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    def is_expired(self):
        """Check if reset token has expired."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        return False


class TokenBlacklist(db.Model):
    """Blacklist for invalidated JWT tokens (on logout)."""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False, index=True)  # JWT ID (from token)
    token_type = db.Column(db.String(20), nullable=False)  # 'access' or 'refresh'
    user_id = db.Column(db.Integer, nullable=True)  # User ID who had the token
    blacklisted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)  # When token naturally expires
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'
    
    @staticmethod
    def is_token_blacklisted(jti: str) -> bool:
        """Check if a token JTI is blacklisted."""
        token = TokenBlacklist.query.filter_by(jti=jti).first()
        return token is not None
    
    @staticmethod
    def add_to_blacklist(jti: str, token_type: str, expires_at: datetime) -> None:
        """Add a token to the blacklist."""
        if not TokenBlacklist.query.filter_by(jti=jti).first():
            blacklist_entry = TokenBlacklist(
                jti=jti,
                token_type=token_type,
                expires_at=expires_at
            )
            db.session.add(blacklist_entry)
            db.session.commit()


class AnonymousUser(AnonymousUserMixin):
    """Anonymous user for when user is not logged in."""
    def is_admin(self):
        return False
    
    def is_user(self):
        return False


class CloudProvider(db.Model):
    """Store cloud provider configurations per admin (encrypted)."""
    __tablename__ = 'cloud_providers'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id', ondelete='CASCADE'), nullable=False, index=True)
    provider_type = db.Column(db.String(50), nullable=False)  # 'aws', 'azure', 'gcs', 'backblaze', etc.
    display_name = db.Column(db.String(255), nullable=False)  # User-friendly name
    credentials_encrypted = db.Column(db.Text, nullable=False)  # JSON encrypted with Fernet
    config_encrypted = db.Column(db.Text)  # Additional provider-specific config (encrypted JSON)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_tested_at = db.Column(db.DateTime)
    
    __table_args__ = (
        db.Index('idx_admin_provider_type', 'admin_id', 'provider_type'),
        db.UniqueConstraint('admin_id', 'display_name', name='unique_admin_provider_name'),
    )
    
    def __repr__(self):
        return f'<CloudProvider {self.provider_type}:{self.display_name} for admin_id={self.admin_id}>'
    
    def encrypt_credentials(self, credentials_dict: dict) -> None:
        """Encrypt and store credentials."""
        if not CIPHER:
            raise ValueError("Encryption key not configured. Set ENCRYPTION_KEY environment variable.")
        
        credentials_json = json.dumps(credentials_dict)
        self.credentials_encrypted = CIPHER.encrypt(credentials_json.encode()).decode()
    
    def decrypt_credentials(self) -> dict:
        """Decrypt and return credentials."""
        if not CIPHER:
            raise ValueError("Encryption key not configured. Set ENCRYPTION_KEY environment variable.")
        
        credentials_json = CIPHER.decrypt(self.credentials_encrypted.encode()).decode()
        return json.loads(credentials_json)
    
    def encrypt_config(self, config_dict: dict) -> None:
        """Encrypt and store additional config."""
        if not CIPHER or not config_dict:
            return
        
        config_json = json.dumps(config_dict)
        self.config_encrypted = CIPHER.encrypt(config_json.encode()).decode()
    
    def decrypt_config(self) -> dict:
        """Decrypt and return additional config."""
        if not CIPHER or not self.config_encrypted:
            return {}
        
        config_json = CIPHER.decrypt(self.config_encrypted.encode()).decode()
        return json.loads(config_json)
    
    def get_provider_instance(self):
        """Get a storage provider instance for this configuration."""
        from backend.app.services.storage_providers import get_storage_provider
        
        credentials = self.decrypt_credentials()
        config = self.decrypt_config()
        
        # Merge config into credentials for provider initialization
        provider_kwargs = {**credentials, **config}
        
        return get_storage_provider(self.provider_type, **provider_kwargs)


class BucketRequest(db.Model):
    """Bucket creation/deletion requests from users to admins."""
    __tablename__ = 'bucket_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id'), nullable=False)
    bucket_name = db.Column(db.String(255), nullable=False)
    
    # Request type: 'create' or 'delete'
    request_type = db.Column(db.String(20), nullable=False)
    
    # AWS Region for bucket creation (e.g., 'us-east-1', 'ap-south-1')
    region = db.Column(db.String(50), nullable=True)
    
    # Status: 'pending', 'approved', 'rejected', 'completed'
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    
    # Admin notes/reason for rejection
    admin_notes = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='bucket_requests')
    provider = db.relationship('CloudProvider', backref='bucket_requests')
    iam_policy = db.relationship('UserBucketPolicy', backref='bucket_request', uselist=False, cascade='all, delete-orphan')
    
    __table_args__ = (
        # Note: Uniqueness for pending requests is enforced at the application level
        # in the request_bucket route, not at the database constraint level
    )
    
    def __repr__(self):
        return f'<BucketRequest {self.request_type} {self.bucket_name} ({self.status})>'


class UserBucketPolicy(db.Model):
    """IAM policies for user access to specific buckets."""
    __tablename__ = 'user_bucket_policies'
    
    id = db.Column(db.Integer, primary_key=True)
    bucket_request_id = db.Column(db.Integer, db.ForeignKey('bucket_requests.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('cloud_providers.id'), nullable=False)
    bucket_name = db.Column(db.String(255), nullable=False)
    
    # Permissions: stored as JSON list of allowed actions
    # e.g., ['s3:GetObject', 's3:PutObject', 's3:DeleteObject']
    allowed_actions = db.Column(db.Text, nullable=False, default='[]')
    
    # Whether policy has been applied to cloud provider
    is_applied = db.Column(db.Boolean, default=False)
    
    # Cloud provider policy ID/name (for tracking)
    policy_id = db.Column(db.String(255))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    applied_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='bucket_policies')
    provider = db.relationship('CloudProvider', backref='user_bucket_policies')
    
    def get_actions(self):
        """Get allowed actions as list."""
        return json.loads(self.allowed_actions)
    
    def set_actions(self, actions: list):
        """Set allowed actions from list."""
        self.allowed_actions = json.dumps(actions)
    
    def __repr__(self):
        return f'<UserBucketPolicy {self.user_id}:{self.bucket_name}>'


def init_db():
    """Initialize the database - create tables if they don't exist."""
    db.create_all()

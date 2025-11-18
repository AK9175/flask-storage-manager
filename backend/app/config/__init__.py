"""
Application configuration management
Environment-based configuration for different deployment scenarios
"""
import os
from datetime import timedelta


class Config:
    """Base configuration class with default settings"""
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'storage_manager.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Lax to allow redirects, Strict is too restrictive
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Security
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-please-set-in-production')
    WTF_CSRF_ENABLED = True
    
    # File upload
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_SIZE', 1073741824))  # 1 GB


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing environment configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


def get_config(env=None):
    """
    Get configuration object based on environment
    
    Args:
        env: Environment name ('development', 'production', 'testing')
             If None, uses FLASK_ENV environment variable or defaults to 'development'
    
    Returns:
        Configuration object for the specified environment
    """
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    
    env = env.lower()
    
    if env == 'production':
        return ProductionConfig
    elif env == 'testing':
        return TestingConfig
    else:  # development
        return DevelopmentConfig

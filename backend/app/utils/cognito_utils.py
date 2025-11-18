"""
AWS Cognito utilities for authentication and JWT validation.
"""
import os
import boto3
import logging
from datetime import datetime
from functools import wraps
from flask import request, jsonify
import jwt
from jwt import PyJWTError
import requests
from cachetools import TTLCache
import hmac
import hashlib
import base64
import uuid

logger = logging.getLogger(__name__)

# Cognito configuration from environment
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_USER_POOL_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.environ.get('COGNITO_USER_POOL_CLIENT_SECRET')
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN')

# Cognito endpoints
COGNITO_IDP_ENDPOINT = f'https://cognito-idp.{AWS_REGION}.amazonaws.com'
COGNITO_AUTH_ENDPOINT = f'https://{COGNITO_DOMAIN}.auth.{AWS_REGION}.amazoncognito.com'
COGNITO_JWKS_URL = f'{COGNITO_IDP_ENDPOINT}/{COGNITO_USER_POOL_ID}/.well-known/jwks.json'

# Initialize Cognito client
cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)

# Cache for JWT keys (TTL: 1 hour)
_jwks_cache = TTLCache(maxsize=1, ttl=3600)


def get_secret_hash(username):
    """
    Compute SECRET_HASH for Cognito client requests when client has a secret.
    Required for clients configured with a client secret.
    
    Args:
        username: The username/email
    
    Returns:
        Base64-encoded HMAC-SHA256 hash
    """
    if not COGNITO_CLIENT_SECRET:
        return None
    
    message = bytes(username + COGNITO_CLIENT_ID, 'utf-8')
    secret = bytes(COGNITO_CLIENT_SECRET, 'utf-8')
    dig = hmac.new(secret, message, hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


def get_cognito_public_keys():
    """
    Fetch and cache Cognito public keys for JWT validation.
    Keys are cached for 1 hour.
    """
    if 'keys' in _jwks_cache:
        return _jwks_cache['keys']
    
    try:
        response = requests.get(COGNITO_JWKS_URL, timeout=5)
        response.raise_for_status()
        keys = response.json()['keys']
        _jwks_cache['keys'] = keys
        return keys
    except Exception as e:
        logger.error(f"Error fetching Cognito public keys: {str(e)}")
        raise


def validate_jwt_token(token):
    """
    Validate JWT token from Cognito.
    Returns decoded token if valid, raises exception if invalid.
    """
    try:
        # Get Cognito public keys
        keys = get_cognito_public_keys()
        
        # Get token header to find the key
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        # Find the correct key
        public_key = None
        for key in keys:
            if key.get('kid') == kid:
                public_key = key
                break
        
        if not public_key:
            raise ValueError('Public key not found')
        
        # Convert JWK to PEM format
        public_key_pem = jwt.algorithms.RSAAlgorithm.from_jwk(public_key)
        
        # Validate and decode token
        # Note: Access tokens don't have 'aud' claim, so we don't verify it
        decoded = jwt.decode(
            token,
            public_key_pem,
            algorithms=['RS256'],
            options={'verify_exp': True, 'verify_aud': False},
            issuer=f'{COGNITO_IDP_ENDPOINT}/{COGNITO_USER_POOL_ID}'
        )
        
        return decoded
        
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        raise
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error validating JWT token: {str(e)}")
        raise


def cognito_jwt_required(f):
    """
    Decorator to protect routes with Cognito JWT validation.
    Validates JWT from:
    1. Authorization header (for API requests)
    2. Session (for page requests)
    Stores decoded claims in request.cognito_claims.
    
    For UI pages (HTML requests), redirects to login if no token.
    For API requests (JSON), returns 401 error.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import session, redirect, url_for
        
        token = None
        token_source = None
        
        # Try authentication sources in order:
        # 1. Authorization header (for API requests)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            token_source = 'Authorization header'
        
        # 2. Non-HttpOnly cookie (for page requests) - curl/testing
        if not token:
            token = request.cookies.get('access_token')
            if token:
                token_source = 'Cookie'
        
        # 3. Flask session (primary for browser requests)
        if not token:
            token = session.get('access_token')
            if token:
                token_source = 'Session'
        
        # Helper function to determine login redirect URL
        def get_login_redirect_url():
            # Check if this is an admin route (admin routes contain '/admin/')
            if '/admin/' in request.path:
                return url_for('auth.admin_login')
            else:
                return url_for('auth.user_login')
        
        if not token:
            # No token found in any source
            accept_header = request.headers.get('Accept', '')
            is_page_request = 'text/html' in accept_header or accept_header == ''
            
            logger.warning(f"NO TOKEN FOUND for {request.method} {request.path}")
            logger.debug(f"Accept header: '{accept_header}', Cookies: {list(request.cookies.keys())}, Session: {list(session.keys())}")
            
            if is_page_request:
                # Browser page request - redirect to appropriate login
                logger.warning(f"Page request without token, redirecting to login")
                return redirect(get_login_redirect_url())
            else:
                # API request - return 401 JSON
                return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        
        logger.info(f"Found token from {token_source} for {request.method} {request.path}")
        
        try:
            # Validate JWT token
            decoded = validate_jwt_token(token)
            
            # Store claims in request context using Flask's g object
            from flask import g
            g.cognito_claims = decoded
            g.cognito_user_email = decoded.get('email')
            g.cognito_user_sub = decoded.get('sub')
            
            # Load and login user for Flask-Login (so current_user works in templates)
            from flask_login import login_user
            from backend.app.models import User, Admin
            
            # Try to find admin first
            admin = Admin.query.filter_by(cognito_sub=g.cognito_user_sub).first()
            if admin:
                login_user(admin, remember=True)
            else:
                # Try to find regular user
                user = User.query.filter_by(cognito_sub=g.cognito_user_sub).first()
                if user:
                    login_user(user, remember=True)
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"JWT token expired for request to {request.path}")
            session.clear()
            accept_header = request.headers.get('Accept', '')
            is_page_request = 'text/html' in accept_header or accept_header == ''
            if is_page_request:
                return redirect(get_login_redirect_url())
            else:
                return jsonify({'error': 'token_expired', 'message': 'Access token has expired. Use refresh token to obtain a new one.'}), 401
        except jwt.InvalidTokenError:
            logger.warning(f"Invalid JWT token for request to {request.path}")
            session.clear()
            accept_header = request.headers.get('Accept', '')
            is_page_request = 'text/html' in accept_header or accept_header == ''
            if is_page_request:
                return redirect(get_login_redirect_url())
            else:
                return jsonify({'error': 'invalid_token', 'message': 'Invalid or malformed token'}), 401
        except Exception as e:
            logger.error(f"JWT validation error for {request.path}: {str(e)}")
            session.clear()
            accept_header = request.headers.get('Accept', '')
            is_page_request = 'text/html' in accept_header or accept_header == ''
            if is_page_request:
                return redirect(get_login_redirect_url())
            else:
                return jsonify({'error': 'auth_failed', 'message': 'Token validation failed'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


def cognito_sign_up(email, password, first_name, last_name):
    """
    Register a new user in Cognito.
    Note: Uses AdminCreateUser for self-signup (admin flow).
    Since pool is configured with email alias, we use UUID-based username
    and set email as attribute.
    
    Returns:
        dict: Response from Cognito AdminCreateUser API
    Raises:
        Exception: If sign up fails
    """
    try:
        # Generate UUID-based username since pool uses email alias
        # and doesn't accept email format as username
        username = str(uuid.uuid4())
        
        # Create user with temporary password using AdminCreateUser
        response = cognito_client.admin_create_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username,  # UUID-based username
            TemporaryPassword=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},  # Email is an attribute/alias
                {'Name': 'given_name', 'Value': first_name},
                {'Name': 'family_name', 'Value': last_name},
                {'Name': 'email_verified', 'Value': 'true'},
            ],
            MessageAction='SUPPRESS'  # Don't send temporary password email
        )
        
        # Set permanent password so user doesn't need to change it on first login
        cognito_client.admin_set_user_password(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username,
            Password=password,
            Permanent=True
        )
        
        logger.info(f"User created in Cognito (admin): {email} (username: {username})")
        return response
    except cognito_client.exceptions.UsernameExistsException:
        logger.warning(f"User already exists in Cognito: {email}")
        raise ValueError(f"User with email {email} already exists")
    except Exception as e:
        logger.error(f"Error signing up user in Cognito: {str(e)}")
        raise


def cognito_authenticate(email, password):
    """
    Authenticate user with Cognito using email and password.
    First finds the user's UUID username by email, then authenticates.
    
    Returns:
        dict: Contains 'access_token', 'id_token', 'refresh_token'
    Raises:
        Exception: If authentication fails
    """
    try:
        # First, find the user's UUID username by their email
        # (Since pool uses email alias but stores with UUID username)
        username = None
        try:
            user_response = cognito_client.admin_get_user(
                UserPoolId=COGNITO_USER_POOL_ID,
                Username=email  # Try email first (might work as alias)
            )
            username = user_response['Username']
        except cognito_client.exceptions.UserNotFoundException:
            # Email didn't work as alias, need to search by email attribute
            try:
                list_response = cognito_client.list_users(
                    UserPoolId=COGNITO_USER_POOL_ID,
                    Filter=f'email = "{email}"'
                )
                if list_response['Users']:
                    username = list_response['Users'][0]['Username']
                else:
                    raise ValueError("User not found")
            except Exception as search_error:
                logger.error(f"Error searching for user by email: {str(search_error)}")
                raise ValueError("User not found")
        
        if not username:
            raise ValueError("User not found")
        
        # Authenticate using the UUID username
        # Public client doesn't need SECRET_HASH
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        
        auth_result = response.get('AuthenticationResult', {})
        logger.info(f"User authenticated with Cognito: {email} (username: {username})")
        
        return {
            'access_token': auth_result.get('AccessToken'),
            'id_token': auth_result.get('IdToken'),
            'refresh_token': auth_result.get('RefreshToken'),
            'expires_in': auth_result.get('ExpiresIn'),
            'token_type': auth_result.get('TokenType', 'Bearer')
        }
        
    except cognito_client.exceptions.NotAuthorizedException:
        logger.warning(f"Invalid credentials for user: {email}")
        raise ValueError("Invalid email or password")
    except cognito_client.exceptions.UserNotConfirmedException:
        logger.warning(f"User not confirmed: {email}")
        raise ValueError("User account not confirmed. Please check your email.")
    except cognito_client.exceptions.UserNotFoundException:
        logger.warning(f"User not found in Cognito: {email}")
        raise ValueError("User not found")
    except Exception as e:
        logger.error(f"Error authenticating user: {str(e)}")
        raise


def cognito_refresh_token(refresh_token):
    """
    Refresh access token using refresh token.
    
    Returns:
        dict: Contains new 'access_token' and 'id_token'
    Raises:
        Exception: If refresh fails
    """
    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token
            }
        )
        
        auth_result = response.get('AuthenticationResult', {})
        logger.info("Token refreshed successfully")
        
        return {
            'access_token': auth_result.get('AccessToken'),
            'id_token': auth_result.get('IdToken'),
            'expires_in': auth_result.get('ExpiresIn'),
            'token_type': auth_result.get('TokenType', 'Bearer')
        }
        
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        raise


def cognito_change_password(access_token, old_password, new_password):
    """
    Change user password.
    
    Args:
        access_token: JWT access token from Cognito
        old_password: Current password
        new_password: New password
    """
    try:
        cognito_client.change_password(
            AccessToken=access_token,
            PreviousPassword=old_password,
            ProposedPassword=new_password
        )
        logger.info("Password changed successfully")
        return True
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        raise


def cognito_forgot_password(email):
    """
    Initiate forgot password flow.
    Cognito sends password reset email to user.
    
    Returns:
        dict: Contains 'CodeDeliveryDetails'
    """
    try:
        params = {
            'ClientId': COGNITO_CLIENT_ID,
            'Username': email
        }
        
        # Add SECRET_HASH if client secret is configured
        secret_hash = get_secret_hash(email)
        if secret_hash:
            params['SecretHash'] = secret_hash
        
        response = cognito_client.forgot_password(**params)
        logger.info(f"Password reset initiated for: {email}")
        return response
    except cognito_client.exceptions.UserNotFoundException:
        # Don't reveal if user exists (security best practice)
        logger.info(f"Password reset requested for non-existent user: {email}")
        return {'message': 'If user exists, reset email will be sent'}
    except Exception as e:
        logger.error(f"Error initiating forgot password: {str(e)}")
        raise


def cognito_confirm_forgot_password(email, confirmation_code, new_password):
    """
    Confirm password reset with verification code.
    
    Args:
        email: User email
        confirmation_code: Code from email
        new_password: New password
    """
    try:
        params = {
            'ClientId': COGNITO_CLIENT_ID,
            'Username': email,
            'ConfirmationCode': confirmation_code,
            'Password': new_password
        }
        
        # Add SECRET_HASH if client secret is configured
        secret_hash = get_secret_hash(email)
        if secret_hash:
            params['SecretHash'] = secret_hash
        
        cognito_client.confirm_forgot_password(**params)
        logger.info(f"Password reset confirmed for: {email}")
        return True
    except Exception as e:
        logger.error(f"Error confirming forgot password: {str(e)}")
        raise


def cognito_get_user(access_token):
    """
    Get user information from Cognito.
    
    Args:
        access_token: JWT access token
        
    Returns:
        dict: User attributes
    """
    try:
        response = cognito_client.get_user(AccessToken=access_token)
        user_attributes = {}
        for attr in response.get('UserAttributes', []):
            user_attributes[attr['Name']] = attr['Value']
        return user_attributes
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise


def cognito_revoke_token(refresh_token):
    """
    Revoke a refresh token using Cognito's /oauth2/revoke endpoint.
    This invalidates the refresh token, preventing new access tokens from being issued.
    
    Already-issued access tokens remain valid until they expire (usually 1 hour).
    
    Args:
        refresh_token: The refresh token to revoke
        
    Returns:
        bool: True if revocation was successful, False otherwise
    """
    try:
        # Cognito token revocation endpoint
        revoke_url = f"{COGNITO_AUTH_ENDPOINT}/oauth2/revoke"
        
        # Prepare the request
        data = {
            'client_id': COGNITO_CLIENT_ID,
            'token': refresh_token
        }
        
        # If client has a secret, include it
        if COGNITO_CLIENT_SECRET:
            data['client_secret'] = COGNITO_CLIENT_SECRET
        
        # Send revocation request
        response = requests.post(revoke_url, data=data)
        
        if response.status_code == 200:
            logger.info(f"Token successfully revoked")
            return True
        else:
            logger.warning(f"Token revocation failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error revoking token: {str(e)}")
        return False


def cognito_get_user(access_token):
    """
    Get user information from Cognito.
    
    Args:
        access_token: JWT access token
        
    Returns:
        dict: User attributes
    """
    try:
        response = cognito_client.get_user(AccessToken=access_token)
        user_attributes = {}
        for attr in response.get('UserAttributes', []):
            user_attributes[attr['Name']] = attr['Value']
        return user_attributes
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise


def cognito_admin_required(f):
    """
    Decorator to ensure the authenticated user is an admin.
    Must be used AFTER @cognito_jwt_required.
    Sets g.current_admin to the admin object.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from backend.app.models import Admin
        from flask import g
        
        # cognito_jwt_required must have already set g.cognito_user_sub
        cognito_sub = g.get('cognito_user_sub', None)
        if not cognito_sub:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Check if user is an admin in the database
        admin = Admin.query.filter_by(cognito_sub=cognito_sub).first()
        if not admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        
        # Store admin in g for use in the route handler
        g.current_admin = admin
        return f(*args, **kwargs)
    
    return decorated_function

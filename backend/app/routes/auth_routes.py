"""
Authentication routes for users and admins - Cognito integrated.
"""
from flask import Blueprint, request, jsonify, url_for, render_template, redirect
from datetime import datetime
import logging
import os
import jwt as pyjwt

from backend.app.models import db, User, Admin, AdminUserMapping, SignupInvitation
from backend.app.utils.auth_utils import (
    send_signup_invitation_email,
    validate_signup_invitation,
    generate_invitation_token_for_user
)
from backend.app.utils.cognito_utils import (
    cognito_sign_up,
    cognito_authenticate,
    cognito_refresh_token,
    cognito_forgot_password,
    cognito_confirm_forgot_password,
    cognito_jwt_required
)

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ============================================================================
# USER AUTHENTICATION (Cognito)
# ============================================================================

@auth_bp.route('/user/login', methods=['GET', 'POST'])
def user_login():
    """User login endpoint - authenticates with Cognito."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        try:
            # Authenticate with Cognito
            tokens = cognito_authenticate(email, password)
            
            # Verify user is active in our DB
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'error': 'User not found in system'}), 404
            
            if not user.is_active:
                return jsonify({'error': 'User account is inactive'}), 403
            
            # Update user's cognito_sub if not already set
            if not user.cognito_sub:
                decoded_id = pyjwt.decode(tokens['id_token'], options={"verify_signature": False})
                user.cognito_sub = decoded_id.get('sub')
                db.session.commit()
            
            logger.info(f"User logged in: {email}")
            
            # Store tokens in Flask session
            from flask import session, make_response
            session['access_token'] = tokens['access_token']
            session['id_token'] = tokens['id_token']
            session['refresh_token'] = tokens['refresh_token']
            session['user_type'] = 'user'
            session.permanent = True  # Make session persist across browser close
            
            # Create response with tokens also set in cookies for cross-tab access
            response = make_response(jsonify({
                'message': 'Login successful',
                'access_token': tokens['access_token'],
                'id_token': tokens['id_token'],
                'refresh_token': tokens['refresh_token'],
                'expires_in': tokens.get('expires_in'),
                'redirect': '/user/dashboard'
            }))
            
            # Set tokens in cookies (non-HttpOnly for cross-tab detection, expires in 24 hours)
            response.set_cookie('access_token', tokens['access_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('id_token', tokens['id_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('refresh_token', tokens['refresh_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('user_type', 'user', 
                              max_age=24*60*60, samesite='Lax')
            
            return response, 200
            
        except ValueError as e:
            logger.warning(f"Login failed for {email}: {str(e)}")
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            logger.error(f"Login error for {email}: {str(e)}")
            return jsonify({'error': 'Login failed. Please try again.'}), 500
    
    # GET request - render login template
    # Check if user has valid token in cookies (from other tabs)
    from flask import session, g
    from backend.app.utils.cognito_utils import validate_jwt_token
    
    # Check for token in cookies (set during login in another tab)
    token = request.cookies.get('access_token')
    if token:
        try:
            decoded = validate_jwt_token(token)
            logger.info(f"User already logged in via cookie, redirecting to dashboard")
            return redirect(url_for('user_dashboard'))
        except Exception:
            pass
    
    return render_template('auth/user_login.html')


@auth_bp.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    """User sign-up endpoint (via invitation) - creates user in Cognito."""
    if request.method == 'POST':
        data = request.get_json()
        token = data.get('invitation_token', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        
        # Validate inputs
        if not token or not email or not password or not first_name or not last_name:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Validate invitation token
        invitation, error = validate_signup_invitation(token)
        if error:
            return jsonify({'error': error}), 400
        
        # Check if email matches invitation
        if invitation.email.lower() != email:  # type: ignore
            return jsonify({'error': 'Email does not match the invitation'}), 400
        
        # Check if user already exists locally
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email is already registered'}), 409
        
        try:
            # Step 1: Create user in Cognito
            cognito_response = cognito_sign_up(email, password, first_name, last_name)
            cognito_sub = cognito_response.get('UserSub')
            
            # Step 2: Create user record in local DB
            user = User(  # type: ignore
                email=email,
                cognito_sub=cognito_sub,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            db.session.add(user)
            db.session.flush()
            
            # Step 3: Map user to admin
            mapping = AdminUserMapping(admin_id=invitation.admin_id, user_id=user.id)  # type: ignore
            db.session.add(mapping)
            
            # Step 4: Mark invitation as used
            invitation.is_used = True  # type: ignore
            
            db.session.commit()
            
            logger.info(f"New user signed up: {email} (Cognito: {cognito_sub})")
            
            return jsonify({
                'message': 'Sign-up successful! Your account is ready to use.',
                'redirect': '/auth/user/login'
            }), 200
            
        except ValueError as e:
            logger.warning(f"Signup error for {email}: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            logger.error(f"Error during user signup: {error_msg}")
            
            # Extract meaningful error from Cognito exceptions
            if 'InvalidPasswordException' in error_msg:
                # Extract the password policy message
                if 'Password must have' in error_msg:
                    return jsonify({'error': error_msg.split(': ')[-1]}), 400
                return jsonify({'error': 'Password does not meet requirements'}), 400
            elif 'UsernameExistsException' in error_msg:
                return jsonify({'error': 'Email is already registered'}), 409
            elif 'InvalidParameterException' in error_msg:
                return jsonify({'error': error_msg.split(': ')[-1]}), 400
            
            # Generic fallback
            return jsonify({'error': 'An error occurred during sign-up. Please try again.'}), 500
    
    # GET request - get invitation details
    token = request.args.get('token', '').strip()
    if not token:
        return render_template('auth/user_signup.html', error='No invitation token provided')
    
    invitation, error = validate_signup_invitation(token)
    if error:
        return render_template('auth/user_signup.html', error=error)
    
    admin = Admin.query.get(invitation.admin_id)  # type: ignore
    return render_template('auth/user_signup.html', 
                          email=invitation.email,  # type: ignore
                          admin_email=admin.email if admin else '',
                          token=token)


@auth_bp.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():
    """User forgot password endpoint - initiates Cognito password reset flow."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        try:
            # Initiate Cognito forgot password flow
            cognito_forgot_password(email)
            logger.info(f"Password reset initiated for: {email}")
            
            # Always return success to prevent email enumeration
            return jsonify({
                'message': 'If an account with that email exists, a password reset link has been sent'
            }), 200
            
        except Exception as e:
            logger.error(f"Error initiating forgot password: {str(e)}")
            return jsonify({'error': 'Failed to process request. Please try again later.'}), 500
    
    # GET request - render forgot password template
    return render_template('auth/user_forgot_password.html')


@auth_bp.route('/user/reset-password', methods=['GET', 'POST'])
def user_reset_password():
    """User reset password endpoint - confirms Cognito password reset."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        confirmation_code = data.get('confirmation_code', '').strip()
        new_password = data.get('password', '')
        
        if not email or not confirmation_code or not new_password:
            return jsonify({'error': 'Email, confirmation code, and password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        try:
            # Confirm password reset with Cognito
            cognito_confirm_forgot_password(email, confirmation_code, new_password)
            logger.info(f"User password reset: {email}")
            
            return jsonify({
                'message': 'Password reset successful',
                'redirect': '/auth/user/login'
            }), 200
            
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            return jsonify({'error': 'Failed to reset password. Please check your code and try again.'}), 400
    
    # GET request - render reset password template
    return render_template('auth/user_reset_password.html')


@auth_bp.route('/user/refresh-token', methods=['POST'])
def user_refresh_token():
    """Refresh access token using refresh token."""
    data = request.get_json()
    refresh_token_val = data.get('refresh_token', '').strip()
    
    if not refresh_token_val:
        return jsonify({'error': 'Refresh token is required'}), 400
    
    try:
        tokens = cognito_refresh_token(refresh_token_val)
        
        return jsonify({
            'access_token': tokens['access_token'],
            'id_token': tokens['id_token'],
            'expires_in': tokens.get('expires_in')
        }), 200
        
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return jsonify({'error': 'Failed to refresh token. Please login again.'}), 401


@auth_bp.route('/user/logout', methods=['GET', 'POST'])
def user_logout():
    """User logout endpoint - revokes refresh token via Cognito."""
    from flask import session, make_response
    from backend.app.utils.cognito_utils import cognito_revoke_token
    
    # Get refresh token from session or cookies before clearing
    refresh_token = session.get('refresh_token') or request.cookies.get('refresh_token')
    
    # Revoke the refresh token with Cognito
    # This prevents new access tokens from being issued
    # Already-issued access tokens remain valid until they expire (1 hour)
    if refresh_token:
        try:
            success = cognito_revoke_token(refresh_token)
            if success:
                logger.info("User logout - refresh token revoked with Cognito")
            else:
                logger.warning("User logout - refresh token revocation failed, but continuing with logout")
        except Exception as e:
            logger.error(f"Error revoking token during logout: {str(e)}")
    
    # Clear Flask session
    session.clear()
    
    logger.info("User logout complete")
    response = make_response(render_template('auth/user_logout.html'))
    
    # Clear all auth cookies
    response.delete_cookie('access_token')
    response.delete_cookie('id_token')
    response.delete_cookie('refresh_token')
    response.delete_cookie('user_type')
    response.delete_cookie('session')
    
    return response


# ============================================================================
# ADMIN AUTHENTICATION (Cognito)
# ============================================================================

@auth_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login endpoint - authenticates with Cognito."""
    # If already logged in, redirect to dashboard
    from flask import session, g
    if request.method == 'GET':
        # Check session first
        if session.get('access_token') and session.get('user_type') == 'admin':
            return redirect(url_for('admin.dashboard'))
        
        # Check for token in cookies (from other tabs)
        token = request.cookies.get('access_token')
        if token:
            try:
                from backend.app.utils.cognito_utils import validate_jwt_token
                decoded = validate_jwt_token(token)
                logger.info(f"Admin already logged in via cookie, redirecting to dashboard")
                return redirect(url_for('admin.dashboard'))
            except Exception:
                pass
    
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        try:
            # Authenticate with Cognito
            tokens = cognito_authenticate(email, password)
            
            # Verify admin exists in our DB
            admin = Admin.query.filter_by(email=email).first()
            if not admin:
                return jsonify({'error': 'Admin not found in system'}), 404
            
            if not admin.is_active:
                return jsonify({'error': 'Admin account is inactive'}), 403
            
            # Update admin's cognito_sub if not already set
            if not admin.cognito_sub:
                decoded_id = pyjwt.decode(tokens['id_token'], options={"verify_signature": False})
                admin.cognito_sub = decoded_id.get('sub')
                db.session.commit()
            
            logger.info(f"Admin logged in: {email}")
            
            # Store tokens in Flask session and cookies
            from flask import session, make_response
            session['access_token'] = tokens['access_token']
            session['id_token'] = tokens['id_token']
            session['refresh_token'] = tokens['refresh_token']
            session['user_type'] = 'admin'
            session.permanent = True  # Make session persist across browser close
            
            # Create response with tokens also set in cookies for cross-tab access
            response = make_response(jsonify({
                'message': 'Login successful',
                'access_token': tokens['access_token'],
                'id_token': tokens['id_token'],
                'refresh_token': tokens['refresh_token'],
                'expires_in': tokens.get('expires_in'),
                'redirect': '/admin/dashboard'
            }))
            
            # Set tokens in cookies (non-HttpOnly for cross-tab detection, expires in 24 hours)
            response.set_cookie('access_token', tokens['access_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('id_token', tokens['id_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('refresh_token', tokens['refresh_token'], 
                              max_age=24*60*60, samesite='Lax')
            response.set_cookie('user_type', 'admin', 
                              max_age=24*60*60, samesite='Lax')
            
            return response, 200
            
        except ValueError as e:
            logger.warning(f"Admin login failed for {email}: {str(e)}")
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            logger.error(f"Admin login error for {email}: {str(e)}")
            return jsonify({'error': 'Login failed. Please try again.'}), 500
    
    # GET request - render admin login template
    return render_template('auth/admin_login.html')


@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token.
    
    This endpoint allows clients to get new access/id tokens when the current
    access token expires, without requiring re-authentication.
    
    Request body:
        {
            "refresh_token": "<refresh_token>"
        }
    
    Response:
        {
            "access_token": "<new_access_token>",
            "id_token": "<new_id_token>",
            "expires_in": 3600,
            "message": "Tokens refreshed successfully"
        }
    """
    data = request.get_json()
    refresh_token_value = data.get('refresh_token', '').strip()
    
    if not refresh_token_value:
        return jsonify({'error': 'refresh_token is required'}), 400
    
    try:
        # Use Cognito to refresh tokens
        new_tokens = cognito_refresh_token(refresh_token_value)
        
        logger.info("Tokens refreshed successfully")
        
        return jsonify({
            'message': 'Tokens refreshed successfully',
            'access_token': new_tokens['access_token'],
            'id_token': new_tokens['id_token'],
            'expires_in': new_tokens.get('expires_in', 3600)
        }), 200
    except ValueError as e:
        logger.warning(f"Token refresh failed: {str(e)}")
        return jsonify({
            'error': 'refresh_failed',
            'message': 'Refresh token is invalid or expired. Please login again.'
        }), 401
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return jsonify({
            'error': 'refresh_error',
            'message': 'Failed to refresh tokens. Please try again or login again.'
        }), 500


@auth_bp.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    """Admin self-signup endpoint - creates admin in Cognito."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        
        # Validate inputs
        if not email or not password or not first_name or not last_name:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Check if admin already exists locally
        if Admin.query.filter_by(email=email).first():
            return jsonify({'error': 'Email is already registered'}), 409
        
        try:
            # Step 1: Create admin in Cognito
            cognito_response = cognito_sign_up(email, password, first_name, last_name)
            cognito_sub = cognito_response.get('UserSub')
            
            # Step 2: Create admin record in local DB
            admin = Admin(  # type: ignore
                email=email,
                cognito_sub=cognito_sub,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            
            logger.info(f"New admin signed up: {email} (Cognito: {cognito_sub})")
            
            return jsonify({
                'message': 'Sign-up successful! You can now login.',
                'redirect': '/auth/admin/login'
            }), 200
            
        except ValueError as e:
            logger.warning(f"Admin signup error for {email}: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            logger.error(f"Error during admin signup: {error_msg}")
            
            # Extract meaningful error from Cognito exceptions
            if 'InvalidPasswordException' in error_msg:
                # Extract the password policy message
                if 'Password must have' in error_msg:
                    return jsonify({'error': error_msg.split(': ')[-1]}), 400
                return jsonify({'error': 'Password does not meet requirements'}), 400
            elif 'UsernameExistsException' in error_msg:
                return jsonify({'error': 'Email is already registered'}), 409
            elif 'InvalidParameterException' in error_msg:
                return jsonify({'error': error_msg.split(': ')[-1]}), 400
            
            # Generic fallback
            return jsonify({'error': 'An error occurred during sign-up. Please try again.'}), 500
    
    # GET request - render signup template
    return render_template('auth/admin_signup.html')


@auth_bp.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    """Admin forgot password endpoint - initiates Cognito password reset flow."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        try:
            # Initiate Cognito forgot password flow
            cognito_forgot_password(email)
            logger.info(f"Admin password reset initiated for: {email}")
            
            # Always return success to prevent email enumeration
            return jsonify({
                'message': 'If an account with that email exists, a password reset link has been sent'
            }), 200
            
        except Exception as e:
            logger.error(f"Error initiating forgot password: {str(e)}")
            return jsonify({'error': 'Failed to process request. Please try again later.'}), 500
    
    # GET request - render forgot password template
    return render_template('auth/admin_forgot_password.html')


@auth_bp.route('/admin/reset-password', methods=['GET', 'POST'])
def admin_reset_password():
    """Admin reset password endpoint - confirms Cognito password reset."""
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        confirmation_code = data.get('confirmation_code', '').strip()
        new_password = data.get('password', '')
        
        if not email or not confirmation_code or not new_password:
            return jsonify({'error': 'Email, confirmation code, and password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        try:
            # Confirm password reset with Cognito
            cognito_confirm_forgot_password(email, confirmation_code, new_password)
            logger.info(f"Admin password reset: {email}")
            
            return jsonify({
                'message': 'Password reset successful',
                'redirect': '/auth/admin/login'
            }), 200
            
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            return jsonify({'error': 'Failed to reset password. Please check your code and try again.'}), 400
    
    # GET request - render reset password template
    return render_template('auth/admin_reset_password.html')


@auth_bp.route('/admin/logout', methods=['GET', 'POST'])
def admin_logout():
    """Admin logout endpoint - revokes refresh token via Cognito."""
    from flask import session, make_response
    from backend.app.utils.cognito_utils import cognito_revoke_token
    
    # Get refresh token from session or cookies before clearing
    refresh_token = session.get('refresh_token') or request.cookies.get('refresh_token')
    
    # Revoke the refresh token with Cognito
    if refresh_token:
        try:
            success = cognito_revoke_token(refresh_token)
            if success:
                logger.info("Admin logout - refresh token revoked with Cognito")
            else:
                logger.warning("Admin logout - refresh token revocation failed, but continuing with logout")
        except Exception as e:
            logger.error(f"Error revoking token during logout: {str(e)}")
    
    # Clear Flask session
    session.clear()
    
    logger.info("Admin logout complete")
    response = make_response(render_template('auth/admin_logout.html'))
    
    # Clear all auth cookies
    response.delete_cookie('access_token')
    response.delete_cookie('id_token')
    response.delete_cookie('refresh_token')
    response.delete_cookie('user_type')
    response.delete_cookie('session')
    
    return response


@auth_bp.route('/test-session', methods=['GET'])
def test_session():
    """Debug route to check session contents."""
    from flask import session
    return jsonify({
        'session_id': request.cookies.get('session', 'NO COOKIE'),
        'session_contents': dict(session),
        'session_keys': list(session.keys())
    })


@auth_bp.route('/test-decorator', methods=['GET'])
@cognito_jwt_required
def test_decorator():
    """Debug route to check what decorator sees."""
    from flask import g, session
    return jsonify({
        'reached_handler': True,
        'g.cognito_user_email': g.get('cognito_user_email'),
        'g.cognito_user_sub': g.get('cognito_user_sub'),
        'session_access_token': session.get('access_token', 'NOT IN SESSION')[:50] if session.get('access_token') else 'NO TOKEN'
    })

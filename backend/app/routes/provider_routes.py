"""
Provider Management REST API Routes

Endpoints for managing cloud storage provider configurations per admin:
- POST /admin/providers - Add new provider
- GET /admin/providers - List admin's providers
- GET /admin/providers/<id> - Get specific provider details
- GET /admin/providers/<id>/buckets - List buckets for provider
- POST /admin/providers/<id>/test - Test provider connection
- PATCH /admin/providers/<id> - Update provider configuration
- DELETE /admin/providers/<id> - Remove provider
"""

import logging
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError
from backend.app.models import db, Admin, CloudProvider, User
from backend.app.config.provider_config import (
    validate_provider_credentials, test_provider_connection, list_provider_buckets as config_list_buckets,
    get_provider_info, list_available_providers, ProviderConfigError, ProviderConnectionError
)
from backend.app.utils.auth_utils import admin_required
from backend.app.utils.cognito_utils import cognito_jwt_required

logger = logging.getLogger(__name__)

provider_bp = Blueprint('provider', __name__, url_prefix='/admin/providers')


def admin_provider_required(f):
    """Decorator: Support both JWT and session-based auth for admin endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import g, session
        
        # Check if JWT token is present in Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            # Use JWT validation
            return cognito_jwt_required(f)(*args, **kwargs)
        
        # Check if session has access_token (Flask-Session)
        if session.get('access_token') and session.get('user_type') == 'admin':
            # Session is valid, proceed
            return f(*args, **kwargs)
        
        # No valid auth
        return jsonify({'error': 'Unauthorized'}), 401
    return decorated_function


def get_admin():
    """Get admin object from current user or JWT or session."""
    from flask import g, session
    
    # First try to get from JWT context (set by cognito_jwt_required)
    admin = g.get('current_admin', None)
    if admin:
        return admin
    
    # Try to get from session (session-based auth)
    if session.get('access_token') and session.get('user_type') == 'admin':
        # Session is valid but admin not in g, need to look it up from Cognito claims
        # For session-based auth, we need to validate and set g.current_admin
        try:
            from backend.app.utils.cognito_utils import validate_jwt_token
            token = session.get('access_token')
            decoded = validate_jwt_token(token)
            cognito_sub = decoded.get('sub')
            if cognito_sub:
                admin = Admin.query.filter_by(cognito_sub=cognito_sub).first()
                if admin:
                    return admin
        except Exception as e:
            logger.error(f"Error validating session token: {str(e)}")
    
    # Fall back to Flask-Login current_user (legacy)
    if hasattr(current_user, 'id') and isinstance(current_user, Admin):
        return current_user
    
    return None


@provider_bp.route('', methods=['GET'])
@admin_provider_required
def list_providers():
    """List all providers configured by this admin."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        providers = CloudProvider.query.filter_by(admin_id=admin.id).all()
        return jsonify({
            'providers': [
                {
                    'id': p.id,
                    'provider_type': p.provider_type,
                    'display_name': p.display_name,
                    'is_active': p.is_active,
                    'created_at': p.created_at.isoformat() if p.created_at else None,
                    'last_tested_at': p.last_tested_at.isoformat() if p.last_tested_at else None,
                }
                for p in providers
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error listing providers: {str(e)}")
        return jsonify({'error': 'Failed to list providers'}), 500


@provider_bp.route('/<int:provider_id>', methods=['GET'])
@admin_provider_required
def get_provider(provider_id):
    """Get provider configuration details."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        provider = CloudProvider.query.filter_by(id=provider_id, admin_id=admin.id).first()
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        return jsonify({
            'id': provider.id,
            'provider_type': provider.provider_type,
            'display_name': provider.display_name,
            'is_active': provider.is_active,
            'created_at': provider.created_at.isoformat() if provider.created_at else None,
            'last_tested_at': provider.last_tested_at.isoformat() if provider.last_tested_at else None,
        }), 200
    except Exception as e:
        logger.error(f"Error getting provider: {str(e)}")
        return jsonify({'error': 'Failed to get provider'}), 500


@provider_bp.route('', methods=['POST'])
@admin_provider_required
def create_provider():
    """Create and validate new provider configuration."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        provider_type = data.get('provider_type')
        display_name = data.get('display_name')
        credentials = data.get('credentials', {})
        
        if not provider_type or not display_name:
            return jsonify({'error': 'provider_type and display_name required'}), 400
        
        # Validate credentials format
        is_valid, error_msg = validate_provider_credentials(provider_type, credentials)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Test connection before saving
        is_connected, test_msg = test_provider_connection(provider_type, credentials)
        if not is_connected:
            return jsonify({
                'error': 'Provider connection failed',
                'details': test_msg
            }), 400
        
        # Create and save provider
        try:
            provider = CloudProvider(
                admin_id=admin.id,
                provider_type=provider_type,
                display_name=display_name,
                is_active=True
            )
            
            # Encrypt and store credentials
            provider.encrypt_credentials(credentials)
            
            db.session.add(provider)
            db.session.commit()
            
            logger.info(f"Admin {admin.id} created provider {provider_type}: {display_name}")
            
            return jsonify({
                'id': provider.id,
                'provider_type': provider.provider_type,
                'display_name': provider.display_name,
                'is_active': provider.is_active,
                'message': 'Provider created and validated successfully'
            }), 201
            
        except IntegrityError as e:
            db.session.rollback()
            if 'display_name' in str(e):
                return jsonify({'error': f'Provider name "{display_name}" already exists for this admin'}), 400
            logger.error(f"Database error creating provider: {str(e)}")
            return jsonify({'error': 'Failed to save provider'}), 400
            
    except Exception as e:
        logger.error(f"Error creating provider: {str(e)}")
        return jsonify({'error': 'Failed to create provider'}), 500


@provider_bp.route('/<int:provider_id>/test', methods=['POST'])
@admin_provider_required
def test_provider(provider_id):
    """Test connection to existing provider."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        provider = CloudProvider.query.filter_by(id=provider_id, admin_id=admin.id).first()
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        # Decrypt credentials and test
        credentials = provider.decrypt_credentials()
        is_connected, test_msg = test_provider_connection(provider.provider_type, credentials)
        
        if is_connected:
            # Update last tested timestamp
            from datetime import datetime
            provider.last_tested_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'connected': True,
                'message': test_msg
            }), 200
        else:
            return jsonify({
                'connected': False,
                'message': test_msg
            }), 400
            
    except Exception as e:
        logger.error(f"Error testing provider: {str(e)}")
        return jsonify({'error': 'Failed to test provider'}), 500


@provider_bp.route('/<int:provider_id>/buckets', methods=['GET'])
@admin_provider_required
def list_provider_buckets_endpoint(provider_id):
    """List available buckets/containers for provider."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        provider = CloudProvider.query.filter_by(id=provider_id, admin_id=admin.id).first()
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        # Decrypt credentials and list buckets
        credentials = provider.decrypt_credentials()
        buckets, error = config_list_buckets(provider.provider_type, credentials)
        
        if error:
            return jsonify({
                'error': 'Failed to list buckets',
                'details': error
            }), 400
        
        # Import here to avoid circular imports
        from backend.app.config.provider_config import create_provider_instance
        
        # Enhance with IAM policy information from cloud provider
        buckets_with_policies = []
        if buckets:
            try:
                # Create provider instance to fetch policies
                storage_provider = create_provider_instance(provider.provider_type, credentials)
                
                for bucket_name in buckets:
                    bucket_info = {
                        'name': bucket_name,
                        'policy': None
                    }
                    
                    # Try to fetch IAM policy from cloud provider
                    policy = storage_provider.get_bucket_policy(bucket_name)
                    if policy:
                        bucket_info['policy'] = policy
                    
                    buckets_with_policies.append(bucket_info)
            except Exception as e:
                logger.warning(f"Error fetching policies from cloud provider: {str(e)}")
                # Still return buckets, just without policy info
                buckets_with_policies = [{'name': b, 'policy': None} for b in buckets]
        
        return jsonify({
            'provider_id': provider_id,
            'provider_type': provider.provider_type,
            'display_name': provider.display_name,
            'buckets': buckets_with_policies,
            'count': len(buckets_with_policies) if buckets_with_policies else 0
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing buckets: {str(e)}")
        return jsonify({'error': 'Failed to list buckets'}), 500


@provider_bp.route('/<int:provider_id>', methods=['PATCH'])
@admin_provider_required
def update_provider(provider_id):
    """Update provider configuration (name or credentials)."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        provider = CloudProvider.query.filter_by(id=provider_id, admin_id=admin.id).first()
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Update display name if provided
        if 'display_name' in data:
            provider.display_name = data['display_name']
        
        # Update is_active status if provided
        if 'is_active' in data:
            provider.is_active = bool(data['is_active'])
        
        # Update credentials if provided
        if 'credentials' in data:
            credentials = data['credentials']
            
            # Validate new credentials
            is_valid, error_msg = validate_provider_credentials(provider.provider_type, credentials)
            if not is_valid:
                return jsonify({'error': error_msg}), 400
            
            # Test connection with new credentials
            is_connected, test_msg = test_provider_connection(provider.provider_type, credentials)
            if not is_connected:
                return jsonify({
                    'error': 'New credentials failed connection test',
                    'details': test_msg
                }), 400
            
            # Update credentials
            provider.encrypt_credentials(credentials)
        
        db.session.commit()
        logger.info(f"Admin {admin.id} updated provider {provider_id}")
        
        return jsonify({
            'id': provider.id,
            'display_name': provider.display_name,
            'is_active': provider.is_active,
            'message': 'Provider updated successfully'
        }), 200
        
    except IntegrityError as e:
        db.session.rollback()
        if 'display_name' in str(e):
            return jsonify({'error': 'A provider with this name already exists'}), 400
        logger.error(f"Database error updating provider: {str(e)}")
        return jsonify({'error': 'Failed to update provider'}), 400
    except Exception as e:
        logger.error(f"Error updating provider: {str(e)}")
        return jsonify({'error': 'Failed to update provider'}), 500


@provider_bp.route('/<int:provider_id>', methods=['DELETE'])
@admin_provider_required
def delete_provider(provider_id):
    """Delete provider configuration."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'error': 'Not an admin'}), 403
        
        provider = CloudProvider.query.filter_by(id=provider_id, admin_id=admin.id).first()
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        display_name = provider.display_name
        db.session.delete(provider)
        db.session.commit()
        
        logger.info(f"Admin {admin.id} deleted provider {provider_id}: {display_name}")
        
        return jsonify({
            'message': f'Provider "{display_name}" deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error deleting provider: {str(e)}")
        return jsonify({'error': 'Failed to delete provider'}), 500


@provider_bp.route('/info', methods=['GET'])
@admin_provider_required
def get_all_provider_info():
    """Get information about all available provider types (for UI form generation)."""
    try:
        providers = list_available_providers()
        return jsonify({
            'providers': providers,
            'count': len(providers)
        }), 200
    except Exception as e:
        logger.error(f"Error getting provider info: {str(e)}")
        return jsonify({'error': 'Failed to get provider information'}), 500


@provider_bp.route('/info/<provider_type>', methods=['GET'])
@admin_provider_required
def get_provider_type_info(provider_type):
    """Get information about specific provider type."""
    try:
        info = get_provider_info(provider_type)
        if not info:
            return jsonify({'error': 'Unknown provider type'}), 404
        
        info['type'] = provider_type
        return jsonify(info), 200
    except Exception as e:
        logger.error(f"Error getting provider type info: {str(e)}")
        return jsonify({'error': 'Failed to get provider information'}), 500

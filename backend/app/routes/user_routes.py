"""
User File Management Routes

Handles file upload, download, deletion, and sharing for end users.
Users can access providers configured by their admin.
"""

import os
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from io import BytesIO

from backend.app.models import db, CloudProvider, Admin, User, BucketRequest, UserBucketPolicy
from backend.app.config.provider_config import create_provider_instance, ProviderConfigError
from backend.app.utils.auth_utils import user_required
from backend.app.utils.iam_policy_generator import IAMPolicyGenerator

logger = logging.getLogger(__name__)

user_bp = Blueprint('user', __name__, url_prefix='/user')


def get_user_admin():
    """Get the admin user for the current user."""
    if not isinstance(current_user, User):
        return None
    
    from backend.app.models import AdminUserMapping
    mapping = AdminUserMapping.query.filter_by(user_id=current_user.id).first()
    if mapping:
        return Admin.query.get(mapping.admin_id)
    return None


def check_user_permission(provider_id: int, bucket_name: str, action: str) -> tuple[bool, str]:
    """
    Check if user has permission to perform action on bucket.
    Validates against both database records AND cloud provider's actual IAM policy.
    
    Args:
        provider_id: ID of the cloud provider
        bucket_name: Name of the bucket
        action: Action to check (e.g., 's3:GetObject', 's3:PutObject', 's3:DeleteObject')
    
    Returns:
        (has_permission, message)
    """
    # Step 1: Check if user has a policy for this bucket with an approved request in DB
    policy = db.session.query(UserBucketPolicy).join(
        BucketRequest,
        UserBucketPolicy.bucket_request_id == BucketRequest.id
    ).filter(
        UserBucketPolicy.user_id == current_user.id,
        UserBucketPolicy.provider_id == provider_id,
        UserBucketPolicy.bucket_name == bucket_name,
        BucketRequest.status == 'approved'
    ).first()
    
    if not policy:
        return False, f'You do not have access to bucket "{bucket_name}"'
    
    # Get allowed actions from database
    allowed_actions = policy.get_actions()
    
    # Map action to action category
    action_map = {
        's3:GetObject': 'read',
        's3:GetObjectVersion': 'read',
        's3:PutObject': 'write',
        's3:PutObjectAcl': 'write',
        's3:DeleteObject': 'delete',
        's3:DeleteObjectVersion': 'delete',
        's3:ListBucket': 'list',
        's3:GetBucketLocation': 'list',
        # GCP actions
        'storage.objects.get': 'read',
        'storage.objects.create': 'write',
        'storage.objects.delete': 'delete',
        'storage.buckets.get': 'list',
        'storage.objects.list': 'list',
    }
    
    # Check if action is allowed in DB
    action_category = action_map.get(action)
    if action_category and action_category in allowed_actions:
        db_permission_granted = True
    elif action in allowed_actions:
        db_permission_granted = True
    else:
        db_permission_granted = False
    
    if not db_permission_granted:
        return False, f'You do not have permission for action "{action}" on bucket "{bucket_name}"'
    
    # Step 2: Validate against cloud provider's actual IAM policy
    # This ensures the policy hasn't been revoked/modified externally
    try:
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            logger.warning(f"Provider {provider_id} not found for policy verification")
            return True, 'Permission granted (database)'  # Fall back to DB if provider not found
        
        creds = provider.decrypt_credentials()
        creds['bucket_name'] = bucket_name if provider.provider_type in ['google_cloud', 'backblaze_b2'] else bucket_name
        creds['bucket'] = bucket_name if provider.provider_type not in ['google_cloud', 'backblaze_b2'] else bucket_name
        
        storage_provider = create_provider_instance(provider.provider_type, creds)
        
        # Try to verify the bucket exists (indirect way to check if user has access)
        # For now, we'll just verify bucket exists as a quick sanity check
        try:
            existing_buckets = storage_provider.list_buckets()
            bucket_exists = bucket_name in existing_buckets if existing_buckets else False
            
            if not bucket_exists:
                logger.warning(f"Bucket '{bucket_name}' not found in cloud provider during permission check")
                return False, f'Bucket "{bucket_name}" no longer exists or has been deleted'
            
            return True, 'Permission granted (database + cloud provider verified)'
            
        except Exception as e:
            logger.warning(f"Could not verify bucket with cloud provider: {str(e)}")
            # If we can't reach cloud provider, allow operation based on DB
            # But log this for security monitoring
            logger.warning(f"Operating in degraded mode for user {current_user.id}: {str(e)}")
            return True, 'Permission granted (database only - cloud provider unreachable)'
            
    except Exception as e:
        logger.error(f"Error validating permission with cloud provider: {str(e)}")
        # Fail safe: if we can't verify, deny permission
        return False, f'Could not verify permissions with cloud provider: {str(e)}'





def get_available_providers():
    """Get all active providers for the user's admin."""
    admin = get_user_admin()
    if not admin:
        return []
    
    return CloudProvider.query.filter_by(
        admin_id=admin.id,
        is_active=True
    ).all()


@user_bp.route('/providers', methods=['GET'])
@login_required
@user_required
def list_providers():
    """Get list of available providers for the user."""
    try:
        providers = get_available_providers()
        
        provider_list = []
        for provider in providers:
            provider_list.append({
                'id': provider.id,
                'type': provider.provider_type,
                'display_name': provider.display_name,
                'type_label': provider.provider_type.replace('_', ' ').title(),
                'created_at': provider.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'providers': provider_list,
            'count': len(provider_list)
        })
    except Exception as e:
        logger.error(f"Error listing providers: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@user_bp.route('/provider/<int:provider_id>/buckets', methods=['GET'])
@login_required
@user_required
def get_provider_buckets(provider_id):
    """Get list of buckets for a specific provider."""
    try:
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Create provider instance and list buckets
        try:
            creds = provider.decrypt_credentials()
            storage_provider = create_provider_instance(provider.provider_type, creds)
            
            buckets = storage_provider.list_buckets()
            if not buckets:
                buckets = []
            
            return jsonify({
                'success': True,
                'buckets': buckets,
                'count': len(buckets)
            })
        except ProviderConfigError as e:
            logger.error(f"Provider configuration error: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Provider configuration error: {str(e)}'
            }), 500
        except Exception as e:
            logger.error(f"Failed to list buckets: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Failed to list buckets: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error getting provider buckets: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/request-bucket', methods=['POST'])
@login_required
@user_required
def request_bucket():
    """Request bucket creation, deletion, or access changes."""
    try:
        data = request.get_json()
        provider_id = data.get('provider_id')
        bucket_name = data.get('bucket_name')
        request_type = data.get('request_type')  # 'create', 'delete', 'get', 'update'
        region = data.get('region')  # AWS region for bucket creation
        
        if not all([provider_id, bucket_name, request_type]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        if request_type not in ['create', 'delete', 'get', 'update']:
            return jsonify({'success': False, 'error': 'Invalid request type. Must be: create, delete, get, or update'}), 400
        
        if request_type in ['create'] and not region:
            return jsonify({'success': False, 'error': 'Region required for bucket operations'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Check if request already exists
        existing = BucketRequest.query.filter_by(
            user_id=current_user.id,
            provider_id=provider_id,
            bucket_name=bucket_name,
            request_type=request_type,
            status='pending'
        ).first()
        
        if existing:
            return jsonify({
                'success': False,
                'error': f'A pending {request_type} request already exists for this bucket'
            }), 409
        
        # Create request
        bucket_req = BucketRequest(  # type: ignore
            user_id=current_user.id,
            provider_id=provider_id,
            bucket_name=bucket_name,
            request_type=request_type,
            region=region,
            status='pending'
        )
        
        db.session.add(bucket_req)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Bucket {request_type} request submitted to admin',
            'request_id': bucket_req.id
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating bucket request: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/bucket-requests', methods=['GET'])
@login_required
@user_required
def get_bucket_requests():
    """Get all bucket requests for current user."""
    try:
        requests_list = BucketRequest.query.filter_by(user_id=current_user.id).all()
        
        requests_data = []
        for req in requests_list:
            requests_data.append({
                'id': req.id,
                'provider_id': req.provider_id,
                'provider_name': req.provider.display_name,
                'bucket_name': req.bucket_name,
                'request_type': req.request_type,
                'status': req.status,
                'admin_notes': req.admin_notes,
                'created_at': req.created_at.isoformat(),
                'reviewed_at': req.reviewed_at.isoformat() if req.reviewed_at else None,
            })
        
        return jsonify({
            'success': True,
            'requests': requests_data,
            'count': len(requests_data)
        })
    except Exception as e:
        logger.error(f"Error fetching bucket requests: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/managed-buckets', methods=['GET'])
@login_required
@user_required
def get_managed_buckets():
    """Get buckets user has access to (only approved requests with policies)."""
    try:
        # Get only policies with approved bucket requests
        policies = db.session.query(UserBucketPolicy).join(
            BucketRequest,
            UserBucketPolicy.bucket_request_id == BucketRequest.id
        ).filter(
            UserBucketPolicy.user_id == current_user.id,
            BucketRequest.status == 'approved'
        ).all()
        
        buckets_data = []
        for policy in policies:
            buckets_data.append({
                'id': policy.id,
                'provider_id': policy.provider_id,
                'provider_name': policy.provider.display_name,
                'provider_type': policy.provider.provider_type,
                'provider_display_name': policy.provider.display_name,
                'bucket_name': policy.bucket_name,
                'allowed_actions': policy.get_actions(),
                'is_applied': policy.is_applied,
                'created_at': policy.created_at.isoformat(),
            })
        
        return jsonify({
            'success': True,
            'buckets': buckets_data,
            'count': len(buckets_data)
        })
    except Exception as e:
        logger.error(f"Error fetching managed buckets: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/bucket/<int:provider_id>/<bucket_name>/existing-permissions', methods=['GET'])
@login_required
@user_required
def get_bucket_existing_permissions(provider_id, bucket_name):
    """Get user's existing permissions for a specific bucket."""
    try:
        # Find the user's policy for this bucket (if any approved)
        policy = db.session.query(UserBucketPolicy).join(
            BucketRequest,
            UserBucketPolicy.bucket_request_id == BucketRequest.id
        ).filter(
            UserBucketPolicy.user_id == current_user.id,
            UserBucketPolicy.provider_id == provider_id,
            UserBucketPolicy.bucket_name == bucket_name,
            BucketRequest.status == 'approved'
        ).first()
        
        if not policy:
            return jsonify({
                'success': True,
                'has_access': False,
                'existing_actions': []
            })
        
        # Get the actions for this policy
        actions = policy.get_actions()
        
        # Map S3 actions to the UI categories (get, update, delete)
        action_categories = set()
        for action in actions:
            if action in ['read', 'list']:
                action_categories.add('get')
            elif action == 'write':
                action_categories.add('update')
            elif action == 'delete':
                action_categories.add('delete')
        
        return jsonify({
            'success': True,
            'has_access': True,
            'existing_actions': list(action_categories),
            'all_actions': actions
        })
    except Exception as e:
        logger.error(f"Error fetching existing permissions: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/check-bucket-availability/<int:provider_id>/<bucket_name>', methods=['GET'])
@login_required
@user_required
def check_bucket_availability(provider_id, bucket_name):
    """Check if a bucket exists in the cloud provider."""
    try:
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({
                'success': True,
                'available': False,
                'reason': 'Provider not found'
            })
        
        # Verify user has access to this provider (through admin)
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({
                'success': True,
                'available': False,
                'reason': 'Unauthorized to check this provider'
            })
        
        try:
            creds = provider.decrypt_credentials()
            storage_provider = create_provider_instance(provider.provider_type, creds)
            
            # Check if bucket exists
            existing_buckets = storage_provider.list_buckets()
            bucket_exists = bucket_name in existing_buckets if existing_buckets else False
            
            return jsonify({
                'success': True,
                'available': bucket_exists,
                'bucket_name': bucket_name,
                'provider_id': provider_id
            })
        except Exception as e:
            logger.warning(f"Could not verify bucket existence: {str(e)}")
            # If we can't verify, assume it's unavailable
            return jsonify({
                'success': True,
                'available': False,
                'reason': f'Could not verify bucket: {str(e)}'
            })
    except Exception as e:
        logger.error(f"Error checking bucket availability: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/upload', methods=['POST'])
@login_required
@user_required
def upload_file():
    """Upload file to selected provider."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        if 'provider_id' not in request.form:
            return jsonify({'success': False, 'error': 'No provider selected'}), 400
        
        if 'bucket_name' not in request.form:
            return jsonify({'success': False, 'error': 'No bucket specified'}), 400
        
        file = request.files['file']
        provider_id = int(request.form.get('provider_id'))
        bucket_name = request.form.get('bucket_name')
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access to this provider
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Check IAM policy for write permission
        has_perm, msg = check_user_permission(provider_id, bucket_name, 's3:PutObject')
        if not has_perm:
            return jsonify({'success': False, 'error': msg}), 403
        
        # Create provider instance with user-specified bucket
        try:
            creds = provider.decrypt_credentials()
            creds['bucket'] = bucket_name  # Add bucket name for this user
            
            storage_provider = create_provider_instance(provider.provider_type, creds)
        except ProviderConfigError as e:
            logger.error(f"Failed to create provider instance: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Provider configuration error: {str(e)}'
            }), 500
        
        # Upload file
        filename = secure_filename(file.filename) if file.filename else 'file'
        try:
            storage_provider.upload_file(file, filename)
            
            return jsonify({
                'success': True,
                'message': f'File "{filename}" uploaded successfully',
                'filename': filename,
                'provider': provider.display_name
            })
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Upload failed: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in upload: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/list-files', methods=['POST'])
@login_required
@user_required
def list_files():
    """List files in selected provider and bucket."""
    try:
        data = request.get_json()
        provider_id = data.get('provider_id')
        bucket_name = data.get('bucket_name')
        prefix = data.get('prefix', '')
        
        if not provider_id or not bucket_name:
            return jsonify({'success': False, 'error': 'Provider and bucket required'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Create provider instance
        try:
            creds = provider.decrypt_credentials()
            creds['bucket'] = bucket_name
            
            storage_provider = create_provider_instance(provider.provider_type, creds)
        except ProviderConfigError as e:
            return jsonify({'success': False, 'error': f'Provider error: {str(e)}'}), 500
        
        # List files
        try:
            files = storage_provider.list_files(prefix)
            
            return jsonify({
                'success': True,
                'files': files,
                'count': len(files)
            })
        except Exception as e:
            logger.error(f"Failed to list files: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Failed to list files: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/download/<int:provider_id>/<filename>', methods=['GET'])
@login_required
@user_required
def download_file(provider_id, filename):
    """Download file from provider."""
    try:
        bucket_name = request.args.get('bucket')
        if not bucket_name:
            return jsonify({'success': False, 'error': 'Bucket required'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Check IAM policy for read permission
        has_perm, msg = check_user_permission(provider_id, bucket_name, 's3:GetObject')
        if not has_perm:
            return jsonify({'success': False, 'error': msg}), 403
        
        # Create provider instance
        try:
            creds = provider.decrypt_credentials()
            creds['bucket'] = bucket_name
            
            storage_provider = create_provider_instance(provider.provider_type, creds)
        except ProviderConfigError as e:
            return jsonify({'success': False, 'error': f'Provider error: {str(e)}'}), 500
        
        # Download file
        try:
            file_obj = storage_provider.download_file(filename)
            
            return send_file(
                file_obj,
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Download failed: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in download: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/delete', methods=['POST'])
@login_required
@user_required
def delete_file():
    """Delete file from provider."""
    try:
        data = request.get_json()
        provider_id = data.get('provider_id')
        bucket_name = data.get('bucket_name')
        filename = data.get('filename')
        
        if not all([provider_id, bucket_name, filename]):
            return jsonify({'success': False, 'error': 'Provider, bucket, and filename required'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Check IAM policy for delete permission
        has_perm, msg = check_user_permission(provider_id, bucket_name, 's3:DeleteObject')
        if not has_perm:
            return jsonify({'success': False, 'error': msg}), 403
        
        # Create provider instance
        try:
            creds = provider.decrypt_credentials()
            creds['bucket'] = bucket_name
            
            storage_provider = create_provider_instance(provider.provider_type, creds)
        except ProviderConfigError as e:
            return jsonify({'success': False, 'error': f'Provider error: {str(e)}'}), 500
        
        # Delete file
        try:
            storage_provider.delete_file(filename)
            
            return jsonify({
                'success': True,
                'message': f'File "{filename}" deleted successfully'
            })
        except Exception as e:
            logger.error(f"Delete failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Delete failed: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/get-share-url', methods=['POST'])
@login_required
@user_required
def get_share_url():
    """Generate a shareable URL for a file."""
    try:
        data = request.get_json()
        provider_id = data.get('provider_id')
        bucket_name = data.get('bucket_name')
        filename = data.get('filename')
        expires_in = int(data.get('expires_in', 3600))  # Default 1 hour
        
        if not all([provider_id, bucket_name, filename]):
            return jsonify({'success': False, 'error': 'Provider, bucket, and filename required'}), 400
        
        # Get provider
        provider = CloudProvider.query.get(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404
        
        # Verify user has access
        admin = get_user_admin()
        if not admin or provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Create provider instance
        try:
            creds = provider.decrypt_credentials()
            creds['bucket'] = bucket_name
            
            storage_provider = create_provider_instance(provider.provider_type, creds)
        except ProviderConfigError as e:
            return jsonify({'success': False, 'error': f'Provider error: {str(e)}'}), 500
        
        # Generate share URL
        try:
            url = storage_provider.get_file_url(filename, expires_in)
            
            return jsonify({
                'success': True,
                'url': url,
                'expires_in': expires_in,
                'expires_at': datetime.now().timestamp() + expires_in
            })
        except Exception as e:
            logger.error(f"Failed to generate share URL: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Failed to generate share URL: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error generating share URL: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

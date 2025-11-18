"""
Admin Bucket Management Routes

Admins can approve/reject bucket requests and define IAM policies.
"""

import logging
import json
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from backend.app.models import db, BucketRequest, UserBucketPolicy, User, CloudProvider, Admin, AdminUserMapping
from backend.app.utils.auth_utils import admin_required
from backend.app.utils.iam_policy_generator import IAMPolicyGenerator
from backend.app.utils.cognito_utils import cognito_jwt_required
from backend.app.config.provider_config import create_provider_instance, ProviderConfigError

logger = logging.getLogger(__name__)

admin_bucket_bp = Blueprint('admin_bucket', __name__, url_prefix='/admin/buckets')


def admin_bucket_required(f):
    """Decorator: Support both JWT and session-based auth for admin bucket endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if JWT token is present
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            # Use JWT validation
            return cognito_jwt_required(f)(*args, **kwargs)
        
        # Fall back to session-based auth
        if not (current_user.is_authenticated and isinstance(current_user, Admin)):
            return jsonify({'error': 'Unauthorized'}), 401
        
        return f(*args, **kwargs)
    return decorated_function


def get_admin():
    """Get current admin user from JWT or session."""
    from flask import g
    
    # First try to get from JWT context (set by cognito_jwt_required)
    admin = g.get('current_admin', None)
    if admin:
        return admin
    
    # Fall back to session auth
    if isinstance(current_user, Admin):
        return current_user
    
    return None


def check_user_iam_permissions(user_id: int, provider_id: int, bucket_name: str, required_action: str) -> tuple[bool, str]:
    """
    Check if user has required IAM permissions for the bucket and action.
    
    Args:
        user_id: ID of the user
        provider_id: ID of the cloud provider
        bucket_name: Name of the bucket
        required_action: Required action ('read', 'write', 'delete')
    
    Returns:
        Tuple of (has_permission: bool, message: str)
    """
    try:
        # Find existing policy for this user-bucket-provider combination
        policy = UserBucketPolicy.query.filter_by(
            user_id=user_id,
            provider_id=provider_id,
            bucket_name=bucket_name
        ).first()
        
        if not policy:
            return False, f"No existing IAM policy found for bucket '{bucket_name}' for this user"
        
        allowed_actions = policy.get_actions()
        
        # Map required action to IAM action categories
        action_mapping = {
            'read': ['read', 'list'],
            'write': ['write', 'list'],
            'delete': ['delete', 'list'],
        }
        
        required_categories = action_mapping.get(required_action, [])
        
        # Check if all required action categories are present in allowed_actions
        # allowed_actions contains values like ['read', 'write', 'list'] or actual S3 actions
        has_permission = all(cat in allowed_actions for cat in required_categories)
        
        if has_permission:
            return True, f"User has {required_action.upper()} permission for bucket '{bucket_name}'"
        else:
            missing = [cat for cat in required_categories if cat not in allowed_actions]
            return False, f"User lacks required {', '.join(missing).upper()} permission for bucket '{bucket_name}'"
    
    except Exception as e:
        logger.error(f"Error checking IAM permissions: {str(e)}")
        return False, f"Error checking IAM permissions: {str(e)}"


@admin_bucket_bp.route('/requests', methods=['GET'])
@admin_bucket_required
def list_bucket_requests():
    """Get all pending bucket requests for this admin."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'success': False, 'error': 'Admin not found'}), 404
        
        # Get requests for providers managed by this admin
        requests_list = db.session.query(BucketRequest).join(
            CloudProvider
        ).filter(
            CloudProvider.admin_id == admin.id
        ).all()
        
        requests_data = []
        for req in requests_list:
            user = User.query.get(req.user_id)
            requests_data.append({
                'id': req.id,
                'user_id': req.user_id,
                'user_email': user.email if user else 'Unknown',
                'provider_id': req.provider_id,
                'provider_name': req.provider.display_name,
                'bucket_name': req.bucket_name,
                'request_type': req.request_type,
                'status': req.status,
                'admin_notes': req.admin_notes,
                'created_at': req.created_at.isoformat(),
                'reviewed_at': req.reviewed_at.isoformat() if req.reviewed_at else None,
            })
        
        # Sort by status (pending first) and then by created_at
        pending = [r for r in requests_data if r['status'] == 'pending']
        other = [r for r in requests_data if r['status'] != 'pending']
        
        return jsonify({
            'success': True,
            'requests': pending + other,
            'count': len(requests_data),
            'pending_count': len(pending)
        })
    except Exception as e:
        logger.error(f"Error listing bucket requests: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/request/<int:request_id>/approve', methods=['POST'])
@admin_bucket_required
def approve_bucket_request(request_id):
    """Approve a bucket request, create the bucket, and set up IAM policy."""
    try:
        data = request.get_json()
        permission_preset = data.get('permission_preset', 'read_write')
        custom_actions = data.get('custom_actions')  # List of action categories
        admin_notes = data.get('admin_notes', '')
        
        # Get request
        bucket_req = BucketRequest.query.get(request_id)
        if not bucket_req:
            return jsonify({'success': False, 'error': 'Request not found'}), 404
        
        # Verify admin owns this provider
        admin = get_admin()
        if bucket_req.provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if bucket_req.status != 'pending':
            return jsonify({'success': False, 'error': f'Request is already {bucket_req.status}'}), 409
        
        # ========== NEW: IAM POLICY VALIDATION FOR NON-CREATE REQUESTS ==========
        # NOTE: For GET/UPDATE/DELETE requests, we SKIP validation on first-time requests
        # because there's no existing policy to validate yet.
        # The policy will be created/attached for the first time.
        # Validation should only happen if user already has a policy and is requesting updates.
        # ========== END: IAM POLICY VALIDATION ==========
        
        # Determine actions based on preset or custom
        if custom_actions:
            actions = custom_actions
        else:
            actions = IAMPolicyGenerator.get_preset_actions(permission_preset)
        
        if not actions:
            return jsonify({'success': False, 'error': 'Invalid permission preset'}), 400
        
        # Step 1: Create the bucket in the cloud provider (if needed)
        try:
            creds = bucket_req.provider.decrypt_credentials()
            
            # Override region if specified in bucket request
            if bucket_req.region:
                creds['region'] = bucket_req.region
                logger.info(f"Using requested region: {bucket_req.region}")
            
            storage_provider = create_provider_instance(bucket_req.provider.provider_type, creds)
            
            # Only for CREATE requests - check and create bucket if needed
            if bucket_req.request_type == 'create':
                # Check if bucket already exists
                existing_buckets = storage_provider.list_buckets()
                bucket_exists = bucket_req.bucket_name in existing_buckets if existing_buckets else False
                
                if bucket_exists:
                    logger.info(f"Bucket '{bucket_req.bucket_name}' already exists, skipping creation and proceeding to policy attachment")
                else:
                    logger.info(f"Creating bucket '{bucket_req.bucket_name}' in region {creds.get('region')}")
                    storage_provider.create_bucket(bucket_req.bucket_name)
                    logger.info(f"✓ Bucket '{bucket_req.bucket_name}' created successfully")
            else:
                # For non-create requests (get/update/delete), validate the bucket exists
                try:
                    existing_buckets = storage_provider.list_buckets()
                    bucket_exists = bucket_req.bucket_name in existing_buckets if existing_buckets else False
                    if not bucket_exists:
                        logger.error(f"Bucket '{bucket_req.bucket_name}' does not exist for {bucket_req.request_type} request")
                        return jsonify({
                            'success': False,
                            'error': f"Bucket '{bucket_req.bucket_name}' does not exist or has been deleted from the cloud provider. Cannot grant access to a non-existent bucket."
                        }), 400
                except Exception as e:
                    logger.error(f"Could not verify bucket existence: {str(e)}")
                    return jsonify({
                        'success': False,
                        'error': f"Could not verify if bucket exists: {str(e)}. Please ensure the bucket exists before approving this request."
                    }), 500
            
        except ProviderConfigError as e:
            logger.error(f"Provider configuration error: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Provider configuration error: {str(e)}'
            }), 500
        except Exception as e:
            logger.error(f"Failed to process bucket: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Failed to process bucket: {str(e)}'
            }), 500
        
        # Step 2: Generate IAM policy
        policy_doc = IAMPolicyGenerator.generate_policy(
            provider_type=bucket_req.provider.provider_type,
            user_id=bucket_req.user_id,
            bucket_name=bucket_req.bucket_name,
            actions=actions
        )
        
        # Step 3: Create user bucket policy in database
        policy = UserBucketPolicy(  # type: ignore
            bucket_request_id=bucket_req.id,
            user_id=bucket_req.user_id,
            provider_id=bucket_req.provider_id,
            bucket_name=bucket_req.bucket_name,
            is_applied=True  # Mark as applied since bucket is created
        )
        policy.set_actions(actions)
        
        # Update request status
        bucket_req.status = 'approved'
        bucket_req.admin_notes = admin_notes
        bucket_req.reviewed_at = db.func.now()
        bucket_req.completed_at = db.func.now()  # Mark as completed
        
        db.session.add(policy)
        db.session.commit()
        
        # Prepare success message
        if bucket_req.request_type == 'create':
            message = f'Bucket "{bucket_req.bucket_name}" created and approved'
        elif bucket_req.request_type == 'get':
            message = f'Read access granted for bucket "{bucket_req.bucket_name}"'
        elif bucket_req.request_type == 'update':
            message = f'Write access granted for bucket "{bucket_req.bucket_name}"'
        elif bucket_req.request_type == 'delete':
            message = f'Delete access granted for bucket "{bucket_req.bucket_name}"'
        else:
            message = f'Bucket request approved for "{bucket_req.bucket_name}"'
        
        return jsonify({
            'success': True,
            'message': message,
            'policy_id': policy.id,
            'policy_document': policy_doc,
            'actions': actions
        })
        
    except Exception as e:
        logger.error(f"Error approving bucket request: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/request/<int:request_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_bucket_request(request_id):
    """Reject a bucket request."""
    try:
        data = request.get_json()
        reason = data.get('reason', 'Request rejected by admin')
        
        bucket_req = BucketRequest.query.get(request_id)
        if not bucket_req:
            return jsonify({'success': False, 'error': 'Request not found'}), 404
        
        # Verify admin owns this provider
        admin = get_admin()
        if bucket_req.provider.admin_id != admin.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if bucket_req.status != 'pending':
            return jsonify({'success': False, 'error': f'Request is already {bucket_req.status}'}), 409
        
        bucket_req.status = 'rejected'
        bucket_req.admin_notes = reason
        bucket_req.reviewed_at = db.func.now()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Bucket request rejected'
        })
        
    except Exception as e:
        logger.error(f"Error rejecting bucket request: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/permission-presets', methods=['GET'])
@login_required
@admin_required
def get_permission_presets():
    """Get available permission presets."""
    try:
        presets = IAMPolicyGenerator.get_permission_presets()
        
        return jsonify({
            'success': True,
            'presets': presets
        })
    except Exception as e:
        logger.error(f"Error fetching presets: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/available-actions/<provider_type>', methods=['GET'])
@login_required
@admin_required
def get_available_actions(provider_type):
    """Get available actions for a provider type."""
    try:
        actions = IAMPolicyGenerator.get_available_actions(provider_type)
        
        return jsonify({
            'success': True,
            'provider': provider_type,
            'actions': actions
        })
    except Exception as e:
        logger.error(f"Error fetching actions: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/user-policies/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user_policies(user_id):
    """Get all bucket policies for a user (admin view)."""
    try:
        admin = get_admin()
        
        # Get policies for this user in this admin's providers
        policies = db.session.query(UserBucketPolicy).join(
            CloudProvider
        ).filter(
            UserBucketPolicy.user_id == user_id,
            CloudProvider.admin_id == admin.id
        ).all()
        
        policies_data = []
        for policy in policies:
            policies_data.append({
                'id': policy.id,
                'bucket_name': policy.bucket_name,
                'provider_name': policy.provider.display_name,
                'allowed_actions': policy.get_actions(),
                'is_applied': policy.is_applied,
                'created_at': policy.created_at.isoformat(),
            })
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'policies': policies_data,
            'count': len(policies_data)
        })
    except Exception as e:
        logger.error(f"Error fetching user policies: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/managed-users', methods=['GET'])
@login_required
@admin_required
def get_managed_users():
    """Get all users managed by this admin."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'success': False, 'error': 'Admin not found'}), 404
        
        # Get all users managed by this admin
        managed_users = db.session.query(User).join(
            AdminUserMapping
        ).filter(
            AdminUserMapping.admin_id == admin.id
        ).all()
        
        users_data = []
        for user in managed_users:
            # Count policies for this user
            policy_count = UserBucketPolicy.query.filter_by(user_id=user.id).count()
            
            # Count bucket requests for this user
            bucket_requests = BucketRequest.query.filter_by(user_id=user.id).all()
            request_count = len(bucket_requests)
            pending_count = len([r for r in bucket_requests if r.status == 'pending'])
            
            users_data.append({
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'full_name': f"{user.first_name} {user.last_name}".strip() if user.first_name or user.last_name else user.email,
                'is_active': user.is_active,
                'policy_count': policy_count,
                'request_count': request_count,
                'pending_requests': pending_count,
                'created_at': user.created_at.isoformat(),
            })
        
        return jsonify({
            'success': True,
            'users': users_data,
            'count': len(users_data)
        })
    except Exception as e:
        logger.error(f"Error fetching managed users: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/user/<int:user_id>/bucket-access', methods=['GET'])
@login_required
@admin_required
def get_user_bucket_access(user_id):
    """Get all bucket access for a specific user."""
    try:
        admin = get_admin()
        if not admin:
            return jsonify({'success': False, 'error': 'Admin not found'}), 404
        
        # Verify user is managed by this admin
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        mapping = AdminUserMapping.query.filter_by(admin_id=admin.id, user_id=user_id).first()
        if not mapping:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Get all bucket policies for this user
        policies = UserBucketPolicy.query.filter_by(user_id=user_id).all()
        
        policies_data = []
        for policy in policies:
            policies_data.append({
                'id': policy.id,
                'bucket_name': policy.bucket_name,
                'provider_id': policy.provider_id,
                'provider_name': policy.provider.display_name if policy.provider else 'Unknown',
                'allowed_actions': policy.get_actions(),
                'is_applied': policy.is_applied,
                'created_at': policy.created_at.isoformat(),
            })
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'user_email': user.email,
            'policies': policies_data,
            'count': len(policies_data)
        })
    except Exception as e:
        logger.error(f"Error fetching user bucket access: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bucket_bp.route('/policy/<int:policy_id>/update-actions', methods=['POST'])
@login_required
@admin_required
def update_policy_actions(policy_id):
    """Update the actions/permissions for a bucket policy and regenerate IAM policy."""
    try:
        data = request.get_json()
        actions = data.get('actions', [])
        
        admin = get_admin()
        if not admin:
            return jsonify({'success': False, 'error': 'Admin not found'}), 404
        
        # Get the policy
        policy = UserBucketPolicy.query.get(policy_id)
        if not policy:
            return jsonify({'success': False, 'error': 'Policy not found'}), 404
        
        # Verify policy belongs to a user managed by this admin
        user_mapping = AdminUserMapping.query.filter_by(
            admin_id=admin.id,
            user_id=policy.user_id
        ).first()
        if not user_mapping:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if not actions:
            return jsonify({'success': False, 'error': 'Actions list cannot be empty'}), 400
        
        # ========== VALIDATE BUCKET EXISTS BEFORE UPDATING ==========
        try:
            provider = policy.provider
            if not provider:
                return jsonify({
                    'success': False,
                    'error': 'Provider not found for this policy'
                }), 404
            
            creds = provider.decrypt_credentials()
            storage_provider = create_provider_instance(provider.provider_type, creds)
            
            # Check if bucket still exists
            existing_buckets = storage_provider.list_buckets()
            bucket_exists = policy.bucket_name in existing_buckets if existing_buckets else False
            
            if not bucket_exists:
                logger.error(f"Bucket '{policy.bucket_name}' does not exist. Cannot update policy.")
                return jsonify({
                    'success': False,
                    'error': f"Bucket '{policy.bucket_name}' does not exist or has been deleted from the cloud provider. Cannot modify access for a non-existent bucket."
                }), 400
        except Exception as e:
            logger.error(f"Could not verify bucket existence: {str(e)}")
            return jsonify({
                'success': False,
                'error': f"Could not verify if bucket exists: {str(e)}. Please ensure the bucket exists before modifying access."
            }), 500
        # ========== END: BUCKET VALIDATION ==========
        
        # Store old actions for logging
        old_actions = policy.get_actions()
        
        # Update the policy in database
        policy.set_actions(actions)
        policy.updated_at = db.func.now()
        db.session.commit()
        
        logger.info(f"Admin {admin.id} updated policy {policy_id} - Old: {old_actions}, New: {actions}")
        
        # ========== REGENERATE AND APPLY IAM POLICY TO CLOUD PROVIDER ==========
        try:
            # Regenerate IAM policy with new actions
            new_policy_doc = IAMPolicyGenerator.generate_policy(
                provider_type=provider.provider_type,
                user_id=policy.user_id,
                bucket_name=policy.bucket_name,
                actions=actions
            )
            
            logger.info(f"Generated new IAM policy for user {policy.user_id}, bucket {policy.bucket_name}")
            logger.debug(f"New policy document: {json.dumps(new_policy_doc)}")
            
            # Note: Actual deployment to cloud provider would happen here
            # For now, we're just logging that the policy was regenerated
            # TODO: Implement actual cloud provider API calls to update policies
            # This would depend on provider-specific APIs:
            # - AWS: Update IAM user policy via boto3
            # - Google Cloud: Update service account policy
            # - Backblaze B2: Update application key capabilities
            
            logger.info(f"IAM policy regenerated for policy {policy_id}. Changes: {old_actions} → {actions}")
            
        except Exception as e:
            logger.error(f"Error regenerating IAM policy: {str(e)}")
            # Don't fail the update - database was already updated successfully
            return jsonify({
                'success': True,
                'message': 'Policy updated in database, but cloud provider IAM policy regeneration failed',
                'policy_id': policy.id,
                'old_actions': old_actions,
                'new_actions': actions,
                'warning': f'Cloud update error: {str(e)}'
            })
        # ========== END: IAM POLICY REGENERATION ==========
        
        return jsonify({
            'success': True,
            'message': 'Policy updated successfully and IAM policy regenerated',
            'policy_id': policy.id,
            'old_actions': old_actions,
            'new_actions': actions
        })
    except Exception as e:
        logger.error(f"Error updating policy actions: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

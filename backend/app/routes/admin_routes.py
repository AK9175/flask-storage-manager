"""
Admin management routes - handle user invitations, user management, and admin dashboard.
"""
from flask import Blueprint, request, jsonify, render_template, g
from datetime import datetime
import logging
import os

from backend.app.models import db, User, Admin, AdminUserMapping, SignupInvitation
from backend.app.utils.auth_utils import generate_invitation_token_for_user, send_signup_invitation_email
from backend.app.utils.cognito_utils import cognito_jwt_required

logger = logging.getLogger(__name__)
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def cognito_admin_required(f):
    """Decorator to ensure JWT token belongs to an admin."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get cognito_user_sub from g (set by cognito_jwt_required)
        cognito_sub = g.get('cognito_user_sub')
        if not cognito_sub:
            logger.warning("No cognito_user_sub in g - JWT validation may have failed")
            return jsonify({'error': 'Unauthorized', 'message': 'Missing or invalid authentication token'}), 401
        
        # Verify admin exists with this cognito_sub
        admin = Admin.query.filter_by(cognito_sub=cognito_sub).first()
        if not admin:
            logger.warning(f"User {cognito_sub} attempted admin access but is not an admin")
            return jsonify({'error': 'Forbidden', 'message': 'Admin access required. You do not have admin privileges.'}), 403
        
        # Store admin in request context for use in the route
        g.current_admin = admin
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Admin Dashboard
# ============================================================================

@admin_bp.route('/dashboard')
@cognito_jwt_required
@cognito_admin_required
def dashboard():
    """Admin dashboard."""
    admin = g.current_admin
    return render_template('admin/dashboard.html', admin=admin)


@admin_bp.route('/users')
@cognito_jwt_required
@cognito_admin_required
def users_management():
    """User management page."""
    admin = g.current_admin
    return render_template('admin/user_management.html', admin=admin)



@admin_bp.route('/stats', methods=['GET'])
@cognito_jwt_required
@cognito_admin_required
def get_stats():
    """Get admin statistics."""
    managed_users = User.query.join(
        AdminUserMapping,
        AdminUserMapping.user_id == User.id
    ).filter(AdminUserMapping.admin_id == g.current_admin.id).all()

    pending_invitations = SignupInvitation.query.filter_by(
        admin_id=g.current_admin.id,
        is_used=False
    ).all()

    active_users = [u for u in managed_users if u.is_active]

    return jsonify({
        'total_users': len(managed_users),
        'active_users': len(active_users),
        'inactive_users': len(managed_users) - len(active_users),
        'pending_invitations': len(pending_invitations)
    }), 200


# ============================================================================
# User Invitations
# ============================================================================

@admin_bp.route('/invitations', methods=['POST'])
@cognito_jwt_required
@cognito_admin_required
def send_invitation():
    """Send invitation to a new user."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Validate email format
    if '@' not in email or '.' not in email.split('@')[1]:
        return jsonify({'error': 'Invalid email format'}), 400

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User with this email already exists'}), 409

    # Check if invitation already exists and not used
    existing_invitation = SignupInvitation.query.filter_by(
        admin_id=g.current_admin.id,
        email=email,
        is_used=False
    ).first()

    if existing_invitation and not existing_invitation.is_expired():
        return jsonify({'error': 'Invitation already sent to this email'}), 409

    try:
        # Generate invitation token
        token = generate_invitation_token_for_user(g.current_admin.id, email)
        
        # Send email
        app_url = os.environ.get('APP_URL', request.host_url.rstrip('/'))
        email_sent = send_signup_invitation_email(email, g.current_admin.email, token, app_url)

        if not email_sent:
            # Delete the invitation if email failed
            invitation = SignupInvitation.query.filter_by(invitation_token=token).first()
            if invitation:
                db.session.delete(invitation)
                db.session.commit()
            logger.error(f"Failed to send invitation email to {email}")
            return jsonify({'error': 'Failed to send invitation email. Please try again later.'}), 500

        logger.info(f"Invitation sent by {g.current_admin.email} to {email}")
        return jsonify({'message': 'Invitation sent successfully', 'email': email}), 200

    except Exception as e:
        logger.error(f"Error sending invitation: {str(e)}")
        return jsonify({'error': 'An error occurred while sending invitation'}), 500


@admin_bp.route('/invitations', methods=['GET'])
@cognito_jwt_required
@cognito_admin_required
def list_invitations():
    """List all invitations sent by this admin."""
    invitations = SignupInvitation.query.filter_by(admin_id=g.current_admin.id).order_by(
        SignupInvitation.created_at.desc()
    ).all()

    invitation_data = []
    for inv in invitations:
        invitation_data.append({
            'id': inv.id,
            'email': inv.email,
            'is_used': inv.is_used,
            'is_expired': inv.is_expired(),
            'created_at': inv.created_at.isoformat(),
            'expires_at': inv.expires_at.isoformat() if inv.expires_at else None
        })

    return jsonify({'invitations': invitation_data}), 200


@admin_bp.route('/invitations/<int:invitation_id>/resend', methods=['POST'])
@cognito_jwt_required
@cognito_admin_required
def resend_invitation(invitation_id):
    """Resend an invitation."""
    invitation = SignupInvitation.query.get(invitation_id)

    if not invitation or invitation.admin_id != g.current_admin.id:
        return jsonify({'error': 'Invitation not found'}), 404

    if invitation.is_used:
        return jsonify({'error': 'This invitation has already been used'}), 400

    if invitation.is_expired():
        return jsonify({'error': 'This invitation has expired'}), 400

    try:
        # Send email again
        app_url = os.environ.get('APP_URL', request.host_url.rstrip('/'))
        email_sent = send_signup_invitation_email(
            invitation.email,
            g.current_admin.email,
            invitation.invitation_token,
            app_url
        )

        if not email_sent:
            logger.error(f"Failed to resend invitation email to {invitation.email}")
            return jsonify({'error': 'Failed to resend invitation email'}), 500

        logger.info(f"Invitation resent by {g.current_admin.email} to {invitation.email}")
        return jsonify({'message': 'Invitation resent successfully'}), 200

    except Exception as e:
        logger.error(f"Error resending invitation: {str(e)}")
        return jsonify({'error': 'An error occurred while resending invitation'}), 500


@admin_bp.route('/invitations/<int:invitation_id>', methods=['DELETE'])
@cognito_jwt_required
@cognito_admin_required
def cancel_invitation(invitation_id):
    """Cancel an invitation."""
    invitation = SignupInvitation.query.get(invitation_id)

    if not invitation or invitation.admin_id != g.current_admin.id:
        return jsonify({'error': 'Invitation not found'}), 404

    if invitation.is_used:
        return jsonify({'error': 'Cannot cancel a used invitation'}), 400

    try:
        db.session.delete(invitation)
        db.session.commit()
        logger.info(f"Invitation to {invitation.email} cancelled by {g.current_admin.email}")
        return jsonify({'message': 'Invitation cancelled successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cancelling invitation: {str(e)}")
        return jsonify({'error': 'An error occurred while cancelling invitation'}), 500


# ============================================================================
# User Management
# ============================================================================

@admin_bp.route('/users', methods=['GET'])
@cognito_jwt_required
@cognito_admin_required
def list_users():
    """List all users managed by this admin."""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str).strip().lower()

    # Query users managed by this admin
    query = User.query.join(
        AdminUserMapping,
        AdminUserMapping.user_id == User.id
    ).filter(AdminUserMapping.admin_id == g.current_admin.id)

    # Apply search filter
    if search:
        query = query.filter(
            (User.email.ilike(f'%{search}%')) |
            (User.first_name.ilike(f'%{search}%')) |
            (User.last_name.ilike(f'%{search}%'))
        )

    # Paginate results
    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    user_data = []
    for user in paginated.items:
        # Get mapping to get assigned_at date
        mapping = AdminUserMapping.query.filter_by(
            admin_id=g.current_admin.id,
            user_id=user.id
        ).first()

        user_data.append({
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat(),
            'assigned_at': mapping.assigned_at.isoformat() if mapping else None
        })

    return jsonify({
        'users': user_data,
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page,
        'per_page': per_page
    }), 200


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@cognito_jwt_required
@cognito_admin_required
def get_user_details(user_id):
    """Get details of a specific user managed by this admin."""
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if admin manages this user
    mapping = AdminUserMapping.query.filter_by(
        admin_id=g.current_admin.id,
        user_id=user_id
    ).first()

    if not mapping:
        return jsonify({'error': 'User not found in your managed users'}), 404

    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'updated_at': user.updated_at.isoformat(),
        'assigned_at': mapping.assigned_at.isoformat()
    }), 200


@admin_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@cognito_jwt_required
@cognito_admin_required
def deactivate_user(user_id):
    """Deactivate a user."""
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if admin manages this user
    mapping = AdminUserMapping.query.filter_by(
        admin_id=g.current_admin.id,
        user_id=user_id
    ).first()

    if not mapping:
        return jsonify({'error': 'User not found in your managed users'}), 404

    try:
        user.is_active = False
        user.updated_at = datetime.utcnow()
        db.session.commit()
        logger.info(f"User {user.email} deactivated by {g.current_admin.email}")
        return jsonify({'message': 'User deactivated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deactivating user: {str(e)}")
        return jsonify({'error': 'An error occurred while deactivating user'}), 500


@admin_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@cognito_jwt_required
@cognito_admin_required
def activate_user(user_id):
    """Activate a deactivated user."""
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if admin manages this user
    mapping = AdminUserMapping.query.filter_by(
        admin_id=g.current_admin.id,
        user_id=user_id
    ).first()

    if not mapping:
        return jsonify({'error': 'User not found in your managed users'}), 404

    try:
        user.is_active = True
        user.updated_at = datetime.utcnow()
        db.session.commit()
        logger.info(f"User {user.email} activated by {g.current_admin.email}")
        return jsonify({'message': 'User activated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error activating user: {str(e)}")
        return jsonify({'error': 'An error occurred while activating user'}), 500


@admin_bp.route('/users/<int:user_id>/remove', methods=['DELETE'])
@cognito_jwt_required
@cognito_admin_required
def remove_user(user_id):
    """Remove a user from admin's management (disconnect only, don't delete user)."""
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if admin manages this user
    mapping = AdminUserMapping.query.filter_by(
        admin_id=g.current_admin.id,
        user_id=user_id
    ).first()

    if not mapping:
        return jsonify({'error': 'User not found in your managed users'}), 404

    try:
        db.session.delete(mapping)
        db.session.commit()
        logger.info(f"User {user.email} removed from management by {g.current_admin.email}")
        return jsonify({'message': 'User removed from your management'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing user: {str(e)}")
        return jsonify({'error': 'An error occurred while removing user'}), 500

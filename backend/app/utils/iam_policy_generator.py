"""
IAM Policy Generator

Generates cloud-provider-specific IAM policies for user bucket access.
Supports AWS S3 and other providers.
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class IAMPolicyGenerator:
    """Generate IAM policies for different cloud providers."""
    
    # Available actions per provider
    AVAILABLE_ACTIONS = {
        'aws_s3': {
            'read': ['s3:GetObject', 's3:GetObjectVersion'],
            'write': ['s3:PutObject', 's3:PutObjectAcl'],
            'delete': ['s3:DeleteObject', 's3:DeleteObjectVersion'],
            'list': ['s3:ListBucket', 's3:GetBucketLocation'],
        },
        'google_cloud': {
            'read': ['storage.objects.get'],
            'write': ['storage.objects.create'],
            'delete': ['storage.objects.delete'],
            'list': ['storage.buckets.get', 'storage.objects.list'],
        },
        'backblaze_b2': {
            'read': ['b2_read_file_by_id'],
            'write': ['b2_write_file'],
            'delete': ['b2_delete_file_version'],
            'list': ['b2_list_file_names', 'b2_list_file_versions'],
        },
    }
    
    # Preset permission sets
    PERMISSION_SETS = {
        'upload_only': {
            'description': 'Can upload files only',
            'actions': ['write', 'list'],
        },
        'download_only': {
            'description': 'Can download files only',
            'actions': ['read', 'list'],
        },
        'full_access': {
            'description': 'Can upload, download, and delete files',
            'actions': ['read', 'write', 'delete', 'list'],
        },
        'read_write': {
            'description': 'Can upload and download, but not delete',
            'actions': ['read', 'write', 'list'],
        },
    }
    
    @staticmethod
    def generate_aws_policy(user_id: int, bucket_name: str, actions: List[str]) -> Dict[str, Any]:
        """
        Generate AWS S3 IAM policy document.
        
        Args:
            user_id: User ID for policy naming
            bucket_name: S3 bucket name
            actions: List of allowed actions (e.g., ['read', 'write', 'list'])
        
        Returns:
            IAM policy document as dict
        """
        # Convert action categories to actual S3 permissions
        s3_actions = []
        for action in actions:
            if action in IAMPolicyGenerator.AVAILABLE_ACTIONS['aws_s3']:
                s3_actions.extend(IAMPolicyGenerator.AVAILABLE_ACTIONS['aws_s3'][action])
        
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"AllowListBucket{user_id}",
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation"
                    ],
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                },
                {
                    "Sid": f"AllowObjectOperations{user_id}",
                    "Effect": "Allow",
                    "Action": list(set(s3_actions)),  # Remove duplicates
                    "Resource": f"arn:aws:s3:::{bucket_name}/*"
                }
            ]
        }
        
        return policy
    
    @staticmethod
    def generate_gcs_policy(user_id: int, bucket_name: str, actions: List[str]) -> Dict[str, Any]:
        """
        Generate Google Cloud Storage IAM policy.
        
        Args:
            user_id: User ID for policy naming
            bucket_name: GCS bucket name
            actions: List of allowed actions (e.g., ['read', 'write', 'list'])
        
        Returns:
            GCS IAM policy document as dict
        """
        gcs_actions = []
        for action in actions:
            if action in IAMPolicyGenerator.AVAILABLE_ACTIONS['google_cloud']:
                gcs_actions.extend(IAMPolicyGenerator.AVAILABLE_ACTIONS['google_cloud'][action])
        
        policy = {
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",
                    "members": [f"user:user-{user_id}@example.com"],
                    "condition": {
                        "expression": f"resource.name.startsWith('projects/_/buckets/{bucket_name}')"
                    }
                } if 'read' in actions else None,
                {
                    "role": "roles/storage.objectCreator",
                    "members": [f"user:user-{user_id}@example.com"],
                    "condition": {
                        "expression": f"resource.name.startsWith('projects/_/buckets/{bucket_name}')"
                    }
                } if 'write' in actions else None,
            ]
        }
        
        # Remove None entries
        policy['bindings'] = [b for b in policy['bindings'] if b is not None]
        
        return policy
    
    @staticmethod
    def generate_policy(provider_type: str, user_id: int, bucket_name: str, actions: List[str]) -> Dict[str, Any]:
        """
        Generate IAM policy for specified provider.
        
        Args:
            provider_type: Type of provider (aws_s3, google_cloud, etc.)
            user_id: User ID for policy naming
            bucket_name: Bucket/container name
            actions: List of allowed action categories
        
        Returns:
            IAM policy document as dict
        """
        if provider_type == 'aws_s3':
            return IAMPolicyGenerator.generate_aws_policy(user_id, bucket_name, actions)
        elif provider_type == 'google_cloud':
            return IAMPolicyGenerator.generate_gcs_policy(user_id, bucket_name, actions)
        else:
            # Return generic policy structure
            logger.warning(f"No specific policy generator for {provider_type}, returning generic policy")
            return {
                "provider": provider_type,
                "bucket": bucket_name,
                "user_id": user_id,
                "actions": actions,
                "generated_at": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    def get_available_actions(provider_type: str) -> Dict[str, List[str]]:
        """Get available actions for a provider."""
        return IAMPolicyGenerator.AVAILABLE_ACTIONS.get(provider_type, {})
    
    @staticmethod
    def get_permission_presets() -> Dict[str, Dict[str, Any]]:
        """Get available permission presets."""
        return IAMPolicyGenerator.PERMISSION_SETS
    
    @staticmethod
    def get_preset_actions(preset_name: str) -> List[str]:
        """Get actions for a preset."""
        if preset_name in IAMPolicyGenerator.PERMISSION_SETS:
            return IAMPolicyGenerator.PERMISSION_SETS[preset_name]['actions']
        return []

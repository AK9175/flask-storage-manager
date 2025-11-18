"""
Provider Configuration Management Module

Handles validation, testing, and instantiation of cloud storage provider credentials.
Provides a unified interface for managing multiple cloud provider configurations per admin.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from backend.app.services.storage_providers import (
    AWSS3Provider, BackblazeB2Provider, WasabiProvider, GoogleCloudStorageProvider,
    DigitalOceanSpacesProvider, CloudflareR2Provider, HetznerStorageProvider,
    StorageProvider
)

logger = logging.getLogger(__name__)


# Provider type mapping (matches get_storage_provider keys)
PROVIDER_CLASSES = {
    'aws_s3': AWSS3Provider,
    'backblaze_b2': BackblazeB2Provider,
    'wasabi': WasabiProvider,
    'google_cloud': GoogleCloudStorageProvider,
    'digitalocean_spaces': DigitalOceanSpacesProvider,
    'cloudflare_r2': CloudflareR2Provider,
    'hetzner': HetznerStorageProvider,
}


class ProviderConfigError(Exception):
    """Raised when provider configuration is invalid."""
    pass


class ProviderConnectionError(Exception):
    """Raised when unable to connect to provider."""
    pass


def get_provider_class(provider_type: str) -> type:
    """
    Get provider class by type.
    
    Args:
        provider_type: Type identifier (e.g., 'aws_s3', 'google_cloud')
        
    Returns:
        Provider class
        
    Raises:
        ProviderConfigError: If provider type not supported
    """
    if provider_type not in PROVIDER_CLASSES:
        raise ProviderConfigError(
            f"Unsupported provider type: {provider_type}. "
            f"Available: {', '.join(PROVIDER_CLASSES.keys())}"
        )
    return PROVIDER_CLASSES[provider_type]


def validate_provider_credentials(provider_type: str, credentials: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate provider credentials format and required fields.
    
    Args:
        provider_type: Type identifier
        credentials: Dictionary of credentials for the provider
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    required_fields = {
        'aws_s3': ['access_key', 'secret_key'],
        'backblaze_b2': ['application_key_id', 'application_key'],
        'wasabi': ['access_key', 'secret_key'],
        'google_cloud': ['project_id', 'credentials_json'],
        'digitalocean_spaces': ['access_key', 'secret_key', 'endpoint'],
        'cloudflare_r2': ['account_id', 'access_key', 'secret_key'],
        'hetzner': ['access_key', 'secret_key', 'endpoint'],
    }
    
    if provider_type not in required_fields:
        return False, f"Unknown provider type: {provider_type}"
    
    missing = [f for f in required_fields[provider_type] if f not in credentials]
    if missing:
        return False, f"Missing required fields for {provider_type}: {', '.join(missing)}"
    
    # Type-specific validation
    if provider_type == 'google_cloud':
        try:
            import json
            json.loads(credentials.get('credentials_json', '{}'))
        except (json.JSONDecodeError, ValueError):
            return False, "credentials_json must be valid JSON"
    
    return True, ""


def test_provider_connection(provider_type: str, credentials: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Test connection to cloud provider.
    
    Args:
        provider_type: Type identifier
        credentials: Validated credentials dictionary
        
    Returns:
        Tuple of (is_connected, message)
    """
    try:
        # Validate credentials format first
        is_valid, error_msg = validate_provider_credentials(provider_type, credentials)
        if not is_valid:
            return False, f"Invalid credentials: {error_msg}"
        
        # Get provider class and instantiate
        provider_class = get_provider_class(provider_type)
        provider = provider_class(**credentials)
        
        # Test connection by listing buckets/containers
        buckets = provider.list_buckets()
        if buckets is None:
            return False, "Failed to list buckets - check credentials"
        
        return True, f"Connected successfully. Found {len(buckets)} bucket(s)"
        
    except Exception as e:
        logger.error(f"Provider connection test failed: {str(e)}")
        return False, f"Connection failed: {str(e)}"


def list_provider_buckets(provider_type: str, credentials: Dict[str, Any]) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    List available buckets/containers for provider.
    
    Args:
        provider_type: Type identifier
        credentials: Validated credentials dictionary
        
    Returns:
        Tuple of (bucket_list, error_message). Returns (None, error_msg) on failure.
    """
    try:
        is_valid, error_msg = validate_provider_credentials(provider_type, credentials)
        if not is_valid:
            return None, f"Invalid credentials: {error_msg}"
        
        provider_class = get_provider_class(provider_type)
        provider = provider_class(**credentials)
        
        buckets = provider.list_buckets()
        if buckets is None:
            return None, "Failed to retrieve buckets"
        
        return buckets, None
        
    except Exception as e:
        logger.error(f"Failed to list buckets for {provider_type}: {str(e)}")
        return None, str(e)


def get_provider_info(provider_type: str) -> Dict[str, Any]:
    """
    Get information about a provider type (required fields, description, etc).
    
    Args:
        provider_type: Type identifier
        
    Returns:
        Dictionary with provider metadata
    """
    provider_info = {
        'aws_s3': {
            'name': 'Amazon S3',
            'description': 'Amazon Web Services Simple Storage Service',
            'fields': [
                {'name': 'access_key', 'label': 'Access Key', 'type': 'text', 'required': True},
                {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'required': True},
                {'name': 'region', 'label': 'Region', 'type': 'text', 'required': True, 'placeholder': 'e.g., us-east-1'},
            ]
        },
        'google_cloud': {
            'name': 'Google Cloud Storage',
            'description': 'Google Cloud Platform Storage',
            'fields': [
                {'name': 'project_id', 'label': 'Project ID', 'type': 'text', 'required': True},
                {'name': 'credentials_json', 'label': 'Service Account JSON', 'type': 'textarea', 'required': True},
            ]
        },
        'backblaze_b2': {
            'name': 'Backblaze B2',
            'description': 'Backblaze B2 Cloud Storage',
            'fields': [
                {'name': 'application_key_id', 'label': 'Application Key ID', 'type': 'text', 'required': True},
                {'name': 'application_key', 'label': 'Application Key', 'type': 'password', 'required': True},
            ]
        },
        'wasabi': {
            'name': 'Wasabi',
            'description': 'Wasabi Cloud Storage',
            'fields': [
                {'name': 'access_key', 'label': 'Access Key', 'type': 'text', 'required': True},
                {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'required': True},
                {'name': 'region', 'label': 'Region', 'type': 'text', 'required': True, 'placeholder': 'e.g., us-west-1'},
            ]
        },
        'digitalocean_spaces': {
            'name': 'DigitalOcean Spaces',
            'description': 'DigitalOcean Spaces Object Storage',
            'fields': [
                {'name': 'access_key', 'label': 'Access Key', 'type': 'text', 'required': True},
                {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'required': True},
                {'name': 'region', 'label': 'Region', 'type': 'text', 'required': True, 'placeholder': 'e.g., nyc3'},
                {'name': 'endpoint', 'label': 'Endpoint', 'type': 'text', 'required': True, 'placeholder': 'nyc3.digitaloceanspaces.com'},
            ]
        },
        'cloudflare_r2': {
            'name': 'Cloudflare R2',
            'description': 'Cloudflare R2 Object Storage',
            'fields': [
                {'name': 'account_id', 'label': 'Account ID', 'type': 'text', 'required': True},
                {'name': 'access_key', 'label': 'Access Key', 'type': 'text', 'required': True},
                {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'required': True},
            ]
        },
        'hetzner': {
            'name': 'Hetzner Storage Box',
            'description': 'Hetzner Storage Box S3 Compatible',
            'fields': [
                {'name': 'access_key', 'label': 'Access Key', 'type': 'text', 'required': True},
                {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'required': True},
                {'name': 'region', 'label': 'Region', 'type': 'text', 'required': True},
                {'name': 'endpoint', 'label': 'Endpoint', 'type': 'text', 'required': True, 'placeholder': 'storage.hetzner.cloud'},
            ]
        },
    }
    
    return provider_info.get(provider_type, {})


def list_available_providers() -> List[Dict[str, Any]]:
    """
    Get list of all available provider types with metadata.
    
    Returns:
        List of provider info dictionaries
    """
    providers = []
    for provider_type in sorted(PROVIDER_CLASSES.keys()):
        info = get_provider_info(provider_type)
        if info:
            info['type'] = provider_type
            providers.append(info)
    return providers


def create_provider_instance(provider_type: str, credentials: Dict[str, Any]) -> StorageProvider:
    """
    Create a storage provider instance with validated credentials.
    
    Args:
        provider_type: Type identifier
        credentials: Validated credentials dictionary
        
    Returns:
        StorageProvider instance
        
    Raises:
        ProviderConfigError: If credentials invalid or provider type unknown
    """
    # Pre-filter credentials to map provider-specific parameter names
    # This must happen BEFORE validation since validation checks for provider-specific keys
    filtered_creds = _filter_credentials_for_provider(provider_type, credentials)
    
    is_valid, error_msg = validate_provider_credentials(provider_type, filtered_creds)
    if not is_valid:
        raise ProviderConfigError(f"Invalid credentials: {error_msg}")
    
    try:
        provider_class = get_provider_class(provider_type)
        return provider_class(**filtered_creds)
    except Exception as e:
        raise ProviderConfigError(f"Failed to create provider instance: {str(e)}")


def _filter_credentials_for_provider(provider_type: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter credentials to only include parameters supported by the specific provider.
    Also maps common parameter names to provider-specific ones.
    
    Args:
        provider_type: Type identifier
        credentials: Full credentials dictionary
        
    Returns:
        Filtered credentials dictionary with only supported parameters
    """
    # Define supported parameters for each provider type
    # Note: We include both 'bucket' and 'bucket_name' in allowed keys, 
    # then map them appropriately for each provider
    supported_params = {
        'aws_s3': ['access_key', 'secret_key', 'region', 'bucket'],
        'backblaze_b2': ['application_key_id', 'application_key', 'bucket_name', 'bucket'],
        'wasabi': ['access_key', 'secret_key', 'region', 'bucket'],
        'google_cloud': ['project_id', 'credentials_json', 'bucket_name', 'bucket'],
        'digitalocean_spaces': ['access_key', 'secret_key', 'region', 'endpoint', 'bucket'],
        'cloudflare_r2': ['account_id', 'access_key', 'secret_key', 'bucket'],
        'hetzner': ['access_key', 'secret_key', 'region', 'endpoint', 'bucket'],
    }
    
    allowed_keys = supported_params.get(provider_type, [])
    filtered = {k: v for k, v in credentials.items() if k in allowed_keys}
    
    # Map 'bucket' parameter to 'bucket_name' for providers that use bucket_name
    if provider_type in ['google_cloud', 'backblaze_b2']:
        if 'bucket' in filtered and 'bucket_name' not in filtered:
            filtered['bucket_name'] = filtered.pop('bucket')
        # Ensure we don't have 'bucket' key left for these providers
        filtered.pop('bucket', None)
    
    return filtered

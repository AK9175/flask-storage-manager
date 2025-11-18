from abc import ABC, abstractmethod
import boto3
import b2sdk.v2 as b2
import requests
from typing import BinaryIO, List, Tuple, Optional
import os
from google.cloud import storage
from google.oauth2 import service_account
import json
import io
import datetime
import logging

logger = logging.getLogger(__name__)

class StorageProvider(ABC):
    """Abstract base class for storage providers"""
    @abstractmethod
    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        pass

    @abstractmethod
    def download_file(self, filename: str) -> BinaryIO:
        pass

    @abstractmethod
    def delete_file(self, filename: str) -> None:
        pass

    @abstractmethod
    def list_files(self, prefix: str = "") -> List[dict]:
        pass

    @abstractmethod
    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        pass

    @abstractmethod
    def list_buckets(self) -> List[str]:
        pass

    @abstractmethod
    def create_bucket(self, bucket_name: str) -> None:
        """Create a new bucket/container"""
        pass

    def get_bucket_policy(self, bucket_name: str) -> Optional[dict]:
        """Get the IAM policy for a bucket - Optional method
        Returns the policy document or None if not supported
        """
        return None

class AWSS3Provider(StorageProvider):
    """Amazon S3 storage provider
    Authentication:
    - AWS Access Key ID
    - AWS Secret Access Key
    - Region (optional, defaults to us-east-1)
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1', bucket: str = None):
        self.region = region or 'us-east-1'
        self.client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=self.region
        )
        self.bucket = bucket

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        self.client.upload_fileobj(file_obj, self.bucket, filename)

    def download_file(self, filename: str) -> BinaryIO:
        response = self.client.get_object(Bucket=self.bucket, Key=filename)
        return response['Body']

    def delete_file(self, filename: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=filename)

    def list_files(self, prefix: str = "") -> List[dict]:
        response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return [{'name': obj['Key'], 'size': obj['Size']} for obj in response.get('Contents', [])]

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        return self.client.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': filename},
            ExpiresIn=expires_in
        )

    def list_buckets(self) -> List[str]:
        """List all available S3 buckets"""
        response = self.client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new S3 bucket"""
        try:
            # For regions other than us-east-1, we need to specify the LocationConstraint
            if self.region == 'us-east-1':
                self.client.create_bucket(Bucket=bucket_name)
                logger.info(f"✓ S3 bucket '{bucket_name}' created in us-east-1")
            else:
                self.client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )
                logger.info(f"✓ S3 bucket '{bucket_name}' created in region {self.region}")
        except Exception as e:
            logger.error(f"Failed to create S3 bucket '{bucket_name}': {str(e)}")
            raise

    def get_bucket_policy(self, bucket_name: str) -> Optional[dict]:
        """Get the IAM bucket policy from AWS S3"""
        try:
            response = self.client.get_bucket_policy(Bucket=bucket_name)
            if response and 'Policy' in response:
                return json.loads(response['Policy'])
            return None
        except self.client.exceptions.NoSuchBucket:
            logger.warning(f"Bucket '{bucket_name}' does not exist")
            return None
        except Exception as e:
            logger.error(f"Failed to get bucket policy for '{bucket_name}': {str(e)}")
            return None

class BackblazeB2Provider(StorageProvider):
    """Backblaze B2 storage provider
    Authentication:
    - Application Key ID (different from AWS)
    - Application Key
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, application_key_id: str, application_key: str, bucket_name: str = None):
        self.info = b2.InMemoryAccountInfo()
        self.b2_api = b2.B2Api(self.info)
        self.b2_api.authorize_account("production", application_key_id, application_key)
        self.bucket = None  # Will be set per-user
        self.bucket_name = bucket_name

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        self.bucket.upload_stream(file_obj, filename)

    def download_file(self, filename: str) -> BinaryIO:
        download_dest = b2.DownloadDestBytes()
        self.bucket.download_file_by_name(filename, download_dest)
        return io.BytesIO(download_dest.get_bytes_written())

    def delete_file(self, filename: str) -> None:
        file_version = self.bucket.get_file_info_by_name(filename)
        self.bucket.delete_file_version(file_version.id_, filename)

    def list_files(self, prefix: str = "") -> List[dict]:
        return [{'name': f.file_name, 'size': f.size} 
                for f in self.bucket.list_file_names(prefix)]

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        return self.bucket.get_download_authorization(
            filename,
            valid_duration_in_seconds=expires_in
        )

    def list_buckets(self) -> List[str]:
        """List all available B2 buckets"""
        buckets = self.b2_api.list_buckets()
        return [bucket.name for bucket in buckets]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new B2 bucket"""
        try:
            self.b2_api.create_bucket(bucket_name, 'allPrivate')
            logger.info(f"✓ B2 bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create B2 bucket: {str(e)}")
            raise

class WasabiProvider(StorageProvider):
    """Wasabi storage provider (S3 compatible)
    Authentication:
    - Access Key
    - Secret Key
    - Region (optional, defaults to us-east-1; Wasabi specific regions)
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1', bucket: str = None):
        self.region = region or 'us-east-1'
        self.client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=self.region,
            endpoint_url=f'https://s3.{self.region}.wasabisys.com'
        )
        self.bucket = bucket

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        self.client.upload_fileobj(file_obj, self.bucket, filename)

    def download_file(self, filename: str) -> BinaryIO:
        response = self.client.get_object(Bucket=self.bucket, Key=filename)
        return response['Body']

    def delete_file(self, filename: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=filename)

    def list_files(self, prefix: str = "") -> List[dict]:
        response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return [{'name': obj['Key'], 'size': obj['Size']} for obj in response.get('Contents', [])]

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        return self.client.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': filename},
            ExpiresIn=expires_in
        )

    def list_buckets(self) -> List[str]:
        """List all available Wasabi buckets"""
        response = self.client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new Wasabi bucket"""
        try:
            self.client.create_bucket(Bucket=bucket_name)
            logger.info(f"✓ Wasabi bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create Wasabi bucket: {str(e)}")
            raise

class GoogleCloudStorageProvider(StorageProvider):
    """Google Cloud Storage provider
    Authentication:
    - Project ID
    - Service Account JSON (contains all auth info)
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, project_id: str, credentials_json: str, bucket_name: str = None):
        try:
            # Parse the credentials JSON string into a dictionary
            if isinstance(credentials_json, str):
                try:
                    credentials_dict = json.loads(credentials_json)
                    print(f"Successfully parsed credentials JSON for project: {credentials_dict.get('project_id')}")
                except json.JSONDecodeError as e:
                    print(f"JSON parsing error: {str(e)}")
                    raise ValueError(f"Invalid service account JSON format: {str(e)}")
            else:
                credentials_dict = credentials_json

            try:
                credentials = service_account.Credentials.from_service_account_info(credentials_dict)
                print(f"Successfully created credentials for service account: {credentials_dict.get('client_email')}")
            except Exception as e:
                print(f"Error creating credentials: {str(e)}")
                raise ValueError(f"Error creating service account credentials: {str(e)}")

            try:
                self.client = storage.Client(project=project_id, credentials=credentials)
                print(f"Successfully created storage client for project: {project_id}")
            except Exception as e:
                print(f"Error creating storage client: {str(e)}")
                raise ValueError(f"Error creating storage client: {str(e)}")

            self.bucket = None  # Will be set per-user
            self.bucket_name = bucket_name
            
            # Set bucket if bucket_name provided
            if bucket_name:
                self.bucket = self.client.bucket(bucket_name)
            
            print(f"Successfully initialized GCS provider")

        except Exception as e:
            print(f"Unexpected error in GCS initialization: {str(e)}")
            raise ValueError(f"Error initializing Google Cloud Storage: {str(e)}")

    def _ensure_bucket(self) -> None:
        """Ensure bucket is set before operations"""
        if self.bucket is None:
            raise ValueError("Bucket not set. Please set bucket_name before performing operations.")

    def list_files(self, prefix: str = "") -> List[dict]:
        try:
            self._ensure_bucket()
            blobs = self.bucket.list_blobs(prefix=prefix)
            return [{'name': blob.name, 'size': blob.size} for blob in blobs]
        except Exception as e:
            print(f"Error listing files: {str(e)}")
            raise ValueError(f"Error listing files: {str(e)}")

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        try:
            self._ensure_bucket()
            blob = self.bucket.blob(filename)
            blob.upload_from_file(file_obj)
        except Exception as e:
            print(f"Error uploading file: {str(e)}")
            raise ValueError(f"Error uploading file: {str(e)}")

    def download_file(self, filename: str) -> BinaryIO:
        try:
            self._ensure_bucket()
            blob = self.bucket.blob(filename)
            file_obj = io.BytesIO()
            blob.download_to_file(file_obj)
            file_obj.seek(0)
            return file_obj
        except Exception as e:
            print(f"Error downloading file: {str(e)}")
            raise ValueError(f"Error downloading file: {str(e)}")

    def delete_file(self, filename: str) -> None:
        try:
            self._ensure_bucket()
            blob = self.bucket.blob(filename)
            blob.delete()
        except Exception as e:
            print(f"Error deleting file: {str(e)}")
            raise ValueError(f"Error deleting file: {str(e)}")

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        try:
            self._ensure_bucket()
            blob = self.bucket.blob(filename)
            return blob.generate_signed_url(expiration=datetime.timedelta(seconds=expires_in))
        except Exception as e:
            print(f"Error generating signed URL: {str(e)}")
            raise ValueError(f"Error generating signed URL: {str(e)}")

    def list_buckets(self) -> List[str]:
        """List all available GCS buckets for the project"""
        all_buckets = self.client.list_buckets()
        return [bucket.name for bucket in all_buckets]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new GCS bucket"""
        try:
            self.client.create_bucket(bucket_name)
            logger.info(f"✓ GCS bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create GCS bucket: {str(e)}")
            raise

    def get_bucket_policy(self, bucket_name: str) -> Optional[dict]:
        """Get the IAM policy for a GCS bucket"""
        try:
            bucket = self.client.bucket(bucket_name)
            policy = bucket.get_iam_policy(requested_policy_version=3)
            # Convert policy object to dict
            return {
                'bindings': [
                    {
                        'role': binding.role,
                        'members': list(binding.members)
                    }
                    for binding in policy.bindings
                ]
            }
        except Exception as e:
            logger.warning(f"Failed to get GCS bucket policy for '{bucket_name}': {str(e)}")
            return None

class DigitalOceanSpacesProvider(StorageProvider):
    """DigitalOcean Spaces provider (S3 compatible)
    Authentication:
    - Spaces Access Key
    - Spaces Secret Key
    - Region (optional, defaults to nyc3; DO specific: nyc3, ams3, sgp1, etc.)
    - Endpoint URL
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, access_key: str, secret_key: str, region: str = 'nyc3', endpoint: str = None, bucket: str = None):
        try:
            self.region = region or 'nyc3'
            logger.debug(f"Initializing DigitalOcean Spaces provider with region: {self.region}")
            self.client = boto3.client(
                's3',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                endpoint_url=f'https://{endpoint}' if endpoint else f'https://{self.region}.digitaloceanspaces.com',
                region_name=self.region,
                config=boto3.session.Config(
                    signature_version='s3v4',
                    s3={'addressing_style': 'virtual'}
                )
            )
            self.bucket = bucket
            logger.debug("Successfully initialized DigitalOcean Spaces client")
        except Exception as e:
            logger.error(f"Error initializing DigitalOcean Spaces client: {str(e)}")
            raise ValueError(f"Failed to initialize DigitalOcean Spaces client: {str(e)}")

    def list_files(self, prefix: str = "") -> List[dict]:
        try:
            logger.debug(f"Listing files in bucket {self.bucket} with prefix: {prefix}")
            response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
            files = [{'name': obj['Key'], 'size': obj['Size']} for obj in response.get('Contents', [])]
            logger.debug(f"Successfully listed {len(files)} files")
            return files
        except Exception as e:
            logger.error(f"Error listing files in bucket {self.bucket}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to list files: {str(e)}")

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        try:
            logger.debug(f"Uploading file {filename} to bucket {self.bucket}")
            self.client.upload_fileobj(file_obj, self.bucket, filename)
            logger.debug(f"Successfully uploaded file {filename}")
        except Exception as e:
            logger.error(f"Error uploading file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to upload file: {str(e)}")

    def download_file(self, filename: str) -> BinaryIO:
        try:
            logger.debug(f"Downloading file {filename} from bucket {self.bucket}")
            response = self.client.get_object(Bucket=self.bucket, Key=filename)
            logger.debug(f"Successfully downloaded file {filename}")
            return response['Body']
        except Exception as e:
            logger.error(f"Error downloading file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to download file: {str(e)}")

    def delete_file(self, filename: str) -> None:
        try:
            logger.debug(f"Deleting file {filename} from bucket {self.bucket}")
            self.client.delete_object(Bucket=self.bucket, Key=filename)
            logger.debug(f"Successfully deleted file {filename}")
        except Exception as e:
            logger.error(f"Error deleting file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to delete file: {str(e)}")

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        try:
            logger.debug(f"Generating presigned URL for file {filename} with expiration {expires_in} seconds")
            url = self.client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket,
                    'Key': filename
                },
                ExpiresIn=expires_in
            )
            logger.debug(f"Successfully generated presigned URL for file {filename}")
            return url
        except Exception as e:
            logger.error(f"Error generating presigned URL for file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to generate presigned URL: {str(e)}")

    def list_buckets(self) -> List[str]:
        """List all available DigitalOcean Spaces buckets"""
        response = self.client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new DigitalOcean Spaces bucket"""
        try:
            self.client.create_bucket(Bucket=bucket_name)
            logger.info(f"✓ DigitalOcean Spaces bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create DigitalOcean Spaces bucket: {str(e)}")
            raise

class CloudflareR2Provider(StorageProvider):
    """Cloudflare R2 provider (S3 compatible)
    Authentication:
    - Account ID (Cloudflare specific)
    - Access Key ID
    - Secret Access Key
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, account_id: str, access_key: str, secret_key: str, bucket: str = None):
        self.client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            endpoint_url=f'https://{account_id}.r2.cloudflarestorage.com',
            region_name='auto'
        )
        self.bucket = bucket

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        self.client.upload_fileobj(file_obj, self.bucket, filename)

    def download_file(self, filename: str) -> BinaryIO:
        response = self.client.get_object(Bucket=self.bucket, Key=filename)
        return response['Body']

    def delete_file(self, filename: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=filename)

    def list_files(self, prefix: str = "") -> List[dict]:
        response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return [{'name': obj['Key'], 'size': obj['Size']} for obj in response.get('Contents', [])]

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        return self.client.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': filename},
            ExpiresIn=expires_in
        )

    def list_buckets(self) -> List[str]:
        """List all available Cloudflare R2 buckets"""
        response = self.client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new Cloudflare R2 bucket"""
        try:
            self.client.create_bucket(Bucket=bucket_name)
            logger.info(f"✓ Cloudflare R2 bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create Cloudflare R2 bucket: {str(e)}")
            raise

class HetznerStorageProvider(StorageProvider):
    """Hetzner Storage Box provider (S3 compatible)
    Authentication:
    - Access Key
    - Secret Key
    - Region (optional, defaults to fsn1; eu-central: fsn1/nbg1, eu-north: hel1, us-east: ash, us-west: hil, ap-southeast: sin)
    - Endpoint URL
    - Bucket Name (optional, can be set per-user)
    """
    def __init__(self, access_key: str, secret_key: str, region: str = 'fsn1', endpoint: str = None, bucket: str = None):
        try:
            self.region = region or 'fsn1'
            logger.debug(f"Initializing Hetzner Storage provider with region: {self.region}")
            self.client = boto3.client(
                's3',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                endpoint_url=f'https://{endpoint}' if endpoint else f'https://{self.region}.storage.hetzner.cloud',
                region_name=self.region,
                config=boto3.session.Config(
                    signature_version='s3v4',
                    s3={'addressing_style': 'path'}
                )
            )
            self.bucket = bucket
            logger.debug("Successfully initialized Hetzner Storage client")
        except Exception as e:
            logger.error(f"Error initializing Hetzner Storage client: {str(e)}")
            raise ValueError(f"Failed to initialize Hetzner Storage client: {str(e)}")

    def upload_file(self, file_obj: BinaryIO, filename: str) -> None:
        try:
            logger.debug(f"Uploading file {filename} to bucket {self.bucket}")
            self.client.upload_fileobj(file_obj, self.bucket, filename)
            logger.debug(f"Successfully uploaded file {filename}")
        except Exception as e:
            logger.error(f"Error uploading file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to upload file: {str(e)}")

    def download_file(self, filename: str) -> BinaryIO:
        try:
            logger.debug(f"Downloading file {filename} from bucket {self.bucket}")
            response = self.client.get_object(Bucket=self.bucket, Key=filename)
            logger.debug(f"Successfully downloaded file {filename}")
            return response['Body']
        except Exception as e:
            logger.error(f"Error downloading file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to download file: {str(e)}")

    def delete_file(self, filename: str) -> None:
        try:
            logger.debug(f"Deleting file {filename} from bucket {self.bucket}")
            self.client.delete_object(Bucket=self.bucket, Key=filename)
            logger.debug(f"Successfully deleted file {filename}")
        except Exception as e:
            logger.error(f"Error deleting file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to delete file: {str(e)}")

    def list_files(self, prefix: str = "") -> List[dict]:
        try:
            logger.debug(f"Listing files in bucket {self.bucket} with prefix: {prefix}")
            response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
            files = [{'name': obj['Key'], 'size': obj['Size']} for obj in response.get('Contents', [])]
            logger.debug(f"Successfully listed {len(files)} files")
            return files
        except Exception as e:
            logger.error(f"Error listing files in bucket {self.bucket}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to list files: {str(e)}")

    def get_file_url(self, filename: str, expires_in: int = 3600) -> str:
        try:
            logger.debug(f"Generating presigned URL for file {filename} with expiration {expires_in} seconds")
            url = self.client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket,
                    'Key': filename
                },
                ExpiresIn=expires_in
            )
            logger.debug(f"Successfully generated presigned URL for file {filename}")
            return url
        except Exception as e:
            logger.error(f"Error generating presigned URL for file {filename}: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to generate presigned URL: {str(e)}")

    def list_buckets(self) -> List[str]:
        """List all available Hetzner Storage buckets"""
        response = self.client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]

    def create_bucket(self, bucket_name: str) -> None:
        """Create a new Hetzner Storage bucket"""
        try:
            self.client.create_bucket(Bucket=bucket_name)
            logger.info(f"✓ Hetzner Storage bucket '{bucket_name}' created successfully")
        except Exception as e:
            logger.error(f"Failed to create Hetzner Storage bucket: {str(e)}")
            raise

def get_storage_provider(provider_type: str, **credentials) -> StorageProvider:
    """Factory function to create storage provider instances
    
    Each provider has different authentication requirements:
    - AWS S3: access_key, secret_key, bucket, region
    - Backblaze B2: application_key_id, application_key, bucket_name
    - Google Cloud: project_id, bucket_name, credentials_json
    - Cloudflare R2: account_id, access_key, secret_key, bucket
    - DigitalOcean: access_key, secret_key, bucket, region
    - Wasabi: access_key, secret_key, bucket, region
    - Hetzner: access_key, secret_key, bucket, region
    """
    providers = {
        'aws': AWSS3Provider,
        'backblaze': BackblazeB2Provider,
        'wasabi': WasabiProvider,
        'gcs': GoogleCloudStorageProvider,
        'digitalocean': DigitalOceanSpacesProvider,
        'cloudflare': CloudflareR2Provider,
        'hetzner': HetznerStorageProvider,
    }
    
    if provider_type not in providers:
        raise ValueError(f"Unsupported storage provider: {provider_type}")
        
    return providers[provider_type](**credentials) 
from config import s3_config
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_credentials(access_key: str, secret_key: str, bucket: str, region: str) -> tuple[bool, str]:
    """Validate AWS credentials and bucket access"""
    try:
        temp_client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        # Test bucket access
        try:
            temp_client.head_bucket(Bucket=bucket)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '403':
                return False, "Access denied. Please check if you have sufficient permissions for this bucket."
            elif error_code == '404':
                return False, f"Bucket '{bucket}' does not exist."
            else:
                return False, f"Error accessing bucket: {str(e)}"
                
        # Test list objects permission
        try:
            temp_client.list_objects_v2(Bucket=bucket, MaxKeys=1)
        except ClientError:
            return False, "The provided credentials don't have permission to list bucket contents."
            
        return True, "Credentials validated successfully"
        
    except NoCredentialsError:
        return False, "Invalid AWS credentials"
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        return False, f"Error validating credentials: {str(e)}"

def get_s3_client():
    """Get an S3 client using the current configuration"""
    from config import s3_config  # Import here to avoid circular import
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=s3_config.aws_access_key_id,
            aws_secret_access_key=s3_config.aws_secret_access_key,
            region_name=s3_config.aws_region
        )
        return s3_client
    except Exception as e:
        logger.error(f"Error creating S3 client: {str(e)}")
        raise Exception(f"Error creating S3 client: {str(e)}")

def upload_file(file_obj, filename: str) -> None:
    """Upload a file to S3"""
    from config import s3_config  # Import here to avoid circular import
    try:
        s3_client = get_s3_client()
        s3_client.upload_fileobj(file_obj, s3_config.s3_bucket, filename)
        logger.info(f"Successfully uploaded file {filename}")
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        raise Exception(f"Error uploading file: {str(e)}")

def download_file(filename: str):
    """Download a file from S3"""
    from config import s3_config  # Import here to avoid circular import
    try:
        s3_client = get_s3_client()
        response = s3_client.get_object(Bucket=s3_config.s3_bucket, Key=filename)
        return response['Body']
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        raise Exception(f"Error downloading file: {str(e)}")

def delete_file(filename: str) -> None:
    """Delete a file from S3"""
    from config import s3_config  # Import here to avoid circular import
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(Bucket=s3_config.s3_bucket, Key=filename)
        logger.info(f"File {filename} deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        raise Exception(f"Error deleting file: {str(e)}")

def is_s3_configured() -> bool:
    """Check if S3 is properly configured"""
    return s3_config.is_configured()

def list_files_and_folders(prefix: str = '', min_file_size: int = 0):
    """List files and folders in the S3 bucket"""
    if not is_s3_configured():
        logger.warning("Attempted to list files but S3 is not configured")
        return [], []
        
    if not s3_config.s3_bucket:
        logger.error("S3 bucket name is empty")
        raise ValueError("S3 bucket name is not configured")
        
    try:
        s3_client = get_s3_client()
        paginator = s3_client.get_paginator('list_objects_v2')
        files = []
        folders = set()
        
        for page in paginator.paginate(Bucket=s3_config.s3_bucket, Prefix=prefix):
            if 'Contents' in page:
                for obj in page['Contents']:
                    if obj['Size'] >= min_file_size:
                        key = obj['Key']
                        if not key.endswith('/'):  # It's a file
                            files.append({
                                'name': key,
                                'size': obj['Size']
                            })
                        else:  # It's a folder
                            folders.add(key)
                            
            # Handle CommonPrefixes (folders)
            if 'CommonPrefixes' in page:
                for prefix_obj in page['CommonPrefixes']:
                    folders.add(prefix_obj['Prefix'])
                    
        logger.info(f"Successfully listed files and folders from the S3 bucket with prefix: {prefix}")
        return files, sorted(list(folders))
    except Exception as e:
        logger.error(f"Error listing files and folders: {str(e)}")
        raise

def get_file_url(filename: str) -> str:
    """Generate a pre-signed URL for file preview"""
    from config import s3_config  # Import here to avoid circular import
    try:
        s3_client = get_s3_client()
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': s3_config.s3_bucket,
                'Key': filename
            },
            ExpiresIn=3600  # URL expires in 1 hour
        )
        logger.info(f"Preview URL generated for file {filename}.")
        return url
    except Exception as e:
        logger.error(f"Error generating preview URL: {str(e)}")
        raise Exception(f"Error generating preview URL: {str(e)}")

def create_folder(folder_name: str) -> None:
    """Create a new folder in S3"""
    from config import s3_config  # Import here to avoid circular import
    if not folder_name.endswith('/'):
        folder_name += '/'
    try:
        s3_client = get_s3_client()
        s3_client.put_object(Bucket=s3_config.s3_bucket, Key=folder_name)
        logger.info(f"Folder {folder_name} created successfully.")
    except Exception as e:
        logger.error(f"Error creating folder: {str(e)}")
        raise Exception(f"Error creating folder: {str(e)}")

def delete_folder(folder_name: str) -> None:
    """Delete a folder and its contents from S3"""
    from config import s3_config  # Import here to avoid circular import
    if not folder_name.endswith('/'):
        folder_name += '/'
    try:
        s3_client = get_s3_client()
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Delete all objects within the folder
        for page in paginator.paginate(Bucket=s3_config.s3_bucket, Prefix=folder_name):
            if 'Contents' in page:
                objects_to_delete = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(
                    Bucket=s3_config.s3_bucket,
                    Delete={'Objects': objects_to_delete}
                )
        
        # Delete the folder itself
        s3_client.delete_object(Bucket=s3_config.s3_bucket, Key=folder_name)
        logger.info(f"Folder {folder_name} deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting folder: {str(e)}")
        raise Exception(f"Error deleting folder: {str(e)}")

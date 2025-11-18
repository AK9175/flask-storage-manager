import os
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class S3Config:
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    s3_bucket: str = ""
    aws_region: str = "us-east-1"
    
    def is_configured(self) -> bool:
        """Check if all required S3 settings are configured"""
        return bool(
            self.aws_access_key_id and 
            self.aws_secret_access_key and 
            self.s3_bucket
        )
    
    def save_to_file(self, filename: str = "s3_config.json") -> None:
        """Save configuration to a file"""
        try:
            with open(filename, 'w') as f:
                json.dump({
                    'aws_access_key_id': self.aws_access_key_id,
                    'aws_secret_access_key': self.aws_secret_access_key,
                    's3_bucket': self.s3_bucket,
                    'aws_region': self.aws_region
                }, f)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            raise
    
    def load_from_file(self, filename: str = "s3_config.json") -> None:
        """Load configuration from a file"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    config = json.load(f)
                self.aws_access_key_id = config.get('aws_access_key_id', '')
                self.aws_secret_access_key = config.get('aws_secret_access_key', '')
                self.s3_bucket = config.get('s3_bucket', '')
                self.aws_region = config.get('aws_region', 'us-east-1')
                logger.info("Configuration loaded successfully")
            else:
                logger.warning("No configuration file found")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            # Don't raise the error, just keep default values
            
    def update(self, access_key: str, secret_key: str, bucket: str, region: str = "us-east-1") -> None:
        """Update configuration with new values"""
        self.aws_access_key_id = access_key
        self.aws_secret_access_key = secret_key
        self.s3_bucket = bucket
        self.aws_region = region
        self.save_to_file()  # Save changes to file

# Create a global instance
s3_config = S3Config()

# Try to load existing configuration
try:
    s3_config.load_from_file()
except Exception as e:
    logger.error(f"Error loading S3 configuration: {str(e)}")

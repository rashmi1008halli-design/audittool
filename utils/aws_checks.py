# utils/aws_checks.py

import boto3

def check_public_s3():
    """Check for public S3 buckets."""
    s3 = boto3.client('s3')
    public_buckets = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    public_buckets.append(name)
    except Exception as e:
        print(f"S3 check error: {e}")
    return public_buckets

def check_root_mfa():
    """Check if root account has MFA enabled."""
    iam = boto3.client('iam')
    try:
        mfa_devices = iam.list_mfa_devices(UserName='root')['MFADevices']
        if len(mfa_devices) == 0:
            return False
        return True
    except Exception as e:
        print(f"IAM check error: {e}")
        return False

def check_open_security_groups():
    """Check for open security group ports (0.0.0.0/0)."""
    ec2 = boto3.client('ec2')
    open_sgs = []
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_sgs.append(sg['GroupName'])
    except Exception as e:
        print(f"EC2 SG check error: {e}")
    return open_sgs

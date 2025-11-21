# utils/checks.py
"""
Simulated AWS security checks. Each check returns structured findings.
This is safe (no AWS required). To connect real AWS, replace internals
with boto3 calls and keep the same return format.
"""

import random
import time

def _sleep_short():
    time.sleep(0.6)  # small pause so UI shows progress

def run_all_checks(progress_emit=None):
    def emit(msg):
        if progress_emit:
            try:
                progress_emit(msg)
            except Exception:
                pass

    results = {}
    emit("Listing S3 buckets...")
    _sleep_short()
    # S3 checks
    s3_buckets_total = random.randint(0, 6)
    public_buckets = []
    unencrypted = []
    for i in range(s3_buckets_total):
        name = f"bucket-{i+1}"
        if random.random() < 0.15:
            public_buckets.append(name)
        if random.random() < 0.2:
            unencrypted.append(name)
    results["s3"] = {
        "buckets_count": s3_buckets_total,
        "public_buckets": public_buckets,
        "unencrypted_buckets": unencrypted,
    }
    emit(f"S3: {s3_buckets_total} buckets checked — {len(public_buckets)} public, {len(unencrypted)} unencrypted")
    _sleep_short()

    # IAM checks
    emit("Scanning IAM users and MFA status...")
    _sleep_short()
    total_users = random.randint(1, 8)
    users_no_mfa = []
    users_with_old_keys = []
    for i in range(total_users):
        uname = f"user{i+1}"
        if random.random() < 0.4:
            users_no_mfa.append(uname)
        if random.random() < 0.25:
            users_with_old_keys.append({"user": uname, "age_days": random.randint(100, 800)})
    results["iam"] = {
        "total_users": total_users,
        "users_no_mfa": users_no_mfa,
        "users_old_keys": users_with_old_keys,
        "root_mfa": random.choice([True, False, True]),  # biased towards True
    }
    emit(f"IAM: {total_users} users, {len(users_no_mfa)} without MFA")
    _sleep_short()

    # Security groups checks
    emit("Scanning Security Groups for open ports...")
    _sleep_short()
    sg_list = []
    total_sg = random.randint(1, 8)
    for i in range(total_sg):
        if random.random() < 0.3:
            sg_list.append({"GroupId": f"sg-{1000+i}", "ports": ["22"], "open_to_world": True})
        elif random.random() < 0.2:
            sg_list.append({"GroupId": f"sg-{1000+i}", "ports": ["80","443"], "open_to_world": True})
        else:
            sg_list.append({"GroupId": f"sg-{1000+i}", "ports": [], "open_to_world": False})
    open_sgs = [s for s in sg_list if s["open_to_world"]]
    results["security_groups"] = {"total": total_sg, "open_sgs": open_sgs}
    emit(f"Security Groups: {len(open_sgs)} open to world")
    _sleep_short()

    # RDS & EBS (storage)
    emit("Checking storage encryption (RDS/EBS)...")
    _sleep_short()
    rds_unencrypted = []
    ebs_unencrypted = []
    for i in range(random.randint(0, 3)):
        if random.random() < 0.25:
            rds_unencrypted.append(f"rds-{i+1}")
    for i in range(random.randint(0, 6)):
        if random.random() < 0.2:
            ebs_unencrypted.append(f"vol-{i+1}")
    results["storage"] = {"rds_unencrypted": rds_unencrypted, "ebs_unencrypted": ebs_unencrypted}
    emit(f"Storage: {len(rds_unencrypted)} RDS unencrypted, {len(ebs_unencrypted)} EBS unencrypted")
    _sleep_short()

    # CloudTrail
    emit("Checking CloudTrail status...")
    _sleep_short()
    results["cloudtrail"] = {"enabled": random.choice([True, False, True])}
    emit(f"CloudTrail enabled: {results['cloudtrail']['enabled']}")
    _sleep_short()

    # S3 Block Public Access
    emit("Evaluating S3 Block Public Access settings...")
    _sleep_short()
    s3_bpa_issues = []
    for b in (results["s3"]["public_buckets"] or []):
        if random.random() < 0.6:
            s3_bpa_issues.append(b)
    results["s3"]["bpa_issues"] = s3_bpa_issues
    emit(f"S3 BPA issues: {len(s3_bpa_issues)}")
    _sleep_short()

    # ECR, Config, CloudWatch simple checks (simulated)
    emit("Checking ECR, AWS Config, CloudWatch alarms...")
    _sleep_short()
    results["ecr"] = {"public_repos": random.randint(0,1)}
    results["aws_config"] = {"recorders": random.randint(0,1)}
    results["cloudwatch"] = {"alarms": random.randint(0,3)}
    emit("Auxiliary checks complete.")
    _sleep_short()

    # Return all collected simulated results
    emit("All checks completed.")
    return results

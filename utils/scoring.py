# utils/scoring.py
def calculate_score_and_details(results):
    """
    Returns (score:int, details:dict)
    details contains deductions and severity mapping.
    """
    base = 100
    deductions = []
    details = {}

    # S3 public buckets (high)
    pub = results.get("s3", {}).get("public_buckets", [])
    if pub:
        d = min(40, 15 * len(pub))
        deductions.append(("Public S3 buckets", d))
        details["public_s3"] = {"count": len(pub), "items": pub, "severity": "high"}
    else:
        details["public_s3"] = {"count": 0, "items": [], "severity": "ok"}

    # Unencrypted S3
    unenc = results.get("s3", {}).get("unencrypted_buckets", [])
    if unenc:
        d = min(20, 7 * len(unenc))
        deductions.append(("Unencrypted S3", d))
        details["unencrypted_s3"] = {"count": len(unenc), "items": unenc, "severity": "medium"}

    # S3 BPA issues
    bpa = results.get("s3", {}).get("bpa_issues", [])
    if bpa:
        d = min(20, 5 * len(bpa))
        deductions.append(("S3 Block Public Access issues", d))
        details["s3_bpa"] = {"items": bpa, "severity": "medium"}

    # IAM root MFA
    iam = results.get("iam", {})
    if not iam.get("root_mfa", False):
        deductions.append(("Root MFA disabled", 25))
        details["root_mfa"] = {"ok": False, "severity": "high"}
    else:
        details["root_mfa"] = {"ok": True, "severity": "ok"}

    # Users without MFA
    users_no_mfa = iam.get("users_no_mfa", [])
    if users_no_mfa:
        d = min(25, 5 * len(users_no_mfa))
        deductions.append(("Users without MFA", d))
        details["users_no_mfa"] = {"items": users_no_mfa, "severity": "high"}

    # Old access keys
    old_keys = iam.get("users_old_keys", [])
    if old_keys:
        d = min(20, 5 * len(old_keys))
        deductions.append(("Old access keys", d))
        details["users_old_keys"] = {"items": old_keys, "severity": "medium"}

    # Open security groups
    open_sgs = results.get("security_groups", {}).get("open_sgs", [])
    if open_sgs:
        d = min(30, 10 * len(open_sgs))
        deductions.append(("Open security groups", d))
        details["open_sgs"] = {"items": open_sgs, "severity": "high"}

    # Storage encryption
    storage = results.get("storage", {})
    if storage.get("rds_unencrypted"):
        d = min(20, 10 * len(storage.get("rds_unencrypted")))
        deductions.append(("Unencrypted RDS", d))
        details["rds_unencrypted"] = {"items": storage.get("rds_unencrypted"), "severity": "high"}
    if storage.get("ebs_unencrypted"):
        d = min(15, 5 * len(storage.get("ebs_unencrypted")))
        deductions.append(("Unencrypted EBS", d))
        details["ebs_unencrypted"] = {"items": storage.get("ebs_unencrypted"), "severity": "medium"}

    # CloudTrail check
    ct = results.get("cloudtrail", {})
    if not ct.get("enabled", False):
        deductions.append(("CloudTrail not enabled", 20))
        details["cloudtrail"] = {"enabled": False, "severity": "high"}
    else:
        details["cloudtrail"] = {"enabled": True, "severity": "ok"}

    # Summarize
    total_deduction = sum(v for _, v in deductions)
    score = max(0, base - total_deduction)
    details["deductions"] = deductions
    details["score"] = score
    return score, details

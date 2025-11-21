# utils/report_generator.py
import csv
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_csv(results, score, details):
    fname = f"scan_report_{int(datetime.utcnow().timestamp())}.csv"
    with open(fname, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Cloud Security Audit Report"])
        writer.writerow(["Generated At", datetime.utcnow().isoformat() + "Z"])
        writer.writerow([])
        writer.writerow(["Security Score", score])
        writer.writerow([])
        # S3
        s3 = results.get("s3", {})
        writer.writerow(["S3 buckets count", s3.get("buckets_count", 0)])
        writer.writerow(["Public S3 buckets", ";".join(s3.get("public_buckets", [])) or "None"])
        writer.writerow(["Unencrypted S3 buckets", ";".join(s3.get("unencrypted_buckets", [])) or "None"])
        writer.writerow([])
        # IAM
        iam = results.get("iam", {})
        writer.writerow(["Root MFA Enabled", iam.get("root_mfa")])
        writer.writerow(["Users without MFA", ";".join(iam.get("users_no_mfa", [])) or "None"])
        writer.writerow(["Users with old keys", str(iam.get("users_old_keys", [])) or "None"])
    return fname

def generate_pdf(results, score, details):
    fname = f"scan_report_{int(datetime.utcnow().timestamp())}.pdf"
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "Cloud Security Audit Report")
    c.setFont("Helvetica", 10)
    c.drawString(50, 730, f"Security Score: {score}/100")
    c.drawString(50, 715, f"Generated At: {datetime.utcnow().isoformat()}Z")
    y = 690
    s3 = results.get("s3", {})
    c.drawString(50, y, f"S3 - Public buckets: {', '.join(s3.get('public_buckets', [])) or 'None'}")
    y -= 15
    c.drawString(50, y, f"S3 - Unencrypted buckets: {', '.join(s3.get('unencrypted_buckets', [])) or 'None'}")
    y -= 20
    iam = results.get("iam", {})
    c.drawString(50, y, f"Root MFA Enabled: {iam.get('root_mfa')}")
    y -= 15
    c.drawString(50, y, f"Users without MFA: {', '.join(iam.get('users_no_mfa', [])) or 'None'}")
    y -= 20
    sgs = results.get("security_groups", {}).get("open_sgs", [])
    c.drawString(50, y, f"Open Security Groups: {', '.join([s['GroupId'] for s in sgs]) or 'None'}")
    c.save()
    buffer.seek(0)
    with open(fname, "wb") as f:
        f.write(buffer.read())
    return fname

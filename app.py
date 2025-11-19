from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO, emit
import boto3
import pandas as pd
from reportlab.pdfgen import canvas
from io import BytesIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------- Helper Functions ---------- #

def check_public_s3_buckets():
    s3 = boto3.client("s3")
    public_buckets = []
    buckets = s3.list_buckets()

    for bucket in buckets.get("Buckets", []):
        try:
            acl = s3.get_bucket_acl(Bucket=bucket["Name"])
            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    public_buckets.append(bucket["Name"])
        except:
            continue

    return public_buckets


def check_root_mfa_enabled():
    iam = boto3.client("iam")
    try:
        response = iam.get_account_summary()
        return response["SummaryMap"]["AccountMFAEnabled"] == 1
    except:
        return False


def check_open_security_groups():
    ec2 = boto3.client("ec2")
    open_groups = []

    sg_list = ec2.describe_security_groups()["SecurityGroups"]

    for sg in sg_list:
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_groups.append(sg["GroupId"])

    return list(set(open_groups))


# ---------- Routes ---------- #

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def scan():
    # Send starting status
    socketio.emit("scan_update", {"message": "Scanning S3 buckets..."})
    public_buckets = check_public_s3_buckets()

    socketio.emit("scan_update", {"message": "Checking root MFA..."})
    mfa_enabled = check_root_mfa_enabled()

    socketio.emit("scan_update", {"message": "Checking security groups..."})
    open_sg = check_open_security_groups()

    score = 100
    if public_buckets:
        score -= 30
    if not mfa_enabled:
        score -= 20
    if open_sg:
        score -= 20

    results = {
        "security_score": score,
        "public_buckets": public_buckets,
        "mfa_enabled": mfa_enabled,
        "open_security_groups": open_sg,
    }

    return jsonify(results)

@app.route("/download_csv")
def download_csv():
    data = {
        "Metric": ["Public S3 Buckets", "Root MFA Enabled", "Open Security Groups"],
        "Value": ["None", "False", "None"]
    }
    df = pd.DataFrame(data)
    file = BytesIO()
    df.to_csv(file, index=False)
    file.seek(0)
    return send_file(file, mimetype="text/csv", download_name="audit_report.csv")

@app.route("/download_pdf")
def download_pdf():
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.drawString(100, 800, "Cloud Security Audit Report")
    p.drawString(100, 780, "Generated Report")
    p.drawString(100, 760, "Security Score: 70/100")
    p.drawString(100, 740, "Public S3 Buckets: None")
    p.drawString(100, 720, "Root MFA Enabled: False")
    p.drawString(100, 700, "Open Security Groups: None")
    p.save()
    buffer.seek(0)
    return send_file(buffer, download_name="audit_report.pdf", mimetype="application/pdf")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)

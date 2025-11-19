# utils/report_generator.py

import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def generate_csv(results, score, filename="scan_report.csv"):
    """Generate a CSV report."""
    data = {
        "Category": ["Public S3 Buckets", "Root MFA Enabled", "Open Security Groups", "Security Score"],
        "Details": [
            ", ".join(results.get("public_buckets", [])) or "None",
            "Yes" if results.get("root_mfa") else "No",
            ", ".join(results.get("open_sgs", [])) or "None",
            score
        ]
    }
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    return filename

def generate_pdf(results, score, filename="scan_report.pdf"):
    """Generate a PDF report."""
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(50, 750, "Cloud Security Audit Report")
    y = 700

    c.drawString(50, y, f"Security Score: {score}/100")
    y -= 40

    c.drawString(50, y, "Public S3 Buckets:")
    y -= 20
    public_buckets = results.get("public_buckets", [])
    if public_buckets:
        for b in public_buckets:
            c.drawString(70, y, f"- {b}")
            y -= 20
    else:
        c.drawString(70, y, "None")
        y -= 20

    c.drawString(50, y, f"Root MFA Enabled: {'Yes' if results.get('root_mfa') else 'No'}")
    y -= 40

    c.drawString(50, y, "Open Security Groups (0.0.0.0/0):")
    y -= 20
    open_sgs = results.get("open_sgs", [])
    if open_sgs:
        for sg in open_sgs:
            c.drawString(70, y, f"- {sg}")
            y -= 20
    else:
        c.drawString(70, y, "None")

    c.save()
    return filename

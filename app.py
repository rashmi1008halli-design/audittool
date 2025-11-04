from flask import Flask, render_template, send_file
from flask_socketio import SocketIO, emit
from utils.aws_checks import check_public_s3, check_root_mfa, check_open_security_groups
from utils.scoring import calculate_score
from utils.report_generator import generate_csv, generate_pdf
from utils.logger import log_scan
import time

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------
# Frontend Route
# ---------------------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------------------
# Real-time Cloud Scan (SocketIO)
# ---------------------------
@socketio.on('start_scan')
def handle_scan_event():
    """Handles real-time scan progress with SocketIO events."""

    emit('scan_progress', {'message': '☁️ Starting cloud scan...'})
    time.sleep(1)

    # Step 1: Check S3 buckets
    public_buckets = check_public_s3()
    emit('scan_progress', {'message': f'🪣 Checked {len(public_buckets)} S3 buckets.'})
    time.sleep(1)

    # Step 2: Check Root MFA
    root_mfa = check_root_mfa()
    emit('scan_progress', {'message': f'🔐 Root MFA Enabled: {root_mfa}'})
    time.sleep(1)

    # Step 3: Check Security Groups
    open_sgs = check_open_security_groups()
    emit('scan_progress', {'message': f'🧱 Found {len(open_sgs)} open security groups.'})
    time.sleep(1)

    # Step 4: Calculate Score
    results = {
        'public_buckets': public_buckets,
        'root_mfa': root_mfa,
        'open_sgs': open_sgs
    }
    score = calculate_score(results)
    log_scan(results, score)

    emit('scan_progress', {'message': '✅ Scan complete!'})
    emit('scan_complete', {'score': score})


# ---------------------------
# Download Routes
# ---------------------------
@app.route('/download/csv')
def download_csv():
    results = {
        'public_buckets': check_public_s3(),
        'root_mfa': check_root_mfa(),
        'open_sgs': check_open_security_groups()
    }
    score = calculate_score(results)
    filename = generate_csv(results, score)
    return send_file(filename, as_attachment=True)


@app.route('/download/pdf')
def download_pdf():
    results = {
        'public_buckets': check_public_s3(),
        'root_mfa': check_root_mfa(),
        'open_sgs': check_open_security_groups()
    }
    score = calculate_score(results)
    filename = generate_pdf(results, score)
    return send_file(filename, as_attachment=True)


# ---------------------------
# Run the App
# ---------------------------
if __name__ == "__main__":
    socketio.run(app, debug=True, port=5001)

# app.py
from flask import Flask, render_template, send_file
from flask_socketio import SocketIO, emit
from utils.aws_checks import run_all_checks
from utils.scoring import calculate_score_and_details
from utils.report_generator import generate_csv, generate_pdf
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
# use threading for local Windows testing; Render will use eventlet when started with gunicorn -k eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Serve dashboard
@app.route("/")
def index():
    return render_template("index.html")

# SocketIO event to start scan
@socketio.on("start_scan")
def handle_start_scan():
    emit("scan_progress", {"message": "Starting cloud audit..."})
    # run checks and emit progress messages through a callback
    def progress_emit(msg):
        emit("scan_progress", {"message": msg})

    results = run_all_checks(progress_emit=progress_emit)  # simulated checks
    emit("scan_progress", {"message": "Computing score..."})

    score, details = calculate_score_and_details(results)

    emit("scan_complete", {"score": score, "details": details, "results": results})

# Download CSV/PDF endpoints (run quick scan again for fresh report)
@app.route("/download/csv")
def download_csv():
    results = run_all_checks()
    score, details = calculate_score_and_details(results)
    filename = generate_csv(results, score, details)
    return send_file(filename, as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    results = run_all_checks()
    score, details = calculate_score_and_details(results)
    filename = generate_pdf(results, score, details)
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)

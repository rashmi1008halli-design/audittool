from flask import Flask, render_template, send_file, request, redirect, session, url_for
from flask_socketio import SocketIO, emit
from utils.aws_checks import run_all_checks
from utils.scoring import calculate_score_and_details
from utils.report_generator import generate_csv, generate_pdf
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "cloud-security-key-123"  # Required for login session

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Dummy login credentials
USERNAME = "admin"
PASSWORD = "admin123"

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == USERNAME and password == PASSWORD:
            session["user"] = username
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Invalid credentials")
    
    return render_template("login.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# Dashboard (requires login)
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

@socketio.on("start_scan")
def handle_start_scan():
    emit("scan_progress", {"message": "Starting cloud audit..."})

    def progress_emit(msg):
        emit("scan_progress", {"message": msg})

    results = run_all_checks(progress_emit=progress_emit)
    emit("scan_progress", {"message": "Computing score..."})

    score, details = calculate_score_and_details(results)
    emit("scan_complete", {"score": score, "details": details, "results": results})

@app.route("/download/csv")
def download_csv():
    if "user" not in session:
        return redirect(url_for("login"))

    results = run_all_checks()
    score, details = calculate_score_and_details(results)
    filename = generate_csv(results, score, details)
    return send_file(filename, as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    if "user" not in session:
        return redirect(url_for("login"))

    results = run_all_checks()
    score, details = calculate_score_and_details(results)
    filename = generate_pdf(results, score, details)
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)

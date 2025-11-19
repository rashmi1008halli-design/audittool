# utils/logger.py
import os

LOG_FILE = os.path.join("logs", "scan_logs.txt")

def log_scan(results, score):
    """Log scan results and score to a log file."""
    os.makedirs("logs", exist_ok=True)  # Ensure logs folder exists

    with open(LOG_FILE, "a") as f:
        f.write(f"Score: {score}\n")
        for key, value in results.items():
            f.write(f"{key}: {value}\n")
        f.write("-" * 40 + "\n")
    
    print(f"Scan results logged to {LOG_FILE}")

import psutil
import hashlib
import os
import time
import ctypes
import shutil

# === CONFIGURATION ===
MALICIOUS_KEYWORDS = ["keylogger"]  # Add more keywords as needed
KNOWN_BAD_HASHES = ["e99a18c428cb38d5f260853678922e03"]  # SHA256 hashes of known malware
QUARANTINE_FOLDER = "quarantine"
LOG_FILE = "hids_log.txt"

# === SETUP ===
if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# === UTILITY FUNCTIONS ===
def hash_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # Silent fail for inaccessible files

def log_alert(message):
    # Alert in terminal, log file, and popup
    print(f"\033[91m{message}\033[0m")  # Red text
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(message + "\n")
    except:
        pass  # Prevent crash if log file fails

    try:
        ctypes.windll.user32.MessageBoxW(0, message, "Mini HIDS Alert", 1)
    except:
        pass  # Prevent crash if GUI alert fails

# === MAIN MONITOR FUNCTION ===
def scan_processes():
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info.get('name', '')
            cmdline_raw = proc.info.get('cmdline')
            cmd = ' '.join(cmdline_raw) if isinstance(cmdline_raw, list) else ''
            exe_path = proc.info.get('exe', '')

            if not name:
                continue

            # Skip if this is the HIDS script itself
            if "hids" in name.lower():
                continue

            # === 1. Keyword Detection ===
            if any(keyword in cmd.lower() for keyword in MALICIOUS_KEYWORDS):
                alert_msg = (
                    f"[ALERT] Suspicious keyword found!\n"
                    f"Process: {name}\n"
                    f"PID: {proc.pid}\n"
                    f"CMD: {cmd}\n"
                    f"File: {exe_path}"
                )
                log_alert(alert_msg)

                # Quarantine logic
                if exe_path and os.path.exists(exe_path):
                    if "python" not in os.path.basename(exe_path).lower():
                        try:
                            proc.kill()
                            quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                            shutil.move(exe_path, quarantine_path)
                            log_alert(f"[X] Quarantined: {exe_path}")
                        except:
                            pass  # Catch any file access errors

            # === 2. Hash Detection ===
            if exe_path and os.path.exists(exe_path):
                file_hash = hash_file(exe_path)
                if file_hash in KNOWN_BAD_HASHES:
                    alert_msg = (
                        f"[ALERT] Malicious hash match!\n"
                        f"Process: {name}\n"
                        f"PID: {proc.pid}\n"
                        f"Hash: {file_hash}\n"
                        f"File: {exe_path}"
                    )
                    log_alert(alert_msg)

                    try:
                        proc.kill()
                        quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                        shutil.move(exe_path, quarantine_path)
                        log_alert(f"[X] Quarantined by hash: {exe_path}")
                    except:
                        pass

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError):
            continue  # Safe skip if process disappears or cmdline is bad

# === MAIN LOOP ===
if __name__ == "__main__":
    print("== Mini Host-Based IDS Started ==")
    while True:
        scan_processes()
        time.sleep(5)  # Scan every 5 seconds
import os
import hashlib
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# === Config ===
MONITOR_DIR = "protected_files"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(MONITOR_DIR, exist_ok=True)

# === FIM Logic ===
def get_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def load_hashes():
    if not os.path.exists(HASH_DB): return {}
    with open(HASH_DB) as f:
        return dict(line.strip().split(" || ") for line in f)

def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path} || {h}\n")

def log_alert(msg):
    timestamped = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    with open(ALERT_LOG, 'a') as f:
        f.write(timestamped + "\n")
    log_box.insert(tk.END, timestamped + "\n")
    log_box.see(tk.END)

def clear_logs():
    open(ALERT_LOG, 'w').close()
    log_box.delete('1.0', tk.END)
    messagebox.showinfo("Logs Cleared", "All alert logs have been cleared.")

def export_logs():
    if not os.path.exists(ALERT_LOG):
        messagebox.showwarning("No Logs", "No alert logs to export.")
        return

    dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if dest:
        with open(ALERT_LOG, 'r') as f, open(dest, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Timestamped Alert"])
            for line in f:
                writer.writerow([line.strip()])
        messagebox.showinfo("Exported", f"Logs exported to:\n{dest}")

def update_table(file_hashes):
    for row in tree.get_children():
        tree.delete(row)
    for filepath, hash_value in file_hashes.items():
        tree.insert("", "end", values=(filepath, hash_value))

# === New: Safe scanning loop using root.after() ===
def monitor_files():
    if not monitoring:
        return  # Stop if turned off

    try:
        previous_hashes = load_hashes()
        current_hashes = {}

        for rootdir, _, files in os.walk(MONITOR_DIR):
            for file in files:
                path = os.path.join(rootdir, file)
                h = get_hash(path)
                if h:
                    current_hashes[path] = h

        for path in previous_hashes:
            if path not in current_hashes:
                log_alert(f"Deleted: {path}")
            elif current_hashes[path] != previous_hashes[path]:
                log_alert(f"Modified: {path}")

        for path in current_hashes:
            if path not in previous_hashes:
                log_alert(f"New file added: {path}")

        prev_dirs = set(os.path.dirname(p) for p in previous_hashes)
        curr_dirs = set(os.path.dirname(p) for p in current_hashes)
        deleted_dirs = prev_dirs - curr_dirs
        for d in deleted_dirs:
            log_alert(f"Directory deleted: {d}")

        save_hashes(current_hashes)
        update_table(current_hashes)
        scan_time_label.config(text=f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
    except Exception as e:
        log_alert(f"[ERROR] {str(e)}")

    root.after(5000, monitor_files)  # Schedule next run

# === GUI Setup ===
def start_monitor():
    global monitoring
    if not monitoring:
        monitoring = True
        log_alert("=== Monitoring Started ===")
        monitor_files()

def stop_monitor():
    global monitoring
    monitoring = False
    log_alert("=== Monitoring Stopped ===")

root = tk.Tk()
root.title("File Integrity Monitor (FIM) Dashboard")
root.geometry("800x600")

# === Logs ===
log_frame = tk.LabelFrame(root, text="Real-Time Alerts", padx=5, pady=5)
log_frame.pack(fill="both", expand=True, padx=10, pady=5)

log_box = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
log_box.pack(fill="both", expand=True)

# === Buttons and Scan Info ===
control_frame = tk.Frame(root)
control_frame.pack(pady=5)

tk.Button(control_frame, text="Start Monitoring", command=start_monitor, bg="green", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Stop Monitoring", command=stop_monitor, bg="red", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Clear Logs", command=clear_logs).pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Export Logs to CSV", command=export_logs).pack(side=tk.LEFT, padx=5)

scan_time_label = tk.Label(root, text="Last Scan: N/A")
scan_time_label.pack()

# === Table of Monitored Files ===
table_frame = tk.LabelFrame(root, text="Monitored Files & Hashes", padx=5, pady=5)
table_frame.pack(fill="both", expand=True, padx=10, pady=5)

columns = ("File Path", "SHA256 Hash")
tree = ttk.Treeview(table_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="w", stretch=True)
tree.pack(fill="both", expand=True)

# === Monitoring State ===
monitoring = False

root.mainloop()
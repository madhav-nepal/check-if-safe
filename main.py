import os
import hashlib
import requests
import smtplib
import threading
import time
import sqlite3
import datetime
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, render_template_string
from werkzeug.utils import secure_filename
from imbox import Imbox

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
VT_API_KEY = os.environ.get('VT_API_KEY')

# Email Config
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASS = os.environ.get('EMAIL_PASS')
ALLOWED_DOMAINS = os.environ.get('ALLOWED_DOMAINS', '').split(',')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect('scan_stats.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY, date TEXT, sender TEXT, filename TEXT, result TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_scan(sender, filename, result):
    conn = sqlite3.connect('scan_stats.db')
    c = conn.cursor()
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO scans (date, sender, filename, result) VALUES (?, ?, ?, ?)", 
              (date_str, sender, filename, result))
    conn.commit()
    conn.close()

# --- VT LOGIC ---
def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_vt_status(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        total_scans = sum(stats.values())
        if total_scans < 5: 
            return {"status": "queued"}
            
        return {
            "status": "finished",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/file/{file_hash}",
            "id": response.json().get("data", {}).get("id")
        }
    elif response.status_code == 404:
        return {"status": "queued"} 
    else:
        return {"status": "error", "message": f"API Error: {response.status_code}"}

def upload_to_vt(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(filepath, "rb") as file:
        files = {"file": (os.path.basename(filepath), file)}
        requests.post(url, headers=headers, files=files)

# --- EMAIL LISTENER (Background Robot) ---
def send_reply(to_email, subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        # Note: Using port 465 for SSL. If your host uses 587, change here.
        with smtplib.SMTP_SSL(EMAIL_HOST, 465) as smtp:
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.send_message(msg)
        print(f"Reply sent to {to_email}")
    except Exception as e:
        print(f"Email Reply Error: {e}")

def email_listener():
    print("Email Robot: Starting up...")
    while True:
        try:
            if not EMAIL_USER or not EMAIL_PASS: 
                print("Email Robot: Credentials missing, sleeping...")
                time.sleep(60)
                continue
            
            # Connect to Email
            with Imbox(EMAIL_HOST, username=EMAIL_USER, password=EMAIL_PASS, ssl=True, ssl_context=None, starttls=False) as imbox:
                unread_msgs = imbox.messages(unread=True)
                for uid, message in unread_msgs:
                    sender = message.sent_from[0]['email']
                    print(f"Email Robot: Processing email from {sender}")
                    
                    summary = []
                    if not message.attachments:
                        summary.append("No attachments found to scan.")
                    else:
                        for attachment in message.attachments:
                            fname = secure_filename(attachment.get('filename'))
                            fpath = os.path.join(UPLOAD_FOLDER, fname)
                            with open(fpath, "wb") as f: f.write(attachment.get('content').read())
                            
                            fhash = get_file_hash(fpath)
                            res = check_vt_status(fhash)
                            
                            # If new file, upload it
                            if res['status'] == 'queued': 
                                upload_to_vt(fpath)
                                res_text = "Analysis Started (Check back later)"
                            else:
                                res_text = "❌ DANGER" if res.get('malicious', 0) > 0 else "✅ SAFE"
                            
                            summary.append(f"File: {fname}\nResult: {res_text}")
                            log_scan(sender, fname, res_text)
                            if os.path.exists(fpath): os.remove(fpath)
                    
                    send_reply(sender, f"Scan Result: {message.subject}", "\n\n".join(summary))
                    imbox.mark_seen(uid)
                    
        except Exception as e:
            print(f"Email Robot Error: {e}")
        
        time.sleep(10) # Check every 10 seconds

# --- DEBUG SECTION ---
# This forces Python to print to the logs immediately (flush=True)
email_user = os.environ.get('EMAIL_USER')
print(f"--- SYSTEM CHECK: Email User Detected? {'YES' if email_user else 'NO'} ---", flush=True)

if email_user:
    print("--- SYSTEM CHECK: Starting Email Robot Thread... ---", flush=True)
    t = threading.Thread(target=email_listener, daemon=True)
    t.start()
else:
    print("--- SYSTEM CHECK: Email Robot SKIPPED (EMAIL_USER is missing) ---", flush=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

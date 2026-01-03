import os
import hashlib
import requests
import smtplib
import threading
import time
import sqlite3
import datetime
import fcntl
import re
import base64
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

# --- VT LOGIC (FILES) ---
def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_vt_file(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        total = sum(stats.values())
        if total < 5: return {"status": "queued"}
        return {
            "status": "finished",
            "malicious": stats.get("malicious", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }
    elif response.status_code == 404:
        return {"status": "queued"}
    else:
        return {"status": "error"}

def upload_file_vt(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(filepath, "rb") as file:
        files = {"file": (os.path.basename(filepath), file)}
        requests.post(url, headers=headers, files=files)

# --- VT LOGIC (URLS) ---
def scan_url_vt(target_url):
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "finished",
                "malicious": stats.get("malicious", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/url/{url_id}"
            }
        elif response.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url})
            return {"status": "queued", "link": f"https://www.virustotal.com/gui/url/{url_id}"}
        else:
            return {"status": "error", "link": "#"}
    except Exception:
        return {"status": "error", "link": "#"}

# --- EMAIL TEMPLATE ---
def generate_html_email(subject, items):
    rows = ""
    for item in items:
        color = "#28a745" # Green
        status_text = "✅ SAFE"
        
        if item['status'] == 'DANGER':
            color = "#dc3545" # Red
            status_text = "⚠️ DANGER"
        elif item['status'] == 'QUEUED':
            color = "#007bff" # Blue
            status_text = "⏳ ANALYZING (Click to Monitor)"
            
        rows += f"""
        <div style="background-color: #f8f9fa; border-left: 5px solid {color}; padding: 15px; margin-bottom: 10px; border-radius: 4px;">
            <strong style="color: #333;">{item['type']}:</strong> {item['name']}<br>
            <strong style="color: {color}; font-size: 16px;">{status_text}</strong><br>
            <a href="{item['link']}" style="color: #666; font-size: 12px; text-decoration: none;">View Full Report</a>
        </div>
        """

    return f"""
    <html>
        <body style="font-family: 'Segoe UI', sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px;">Scan Results</h2>
                <p style="color: #666;">Here is the security analysis for: <strong>{subject}</strong></p>
                {rows}
                <div style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
                    Powered by VirusTotal | CheckIfSafe
                </div>
            </div>
        </body>
    </html>
    """

# --- EMAIL LISTENER ---
def email_listener():
    lock_file = open("email_bot.lock", "w")
    try:
        fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("--- ROBOT: I am the Master. Starting loop... ---", flush=True)
    except IOError:
        print("--- ROBOT: Slave mode. Sleeping. ---", flush=True)
        return

    while True:
        try:
            if not EMAIL_USER: 
                time.sleep(60)
                continue
            
            with Imbox(EMAIL_HOST, username=EMAIL_USER, password=EMAIL_PASS, ssl=True, ssl_context=None, starttls=False) as imbox:
                unread_msgs = imbox.messages(unread=True)
                for uid, message in unread_msgs:
                    sender = message.sent_from[0]['email']
                    subject = message.subject
                    body_plain = message.body['plain'][0] if message.body['plain'] else ""
                    print(f"Processing email from {sender}", flush=True)
                    
                    scan_items = []

                    # 1. SCAN LINKS
                    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body_plain)
                    unique_urls = list(set(urls)) 

                    for url in unique_urls:
                        res = scan_url_vt(url)
                        status = "QUEUED"
                        if res['status'] == 'finished':
                            status = "DANGER" if res.get('malicious', 0) > 0 else "SAFE"
                        scan_items.append({'name': url, 'type': 'Link', 'status': status, 'link': res['link']})

                    # 2. SCAN ATTACHMENTS (Optimized Wait Loop)
                    if message.attachments:
                        for attachment in message.attachments:
                            fname = secure_filename(attachment.get('filename'))
                            fpath = os.path.join(UPLOAD_FOLDER, fname)
                            with open(fpath, "wb") as f: f.write(attachment.get('content').read())
                            
                            fhash = get_file_hash(fpath)
                            res = check_vt_file(fhash)
                            
                            status = "QUEUED"
                            if res['status'] == 'queued':
                                upload_file_vt(fpath)
                                print(f"File {fname} is new. Waiting for analysis (Max 60s)...", flush=True)
                                
                                # OPTIMIZED LOOP: Check every 10s, Max 6 times (60s total)
                                for _ in range(6): 
                                    time.sleep(10) 
                                    res = check_vt_file(fhash)
                                    if res['status'] == 'finished':
                                        status = "DANGER" if res.get('malicious', 0) > 0 else "SAFE"
                                        break
                            else:
                                status = "DANGER" if res.get('malicious', 0) > 0 else "SAFE"
                            
                            # If still queued after 60s, it stays "QUEUED"
                            scan_items.append({'name': fname, 'type': 'File', 'status': status, 'link': res.get('link', '#')})
                            if os.path.exists(fpath): os.remove(fpath)
                    
                    # 3. SEND HTML REPLY
                    if scan_items:
                        html_body = generate_html_email(subject, scan_items)
                        
                        msg = EmailMessage()
                        msg['Subject'] = f"Scan Result: {subject}"
                        msg['From'] = EMAIL_USER
                        msg['To'] = sender
                        msg.set_content("Please enable HTML to view this report.")
                        msg.add_alternative(html_body, subtype='html')
                        
                        with smtplib.SMTP_SSL(EMAIL_HOST, 465) as smtp:
                            smtp.login(EMAIL_USER, EMAIL_PASS)
                            smtp.send_message(msg)
                        
                        imbox.mark_seen(uid)
                        print(f"Reply sent to {sender}", flush=True)

        except Exception as e:
            print(f"Error: {e}", flush=True)
        
        time.sleep(10)

if os.environ.get('EMAIL_USER'):
    t = threading.Thread(target=email_listener, daemon=True)
    t.start()

# --- WEB ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files: return redirect(request.url)
        file = request.files['file']
        if file.filename == '': return redirect(request.url)
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_hash = get_file_hash(file_path)
        status = check_vt_file(file_hash)
        if status['status'] == 'queued': upload_file_vt(file_path)
        if os.path.exists(file_path): os.remove(file_path)
        return redirect(url_for('scan_status', file_hash=file_hash))
    return render_template('index.html')

@app.route('/scan/<file_hash>')
def scan_status(file_hash):
    result = check_vt_file(file_hash)
    return render_template('result.html', result=result, file_hash=file_hash)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

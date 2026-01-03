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
from urllib.parse import urlparse
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, render_template_string
from werkzeug.utils import secure_filename
from imbox import Imbox

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
DB_FOLDER = 'db'
DB_FILE = os.path.join(DB_FOLDER, 'scan_stats.db')
MAX_FILE_SIZE = 32 * 1024 * 1024 

VT_API_KEY = os.environ.get('VT_API_KEY')
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASS = os.environ.get('EMAIL_PASS')

# SKIPPED DOMAINS
SKIP_DOMAINS = [
    'facebook.com', 'www.facebook.com', 'twitter.com', 'www.twitter.com', 'x.com',
    'instagram.com', 'www.instagram.com', 'linkedin.com', 'www.linkedin.com',
    'youtube.com', 'www.youtube.com', 'google.com', 'www.google.com',
    'apple.com', 'www.apple.com', 'microsoft.com', 'www.microsoft.com'
]

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE 

if not os.path.exists(DB_FOLDER): os.makedirs(DB_FOLDER)
if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)

# --- FORCE NON-WWW REDIRECT ---
@app.before_request
def redirect_www():
    if request.host.startswith('www.'):
        return redirect(request.url.replace('www.', '', 1), code=301)

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY, date TEXT, sender TEXT, filename TEXT, result TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_scan(sender, filename, result):
    conn = sqlite3.connect(DB_FILE)
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

def check_vt_file(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values())
            if total < 5: return {"status": "queued"}
            return {
                "status": "finished",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        elif response.status_code == 404:
            return {"status": "queued"}
    except: pass
    return {"status": "error"}

def upload_file_vt(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(filepath, "rb") as file:
        files = {"file": (os.path.basename(filepath), file)}
        requests.post(url, headers=headers, files=files)

def scan_url_vt(target_url):
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "finished",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/url/{url_id}"
            }
        elif response.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url})
            print(f"URL {target_url} is new. Waiting...", flush=True)
            
            # INCREASED PATIENCE: Check every 5s for 60s (was 30s)
            for _ in range(12): 
                time.sleep(5)
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    if sum(stats.values()) > 0:
                        return {
                            "status": "finished",
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "link": f"https://www.virustotal.com/gui/url/{url_id}"
                        }
            return {"status": "queued", "link": f"https://www.virustotal.com/gui/url/{url_id}"}
    except: pass
    return {"status": "error", "link": "#"}

# --- EMAIL TEMPLATE ---
def generate_html_email(subject, items):
    rows = ""
    for item in items:
        if item['status'] == 'DANGER':
            badge_style = "background-color: #dc3545; color: white; border: 1px solid #dc3545;"
            badge_text = "⚠️ DANGER"
        elif item['status'] == 'QUEUED':
            badge_style = "background-color: #ffc107; color: #212529; border: 1px solid #ffc107;"
            badge_text = "⏳ ANALYZING"
        else:
            badge_style = "background-color: #e6f4ea; color: #1e8e3e; border: 1px solid #1e8e3e;"
            badge_text = "✅ SAFE"
            
        display_name = item['name']
        if len(display_name) > 50: display_name = display_name[:47] + "..."

        rows += f"""
        <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 12px 5px; color: #555;">
                <span style="font-size: 11px; color: #999; text-transform: uppercase; font-weight: bold; display: block;">{item['type']}</span>
                <span style="font-size: 14px; color: #333;">{display_name}</span>
            </td>
            <td style="padding: 12px 5px; text-align: right;">
                <a href="{item['link']}" style="text-decoration: none; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; font-family: sans-serif; {badge_style}">
                    {badge_text}
                </a>
            </td>
        </tr>
        """
    return f"""<html><body style="font-family: 'Segoe UI', sans-serif; background-color: #f8f9fa; padding: 20px;"><div style="max-width: 500px; margin: 0 auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05);"><h3 style="color: #2c3e50; margin-top: 0; padding-bottom: 15px; border-bottom: 2px solid #f1f1f1;">🛡️ Scan Report</h3><p style="font-size: 13px; color: #666; margin-bottom: 20px;">Analysis for: <strong>{subject}</strong></p><table style="width: 100%; border-collapse: collapse;">{rows}</table><div style="margin-top: 25px; font-size: 11px; color: #aaa; text-align: center; border-top: 1px solid #f1f1f1; padding-top: 15px;">Madhav Nepal | CheckIfSafe.com | Powered by VirusTotal</div></div></body></html>"""

# --- BACKUP ROBOT ---
def backup_task():
    BACKUP_DIR = os.path.join(os.getcwd(), 'backups')
    if not os.path.exists(BACKUP_DIR): os.makedirs(BACKUP_DIR)
    while True:
        time.sleep(86400)
        try:
            if not os.path.exists(DB_FILE): continue
            date_str = datetime.datetime.now().strftime('%Y-%m-%d')
            backup_path = os.path.join(BACKUP_DIR, f"backup_{date_str}.db")
            src = sqlite3.connect(DB_FILE)
            dst = sqlite3.connect(backup_path)
            with dst: src.backup(dst)
            dst.close()
            src.close()
            now = time.time()
            cutoff = now - (365 * 86400)
            for filename in os.listdir(BACKUP_DIR):
                if os.path.getmtime(os.path.join(BACKUP_DIR, filename)) < cutoff:
                    os.remove(os.path.join(BACKUP_DIR, filename))
            if EMAIL_USER:
                msg = EmailMessage()
                msg['Subject'] = f"✅ Backup Success: {date_str}"
                msg['From'] = EMAIL_USER
                msg['To'] = EMAIL_USER 
                msg.set_content(f"Database backed up.\nFile: {backup_path}")
                with smtplib.SMTP_SSL(EMAIL_HOST, 465) as smtp:
                    smtp.login(EMAIL_USER, EMAIL_PASS)
                    smtp.send_message(msg)
        except: pass

# --- EMAIL LISTENER ---
def email_listener():
    lock_file = open("email_bot.lock", "w")
    try:
        fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("--- ROBOT: I am the Master. ---", flush=True)
        t_backup = threading.Thread(target=backup_task, daemon=True)
        t_backup.start()
    except IOError: return
    while True:
        try:
            if not EMAIL_USER: 
                time.sleep(30)
                continue
            with Imbox(EMAIL_HOST, username=EMAIL_USER, password=EMAIL_PASS, ssl=True, ssl_context=None, starttls=False) as imbox:
                unread_msgs = imbox.messages(unread=True)
                for uid, message in unread_msgs:
                    sender = message.sent_from[0]['email']
                    subject = message.subject
                    
                    body_plain = message.body['plain'][0] if message.body['plain'] else ""
                    body_html = message.body['html'][0] if message.body['html'] else ""
                    full_body = body_plain + " " + body_html

                    print(f"Processing {sender}...", flush=True)
                    scan_items = []
                    
                    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', full_body)
                    unique_urls = list(set(urls)) 
                    
                    for url in unique_urls:
                        url = url.strip('">')
                        domain = urlparse(url).netloc.lower()
                        if any(skip in domain for skip in SKIP_DOMAINS): continue
                        res = scan_url_vt(url)
                        status = "QUEUED"
                        if res['status'] == 'finished':
                            status = "DANGER" if res.get('malicious', 0) > 0 else "SAFE"
                        scan_items.append({'name': url, 'type': 'Link', 'status': status, 'link': res['link']})
                    
                    if message.attachments:
                        for attachment in message.attachments:
                            fname = secure_filename(attachment.get('filename'))
                            fpath = os.path.join(UPLOAD_FOLDER, fname)
                            with open(fpath, "wb") as f: f.write(attachment.get('content').read())
                            fhash = get_file_hash(fpath)
                            res = check_vt_file(fhash)
                            if res['status'] == 'queued':
                                upload_file_vt(fpath)
                                
                                # INCREASED PATIENCE: Check every 5s for 120s (was 60s)
                                for _ in range(24): 
                                    time.sleep(5) 
                                    res = check_vt_file(fhash)
                                    if res['status'] == 'finished': break
                                    
                            status = "DANGER" if res.get('malicious', 0) > 0 else "SAFE" if res['status'] == 'finished' else "QUEUED"
                            scan_items.append({'name': fname, 'type': 'File', 'status': status, 'link': res.get('link', '#')})
                            if os.path.exists(fpath): os.remove(fpath)
                            log_scan(sender, fname, status)
                    
                    if scan_items:
                        html_body = generate_html_email(subject, scan_items)
                        msg = EmailMessage()
                        msg['Subject'] = f"Scan Result: {subject}"
                        msg['From'] = EMAIL_USER
                        msg['To'] = sender
                        msg.set_content("Please enable HTML.")
                        msg.add_alternative(html_body, subtype='html')
                        with smtplib.SMTP_SSL(EMAIL_HOST, 465) as smtp:
                            smtp.login(EMAIL_USER, EMAIL_PASS)
                            smtp.send_message(msg)
                        imbox.mark_seen(uid)
                        print(f"Reply sent to {sender}", flush=True)
        except Exception as e: print(f"Error: {e}", flush=True)
        time.sleep(5)

if os.environ.get('EMAIL_USER'):
    t = threading.Thread(target=email_listener, daemon=True)
    t.start()

# --- WEB ROUTES (UNCHANGED) ---
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
        log_scan("Web User", filename, "QUEUED")
        if os.path.exists(file_path): os.remove(file_path)
        return redirect(url_for('scan_status', file_hash=file_hash))
    return render_template('index.html')

@app.route('/scan/<file_hash>')
def scan_status(file_hash):
    result = check_vt_file(file_hash)
    return render_template('result.html', result=result, file_hash=file_hash)

@app.route('/stats')
def stats():
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if start_date and end_date:
        query = "SELECT * FROM scans WHERE date >= ? AND date <= ? ORDER BY id DESC"
        c.execute(query, (f"{start_date} 00:00:00", f"{end_date} 23:59:59"))
        title = f"Stats: {start_date} to {end_date}"
    else:
        c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50")
        title = "Recent Scan Stats (Last 50)"
    rows = c.fetchall()
    conn.close()
    table_rows = "".join([f"<tr><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>" for r in rows])
    html = f"""<html><head><title>Scan Reports</title><style>body {{ font-family: 'Segoe UI', sans-serif; padding: 40px; background: #f4f4f4; }}.container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}h1 {{ color: #333; }}table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}th, td {{ padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }}th {{ background-color: #f8f9fa; }}.form-box {{ background: #e9ecef; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}input[type='date'] {{ padding: 8px; border-radius: 4px; border: 1px solid #ccc; }}button {{ padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}</style></head><body><div class="container"><h1>🛡️ {title}</h1><div class="form-box"><form action="/stats" method="get"><label>From:</label><input type="date" name="start" required><label>To:</label><input type="date" name="end" required><button type="submit">Generate Report</button><a href="/stats" style="margin-left: 10px; color: #666; font-size: 14px;">Reset</a></form></div><table border='0'><tr><th>Date</th><th>Sender</th><th>File</th><th>Result</th></tr>{table_rows}</table></div></body></html>"""
    return render_template_string(html)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

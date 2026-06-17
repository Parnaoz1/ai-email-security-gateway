import csv
import imaplib
import os
import re

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from analyzer import analyze_email
from ai_model import predict_email
from database import (
    init_db,
    save_email_log,
    get_email_logs,
    get_email_logs_by_decision,
    update_email_decision,
    get_top_threat_words,
    get_top_domains,
    get_email_by_id,
    add_blocked_domain,
    add_blocked_sender,
    get_blocked_domains,
    get_blocked_senders,
    add_whitelist_domain,
    get_whitelist_domains,
    search_email_logs,
    get_gmail_info_by_email_id,
    update_gmail_location,
    save_action_log,
    get_action_logs,
)

load_dotenv()

app = FastAPI(title="AI Email Security Gateway")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "change-this-secret-key"))

init_db()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
GMAIL_EMAIL = os.getenv("GMAIL_EMAIL", "ai.email.gateway@gmail.com")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")


class EmailRequest(BaseModel):
    content: str


def is_logged_in(request: Request):
    return request.session.get("logged_in") is True


def extract_sender(content):
    match = re.search(r"From:\s*(.+)", content, re.IGNORECASE)
    return match.group(1).strip() if match else "Unknown"


def extract_sender_and_domain(content):
    match = re.search(r"From:\s*([\w\.-]+@[\w\.-]+)", content, re.IGNORECASE)
    if not match:
        return "", ""
    sender = match.group(1).lower()
    return sender, sender.split("@")[-1].lower()


def classify_email(content):
    result = analyze_email(content)
    ai_result = predict_email(content)
    score = result["score"]

    if ai_result["prediction"] == "phishing":
        confidence = ai_result["confidence"]
        if confidence >= 0.95:
            score += 20
        elif confidence >= 0.85:
            score += 12
        elif confidence >= 0.70:
            score += 6
        result["reasons"].append("AI model detected phishing with confidence: " + str(confidence))

    score = max(0, min(score, 100))

    if score >= 90:
        decision = "DELETE"
    elif score >= 65:
        decision = "QUARANTINE"
    elif score >= 30:
        decision = "SPAM"
    else:
        decision = "SAFE"

    return decision, score, result, ai_result


def gmail_connect():
    if not GMAIL_APP_PASSWORD:
        raise ValueError("GMAIL_APP_PASSWORD is missing in .env")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)
    return mail


def ensure_gmail_folder(mail, folder_name):
    try:
        mail.create(folder_name)
    except Exception:
        pass


def find_uid_by_msgid(mail, folder, gmail_msgid):
    try:
        mail.select(f'"{folder}"')
        status, data = mail.uid("search", None, "X-GM-MSGID", gmail_msgid)
        if status == "OK" and data[0]:
            return data[0].split()[0].decode()
    except Exception:
        pass
    return None


def move_gmail_email(email_id, decision):
    gmail_info = get_gmail_info_by_email_id(email_id)
    if not gmail_info:
        print("No Gmail info found for email:", email_id)
        return False

    gmail_uid, gmail_folder, gmail_msgid = gmail_info
    if not gmail_uid or not gmail_folder or not gmail_msgid:
        print("Missing Gmail UID/folder/msgid for email:", email_id)
        return False

    try:
        mail = gmail_connect()
        current_uid = find_uid_by_msgid(mail, gmail_folder, gmail_msgid)

        if not current_uid:
            for folder in ["inbox", "AI-SPAM", "AI-QUARANTINE", "[Gmail]/Trash"]:
                current_uid = find_uid_by_msgid(mail, folder, gmail_msgid)
                if current_uid:
                    gmail_folder = folder
                    break

        if not current_uid:
            print("Could not find Gmail message by msgid:", gmail_msgid)
            mail.logout()
            return False

        mail.select(f'"{gmail_folder}"')

        if decision == "SAFE":
            target_folder = "inbox"
        elif decision == "SPAM":
            target_folder = "AI-SPAM"
            ensure_gmail_folder(mail, '"AI-SPAM"')
        elif decision == "QUARANTINE":
            target_folder = "AI-QUARANTINE"
            ensure_gmail_folder(mail, '"AI-QUARANTINE"')
        elif decision == "DELETE":
            target_folder = "[Gmail]/Trash"
        else:
            mail.logout()
            return False

        status, _ = mail.uid("copy", current_uid, f'"{target_folder}"')
        if status == "OK":
            mail.uid("store", current_uid, "+FLAGS", "\\Deleted")
            mail.expunge()
            new_uid = find_uid_by_msgid(mail, target_folder, gmail_msgid)
            if new_uid:
                update_gmail_location(email_id, new_uid, target_folder)
            mail.logout()
            return True

        mail.logout()
        return False

    except Exception as e:
        print("Gmail action error:", e)
        return False


def page(title, body):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta http-equiv="refresh" content="10">
        <style>
            body {{ font-family: Arial; background:#f4f6f8; padding:30px; }}
            a {{ display:inline-block; background:#222; color:white; padding:10px 14px; border-radius:8px; text-decoration:none; margin:4px; }}
            .nav {{ margin-bottom:25px; display:flex; flex-wrap:wrap; gap:8px; }}
            .search-form {{ margin-bottom:20px; display:flex; gap:8px; flex-wrap:wrap; }}
            .search-form input {{ padding:10px; width:300px; border-radius:8px; border:1px solid #ccc; }}
            .search-form button {{ padding:10px 14px; border:none; background:#222; color:white; border-radius:8px; cursor:pointer; }}
            .stats, .intel {{ display:flex; gap:20px; flex-wrap:wrap; margin-bottom:30px; }}
            .stat, .card, .intel-card, .box {{ background:white; padding:20px; border-radius:12px; box-shadow:0 2px 10px #ccc; margin-bottom:20px; }}
            .stat {{ min-width:150px; }}
            .stat a {{ color:inherit; background:transparent; padding:0; margin:0; }}
            .stat p {{ font-size:28px; font-weight:bold; }}
            .critical {{ border-left:8px solid red; }}
            .SAFE {{ color:green; font-weight:bold; }}
            .SPAM {{ color:goldenrod; font-weight:bold; }}
            .QUARANTINE {{ color:orange; font-weight:bold; }}
            .DELETE {{ color:red; font-weight:bold; }}
            .actions {{ display:flex; flex-wrap:wrap; gap:8px; margin:15px 0; }}
            .actions a {{ margin:0; }}
            .btn-safe {{ background:green; }}
            .btn-spam {{ background:goldenrod; }}
            .btn-quarantine {{ background:orange; }}
            .btn-delete {{ background:red; }}
            pre {{ background:#eee; padding:10px; border-radius:6px; white-space:pre-wrap; }}
            table {{ background:white; border-collapse:collapse; width:100%; }}
            th, td {{ border:1px solid #ddd; padding:10px; text-align:left; }}
            th {{ background:#222; color:white; }}
            .alert-box {{ background:#ffe5e5; border:2px solid red; padding:18px; border-radius:12px; margin-bottom:25px; color:#8b0000; font-weight:bold; }}
        </style>
    </head>
    <body>{body}</body>
    </html>
    """


def nav(current_path):
    def active(path):
        return 'style="background:#d9d9d9;color:#111;"' if current_path == path else ""
    return f"""
    <div class="nav">
        <a {active('/dashboard')} href="/dashboard">All Emails</a>
        <a {active('/alerts')} href="/alerts">Critical Alerts</a>
        <a {active('/blacklist')} href="/blacklist">Blacklist</a>
        <a {active('/whitelist')} href="/whitelist">Whitelist</a>
        <a {active('/security-logs')} href="/security-logs">Security Logs</a>
        <a {active('/action-logs')} href="/action-logs">Action Logs</a>
        <a href="/export-logs">Export CSV</a>
        <a href="/logout">Logout</a>
    </div>
    """


def render_dashboard(request, title, logs):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    all_logs = get_email_logs()
    counts = {"SAFE": 0, "SPAM": 0, "QUARANTINE": 0, "DELETE": 0}
    for log in all_logs:
        if log[2] in counts:
            counts[log[2]] += 1

    total_count = len(all_logs)
    alerts_count = counts["QUARANTINE"] + counts["DELETE"]
    top_threats = get_top_threat_words()
    top_domains = get_top_domains()
    current_path = request.url.path

    def active_card(path):
        return 'style="background:#d9d9d9;color:#111;"' if current_path == path else ""

    body = f"""
    <h1>{title}</h1>
    <form class="search-form" method="get" action="/search">
        <input type="text" name="query" placeholder="Search emails, domains, threats...">
        <button type="submit">Search</button>
    </form>
    {nav(current_path)}
    <div class="stats">
        <div class="stat" {active_card('/dashboard')}><a href="/dashboard"><h2>All Emails</h2><p>{total_count}</p></a></div>
        <div class="stat" {active_card('/alerts')}><a href="/alerts"><h2>Alerts</h2><p class="DELETE">{alerts_count}</p></a></div>
        <div class="stat" {active_card('/safe')}><a href="/safe"><h2>Safe</h2><p class="SAFE">{counts['SAFE']}</p></a></div>
        <div class="stat" {active_card('/spam')}><a href="/spam"><h2>Spam</h2><p class="SPAM">{counts['SPAM']}</p></a></div>
        <div class="stat" {active_card('/quarantine')}><a href="/quarantine"><h2>Quarantine</h2><p class="QUARANTINE">{counts['QUARANTINE']}</p></a></div>
        <div class="stat" {active_card('/deleted')}><a href="/deleted"><h2>Delete</h2><p class="DELETE">{counts['DELETE']}</p></a></div>
    </div>
    """

    if alerts_count > 0:
        body += f'<div class="alert-box">⚠ Critical Alerts Detected: {alerts_count}</div>'

    body += '<div class="intel"><div class="intel-card"><h2>Top Threat Indicators</h2>'
    body += "<p>No threat indicators yet.</p>" if not top_threats else "".join([f"<p><b>{t}</b> → {c}</p>" for t, c in top_threats[:5]])
    body += '</div><div class="intel-card"><h2>Top Malicious Domains</h2>'
    body += "<p>No suspicious domains yet.</p>" if not top_domains else "".join([f"<p><b>{d}</b> → {c}</p>" for d, c in top_domains[:5]])
    body += "</div></div>"

    for log in logs:
        email_id, content, decision, risk_score, reasons, links, created_at = log
        sender = extract_sender(content)
        critical_class = "critical" if decision == "DELETE" or risk_score >= 80 else ""
        body += f"""
        <div class="card {critical_class}">
            <h3>Email #{email_id}</h3>
            <p><b>Sender:</b> {sender}</p>
            <p><b>Decision:</b> <span class="{decision}">{decision}</span></p>
            <p><b>Risk Score:</b> {risk_score}</p>
            <p><b>Reasons:</b> {reasons}</p>
            <p><b>Links:</b> {links}</p>
            <p><b>Date:</b> {created_at}</p>
            <div class="actions">
                <a class="btn-safe" href="/update/{email_id}/SAFE">Mark Safe</a>
                <a class="btn-spam" href="/update/{email_id}/SPAM">Move to Spam</a>
                <a class="btn-quarantine" href="/update/{email_id}/QUARANTINE">Quarantine</a>
                <a class="btn-delete" href="/update/{email_id}/DELETE">Delete</a>
                <a class="btn-delete" href="/block-sender/{email_id}">Block Sender</a>
                <a class="btn-delete" href="/block-domain/{email_id}">Block Domain</a>
            </div>
            <pre>{content}</pre>
        </div>
        """

    return page(title, body)


@app.get("/")
def home():
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page("Admin Login", """
    <div class="box" style="max-width:340px;margin:120px auto;">
        <h2>AI Email Gateway</h2>
        <form method="post" action="/login">
            <input style="width:100%;padding:10px;margin-bottom:12px;" type="text" name="username" placeholder="Username">
            <input style="width:100%;padding:10px;margin-bottom:12px;" type="password" name="password" placeholder="Password">
            <button style="width:100%;padding:10px;background:#222;color:white;border:none;border-radius:6px;" type="submit">Login</button>
        </form>
    </div>
    """)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        request.session["logged_in"] = True
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.post("/scan")
def scan_email(email: EmailRequest):
    decision, score, result, ai_result = classify_email(email.content)
    save_email_log(email.content, decision, score, result["reasons"], result["links"])
    return {"decision": decision, "risk_score": score, "analysis": result, "ai_result": ai_result}


@app.get("/update/{email_id}/{decision}")
def update_decision(request: Request, email_id: int, decision: str):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    if decision in ["SAFE", "SPAM", "QUARANTINE", "DELETE"]:
        update_email_decision(email_id, decision)
        save_action_log(email_id, "MANUAL_" + decision)
        gmail_result = move_gmail_email(email_id, decision)
        save_action_log(email_id, "GMAIL_MANUAL_" + decision + "_" + str(gmail_result))
        print("Dashboard Gmail action:", decision, gmail_result)

    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return render_dashboard(request, "AI Email Security Gateway Dashboard", get_email_logs())


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    logs = [log for log in get_email_logs() if log[2] in ["DELETE", "QUARANTINE"] or log[3] >= 80]
    return render_dashboard(request, "Critical Alerts", logs)


@app.get("/safe", response_class=HTMLResponse)
def safe_page(request: Request):
    return render_dashboard(request, "Safe Emails", get_email_logs_by_decision("SAFE"))


@app.get("/spam", response_class=HTMLResponse)
def spam_page(request: Request):
    return render_dashboard(request, "Spam Emails", get_email_logs_by_decision("SPAM"))


@app.get("/quarantine", response_class=HTMLResponse)
def quarantine_page(request: Request):
    return render_dashboard(request, "Quarantined Emails", get_email_logs_by_decision("QUARANTINE"))


@app.get("/deleted", response_class=HTMLResponse)
def deleted_page(request: Request):
    return render_dashboard(request, "Deleted Emails", get_email_logs_by_decision("DELETE"))


@app.get("/search", response_class=HTMLResponse)
def search_page(request: Request, query: str = ""):
    return render_dashboard(request, f"Search Results: {query}", search_email_logs(query))


@app.get("/block-sender/{email_id}")
def block_sender(request: Request, email_id: int):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    email_item = get_email_by_id(email_id)
    if email_item:
        sender, domain = extract_sender_and_domain(email_item[1])
        if sender:
            add_blocked_sender(sender)
            save_action_log(email_id, "BLOCK_SENDER_" + sender)
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/block-domain/{email_id}")
def block_domain(request: Request, email_id: int):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    email_item = get_email_by_id(email_id)
    if email_item:
        sender, domain = extract_sender_and_domain(email_item[1])
        if domain:
            add_blocked_domain(domain)
            save_action_log(email_id, "BLOCK_DOMAIN_" + domain)
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/blacklist", response_class=HTMLResponse)
def blacklist_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    body = nav(request.url.path) + "<h1>Blocked Domains and Senders</h1><div class='box'><h2>Blocked Domains</h2>"
    for domain, created_at in get_blocked_domains():
        body += f"<p><b>{domain}</b> - {created_at}</p>"
    body += "</div><div class='box'><h2>Blocked Senders</h2>"
    for sender, created_at in get_blocked_senders():
        body += f"<p><b>{sender}</b> - {created_at}</p>"
    body += "</div>"
    return page("Blacklist", body)


@app.get("/whitelist-domain/{domain}")
def whitelist_domain(request: Request, domain: str):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)
    add_whitelist_domain(domain)
    return RedirectResponse(url="/whitelist", status_code=303)


@app.get("/whitelist", response_class=HTMLResponse)
def whitelist_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)
    body = nav(request.url.path) + "<h1>Whitelisted Domains</h1><div class='box'>"
    for domain in get_whitelist_domains():
        body += f"<p><b>{domain[0]}</b></p>"
    body += "</div>"
    return page("Whitelist", body)


@app.get("/security-logs", response_class=HTMLResponse)
def security_logs(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    body = nav(request.url.path) + "<h1>SIEM-style Security Logs</h1>"
    for log in get_email_logs():
        email_id, content, decision, risk_score, reasons, links, created_at = log
        if risk_score >= 80 or decision == "DELETE":
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        body += f"""
        <div class="card">
            <h3>[{severity}] Email #{email_id}</h3>
            <p><b>Time:</b> {created_at}</p>
            <p><b>Decision:</b> {decision}</p>
            <p><b>Risk Score:</b> {risk_score}</p>
            <p><b>Event:</b> {reasons}</p>
            <p><b>Links:</b> {links}</p>
        </div>
        """
    return page("Security Logs", body)


@app.get("/action-logs", response_class=HTMLResponse)
def action_logs(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    body = nav(request.url.path) + """
    <h1>Action Logs</h1>
    <table>
        <tr><th>ID</th><th>Email ID</th><th>Action</th><th>Date</th></tr>
    """
    for log in get_action_logs():
        body += f"<tr><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td>{log[3]}</td></tr>"
    body += "</table>"
    return page("Action Logs", body)


@app.get("/export-logs")
def export_logs(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login", status_code=303)

    logs = get_email_logs()
    filename = "security_logs.csv"
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Decision", "Risk Score", "Reasons", "Links", "Date"])
        for log in logs:
            email_id, content, decision, risk_score, reasons, links, created_at = log
            writer.writerow([email_id, decision, risk_score, reasons, links, created_at])

    return FileResponse(path=filename, filename=filename, media_type="text/csv")

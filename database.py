import sqlite3
from datetime import datetime

DB_NAME = "emails.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT,
            decision TEXT,
            risk_score INTEGER,
            reasons TEXT,
            links TEXT,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_senders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT UNIQUE,
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS action_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            action TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()

    add_gmail_columns()
    add_gmail_msgid_column()


def add_gmail_columns():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE email_logs ADD COLUMN gmail_uid TEXT")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE email_logs ADD COLUMN gmail_folder TEXT")
    except Exception:
        pass

    conn.commit()
    conn.close()


def add_gmail_msgid_column():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE email_logs ADD COLUMN gmail_msgid TEXT")
    except Exception:
        pass

    conn.commit()
    conn.close()


def save_email_log(content, decision, risk_score, reasons, links):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO email_logs
        (content, decision, risk_score, reasons, links, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        content,
        decision,
        risk_score,
        ", ".join(reasons),
        ", ".join(links),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    email_log_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return email_log_id


def save_email_log_with_gmail(
    content,
    decision,
    risk_score,
    reasons,
    links,
    gmail_uid,
    gmail_folder,
    gmail_msgid
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO email_logs
        (content, decision, risk_score, reasons, links, created_at, gmail_uid, gmail_folder, gmail_msgid)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        content,
        decision,
        risk_score,
        ", ".join(reasons),
        ", ".join(links),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        gmail_uid,
        gmail_folder,
        gmail_msgid
    ))

    email_log_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return email_log_id


def get_email_logs():
    return get_email_logs_by_decision(None)


def get_email_logs_by_decision(decision):
    conn = get_connection()
    cursor = conn.cursor()

    if decision is None:
        cursor.execute("""
            SELECT id, content, decision, risk_score, reasons, links, created_at
            FROM email_logs
            ORDER BY id DESC
        """)
    else:
        cursor.execute("""
            SELECT id, content, decision, risk_score, reasons, links, created_at
            FROM email_logs
            WHERE decision = ?
            ORDER BY id DESC
        """, (decision,))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_email_by_id(email_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, content, decision, risk_score, reasons, links, created_at
        FROM email_logs
        WHERE id = ?
    """, (email_id,))

    row = cursor.fetchone()
    conn.close()
    return row


def update_email_decision(email_id, new_decision):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE email_logs
        SET decision = ?
        WHERE id = ?
    """, (new_decision, email_id))

    conn.commit()
    conn.close()


def update_gmail_location(email_id, gmail_uid, gmail_folder):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE email_logs
        SET gmail_uid = ?, gmail_folder = ?
        WHERE id = ?
    """, (gmail_uid, gmail_folder, email_id))

    conn.commit()
    conn.close()


def get_gmail_info_by_email_id(email_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT gmail_uid, gmail_folder, gmail_msgid
        FROM email_logs
        WHERE id = ?
    """, (email_id,))

    row = cursor.fetchone()
    conn.close()
    return row


def get_critical_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, content, decision, risk_score, reasons, links, created_at
        FROM email_logs
        WHERE decision = 'DELETE' OR risk_score >= 80
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_statistics():
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    for decision in ["SAFE", "SPAM", "QUARANTINE", "DELETE"]:
        cursor.execute(
            "SELECT COUNT(*) FROM email_logs WHERE decision = ?",
            (decision,)
        )
        stats[decision.lower()] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_logs")
    stats["total"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM email_logs
        WHERE decision = 'DELETE' OR risk_score >= 80
    """)
    stats["alerts"] = cursor.fetchone()[0]

    conn.close()
    return stats


def add_blocked_domain(domain):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO blocked_domains (domain, created_at)
        VALUES (?, ?)
    """, (
        domain.lower(),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def add_blocked_sender(sender):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO blocked_senders (sender, created_at)
        VALUES (?, ?)
    """, (
        sender.lower(),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def is_domain_blocked(domain):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM blocked_domains WHERE domain = ?",
        (domain.lower(),)
    )

    row = cursor.fetchone()
    conn.close()
    return row is not None


def is_sender_blocked(sender):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM blocked_senders WHERE sender = ?",
        (sender.lower(),)
    )

    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_blocked_domains():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT domain, created_at
        FROM blocked_domains
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_blocked_senders():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender, created_at
        FROM blocked_senders
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def add_whitelist_domain(domain):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO whitelist_domains (domain)
        VALUES (?)
    """, (domain.lower(),))

    conn.commit()
    conn.close()


def is_domain_whitelisted(domain):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM whitelist_domains
        WHERE domain = ?
    """, (domain.lower(),))

    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_whitelist_domains():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT domain
        FROM whitelist_domains
        ORDER BY domain ASC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def search_email_logs(query):
    conn = get_connection()
    cursor = conn.cursor()

    search = f"%{query.lower()}%"

    cursor.execute("""
        SELECT id, content, decision, risk_score, reasons, links, created_at
        FROM email_logs
        WHERE
            LOWER(content) LIKE ?
            OR LOWER(decision) LIKE ?
            OR LOWER(reasons) LIKE ?
            OR LOWER(links) LIKE ?
        ORDER BY id DESC
    """, (
        search,
        search,
        search,
        search
    ))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_top_threat_words():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT reasons FROM email_logs")
    rows = cursor.fetchall()
    conn.close()

    threat_counts = {}
    keywords = [
        "urgent",
        "verify",
        "password",
        "click here",
        "bank",
        "invoice",
        "payment",
        "login"
    ]

    for row in rows:
        reasons = str(row[0]).lower()

        for keyword in keywords:
            if keyword in reasons:
                threat_counts[keyword] = threat_counts.get(keyword, 0) + 1

    return sorted(threat_counts.items(), key=lambda item: item[1], reverse=True)


def get_top_domains():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT links
        FROM email_logs
        WHERE links IS NOT NULL AND links != ''
    """)

    rows = cursor.fetchall()
    conn.close()

    domain_counts = {}

    for row in rows:
        links = str(row[0])
        domains = links.split(",")

        for domain in domains:
            domain = domain.strip()

            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1

    return sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)[:5]


def save_action_log(email_id, action):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO action_logs (
            email_id,
            action,
            created_at
        )
        VALUES (?, ?, ?)
    """, (
        email_id,
        action,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_action_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, email_id, action, created_at
        FROM action_logs
        ORDER BY id DESC
        LIMIT 100
    """)

    logs = cursor.fetchall()
    conn.close()
    return logs

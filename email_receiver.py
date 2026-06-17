import email
import imaplib
import os
from email.header import decode_header
from time import sleep

from dotenv import load_dotenv

from analyzer import analyze_email
from ai_model import predict_email
from database import save_email_log_with_gmail, save_action_log


load_dotenv()

EMAIL = os.getenv("GMAIL_EMAIL", "ai.email.gateway@gmail.com")
APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")

FOLDERS = [
    "inbox",
    "[Gmail]/Spam"
]

CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "5"))


def clean_text(value):
    if value is None:
        return ""

    decoded_parts = decode_header(value)
    result = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="ignore")
        else:
            result += part

    return result


def get_email_body(msg):
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)

                if payload:
                    body = payload.decode(errors="ignore")
                    break
    else:
        payload = msg.get_payload(decode=True)

        if payload:
            body = payload.decode(errors="ignore")

    return body


def ensure_folder(mail, folder_name):
    try:
        mail.create(folder_name)
    except Exception:
        pass


def apply_gmail_action(mail, gmail_uid, decision):
    try:
        if decision == "SAFE":
            mail.uid("store", gmail_uid, "+FLAGS", "\\Seen")
            print("Gmail action: SAFE - left in inbox")
            return True

        if decision == "SPAM":
            mail.uid("store", gmail_uid, "+X-GM-LABELS", "\\Spam")
            mail.uid("store", gmail_uid, "-X-GM-LABELS", "\\Inbox")
            mail.uid("store", gmail_uid, "+FLAGS", "\\Seen")
            print("Gmail action: moved to Gmail Spam")
            return True

        if decision == "QUARANTINE":
            ensure_folder(mail, "AI-QUARANTINE")
            mail.uid("store", gmail_uid, "+X-GM-LABELS", "AI-QUARANTINE")
            mail.uid("store", gmail_uid, "-X-GM-LABELS", "\\Inbox")
            mail.uid("store", gmail_uid, "+FLAGS", "\\Seen")
            print("Gmail action: moved to AI-QUARANTINE")
            return True

        if decision == "DELETE":
            mail.uid("store", gmail_uid, "+X-GM-LABELS", "\\Trash")
            mail.uid("store", gmail_uid, "-X-GM-LABELS", "\\Inbox")
            mail.uid("store", gmail_uid, "+FLAGS", "\\Seen")
            print("Gmail action: moved to Trash")
            return True

        return False

    except Exception as e:
        print("Gmail action error:", e)
        return False


def calculate_ai_score(ai_result):
    if ai_result["prediction"] != "phishing":
        return 0

    confidence = ai_result["confidence"]

    if confidence >= 0.95:
        return 20

    if confidence >= 0.85:
        return 12

    if confidence >= 0.70:
        return 6

    return 0


def decide_email(score):
    if score >= 90:
        return "DELETE"

    if score >= 65:
        return "QUARANTINE"

    if score >= 30:
        return "SPAM"

    return "SAFE"


def scan_and_save_email(full_content, gmail_uid, gmail_folder, gmail_msgid):
    result = analyze_email(full_content)
    ai_result = predict_email(full_content)

    score = result["score"]
    ai_score = calculate_ai_score(ai_result)
    score += ai_score

    if ai_score > 0:
        result["reasons"].append(
            "AI model detected phishing with confidence: " + str(ai_result["confidence"])
        )

    score = max(score, 0)
    score = min(score, 100)

    decision = decide_email(score)

    email_log_id = save_email_log_with_gmail(
        full_content,
        decision,
        score,
        result["reasons"],
        result["links"],
        gmail_uid,
        gmail_folder,
        gmail_msgid
    )

    save_action_log(email_log_id, "AUTO_" + decision)

    return decision, score, email_log_id


def extract_gmail_msgid(msg_data):
    gmail_msgid = ""

    for item in msg_data:
        if isinstance(item, tuple):
            header_text = item[0].decode(errors="ignore")

            if "X-GM-MSGID" in header_text:
                try:
                    gmail_msgid = header_text.split("X-GM-MSGID")[1].split()[0]
                except Exception:
                    gmail_msgid = ""

    return gmail_msgid


def get_raw_email(msg_data):
    for item in msg_data:
        if isinstance(item, tuple) and item[1]:
            return item[1]

    return None


def receive_emails():
    if not APP_PASSWORD:
        print("GMAIL_APP_PASSWORD is missing in .env")
        return

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(EMAIL, APP_PASSWORD)

    total_scanned = 0

    for folder in FOLDERS:
        try:
            status, _ = mail.select(folder)

            if status != "OK":
                print("Could not open folder:", folder)
                continue

            status, messages = mail.uid("search", None, "UNSEEN")

            if status != "OK":
                print("Could not search folder:", folder)
                continue

            email_ids = messages[0].split()

            if len(email_ids) == 0:
                print("No unread emails in:", folder)
                continue

            for gmail_uid in email_ids:
                status, msg_data = mail.uid(
                    "fetch",
                    gmail_uid,
                    "(X-GM-MSGID RFC822)"
                )

                if status != "OK":
                    continue

                gmail_msgid = extract_gmail_msgid(msg_data)
                raw_email = get_raw_email(msg_data)

                if raw_email is None:
                    print("Could not read email body")
                    continue

                msg = email.message_from_bytes(raw_email)

                sender = clean_text(msg.get("From"))
                subject = clean_text(msg.get("Subject"))
                reply_to = clean_text(msg.get("Reply-To"))
                return_path = clean_text(msg.get("Return-Path"))

                body = get_email_body(msg)

                full_content = f"""From: {sender}
Return-Path: {return_path}
Reply-To: {reply_to}
Subject: {subject}
Folder: {folder}

{body}
"""

                decision, score, email_log_id = scan_and_save_email(
                    full_content,
                    gmail_uid.decode(),
                    folder,
                    gmail_msgid
                )

                gmail_action_result = apply_gmail_action(mail, gmail_uid, decision)

                save_action_log(
                    email_log_id,
                    "GMAIL_ACTION_" + decision + "_" + str(gmail_action_result)
                )

                total_scanned += 1

                print(
                    "Scanned from",
                    folder + ":",
                    subject,
                    "| Decision:",
                    decision,
                    "| Score:",
                    score,
                    "| Gmail Action:",
                    gmail_action_result
                )

        except Exception as e:
            print("Folder error:", folder, e)

    try:
        mail.logout()
    except Exception:
        pass

    print("Total scanned:", total_scanned)


if __name__ == "__main__":
    while True:
        try:
            print("Checking Gmail inbox...")
            receive_emails()
            print("Waiting", CHECK_INTERVAL_SECONDS, "seconds...")
            sleep(CHECK_INTERVAL_SECONDS)

        except Exception as e:
            print("Error:", e)
            sleep(CHECK_INTERVAL_SECONDS)

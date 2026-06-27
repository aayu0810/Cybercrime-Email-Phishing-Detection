import re
import pyshark

# keywords that may indicate phishing
KEYWORDS = ["urgent", "verify", "password", "bank", "invoice", "free", "winner"]

# suspicious name and titles in sender domain
SUSPICIOUS_DOMAIN = ["paypa1", "amaz0n", "micros0ft", "apple-", "secure-", "verify-", "login-", "account-", "invoices-"]

# load pcap file and apply smtp/pop/imap filter
def filter_email_traffic(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="smtp || pop || imap")
    return capture

# go through packets and extract email info
def extract_emails(capture):
    emails = []
    current = None

    for pkt in capture:
        try:
            if "SMTP" not in pkt:
                continue
            
            # get source and destination IP addresses if available
            src_ip = pkt.ip.src if hasattr(pkt, "ip") else "N/A"
            dst_ip = pkt.ip.dst if hasattr(pkt, "ip") else "N/A"

            # extract email sender and recipient addresses 
            if hasattr(pkt.smtp, "req_parameter"):
                param = pkt.smtp.req_parameter

                # new email starts with MAIL FROM
                if "FROM:" in param.upper():
                    if current:
                        emails.append(current)
                    current = {"from": "Unknown", "to": "Unknown", "subject": "N/A", "body": "", "src_ip": src_ip, "dst_ip": dst_ip}
                    m = re.search(r"<?([\w.\-]+@[\w.\-]+)>?", param)
                    if m:
                        current["from"] = m.group(1)

                # recipient address
                elif "TO:" in param.upper() and current:
                    m = re.search(r"<?([\w.\-]+@[\w.\-]+)>?", param)
                    if m:
                        current["to"] = m.group(1)

            # read subject and body from IMF layer (parsed email format)
            if hasattr(pkt, "imf") and current:
                # extract subject
                if hasattr(pkt.imf, "subject"):
                    current["subject"] = pkt.imf.subject
                # extract email body
                if hasattr(pkt.imf, "mime_entity_body"):
                    current["body"] += pkt.imf.mime_entity_body

        except AttributeError:
            continue

    if current:
        emails.append(current)
    return emails

# check for phishing keywords in subject/body, and suspicious sender domain
def detect_phishing(email):
    alerts = []
    text = email["body"].lower() + email["subject"].lower()
    for kw in KEYWORDS:
        if kw in text:
            alerts.append(kw)
    if re.search(r"https?://", text):
        alerts.append("URL found")
    # check if sender domain looks fake
    sender = email["from"].lower()
    for pattern in SUSPICIOUS_DOMAIN:
        if pattern in sender:
            alerts.append("suspicious sender domain")
            break
    return alerts

# write results to a report file
def generate_report(emails):
    report = ""
    for i, email in enumerate(emails):
        alerts = detect_phishing(email)
        report += f"Email #{i + 1}\n"
        report += f"From: {email['from']}\n"
        report += f"To: {email['to']}\n"
        report += f"Subject: {email['subject']}\n"
        report += f"Phishing alerts: {', '.join(alerts) if alerts else 'None'}\n"
        report += "\n"

    print(report)
    with open("phishing_report.txt", "w") as f:
        f.write(report)
    print("Report saved: phishing_report.txt")


if __name__ == "__main__":
    pcap_file = "smtp_capture.pcapng"
    capture = filter_email_traffic(pcap_file)
    emails = extract_emails(capture)
    if not emails:
        print("No emails found.")
    else:
        generate_report(emails)

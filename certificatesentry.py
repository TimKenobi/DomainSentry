import os
import sys
import requests
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import smtplib
from email.message import EmailMessage
import argparse
import time
import csv
import glob
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
OUTPUT_DIR = "/opt/certificate_checker/output"
SMTP_HOST = "smtp.yoursmtpserver.com" #Change this to your SMTP Server
SMTP_PORT = 25
LOG_FILE = os.path.join(OUTPUT_DIR, "log.txt")
EMAIL_RECIPIENTS = [
    "youremail@yourdomain.com",
    # Add more email addresses here, e.g.:
    # "another@example.com",
    # "team@company.com",
]

def send_email(subject, body, attachments):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = "youremail@email.com" #Set your email
    msg['To'] = ", ".join(EMAIL_RECIPIENTS)

    for file_path in attachments:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_name = os.path.basename(file_path)
            msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Email sent: {subject} to {', '.join(EMAIL_RECIPIENTS)}\n")
        logger.info(f"Email sent: {subject} to {', '.join(EMAIL_RECIPIENTS)}")
    except Exception as e:
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Email failed to send to {', '.join(EMAIL_RECIPIENTS)}: {subject} - {str(e)}\n")
        logger.error(f"Email failed to send to {', '.join(EMAIL_RECIPIENTS)}: {subject} - {str(e)}")

def check_new_certificates(domain, retries=3, backoff=2):
    cert_file = os.path.join(OUTPUT_DIR, f"{domain}_certs.txt")
    prev_cert_file = os.path.join(OUTPUT_DIR, f"{domain}_certs_prev.txt")
    new_certs = []
    current_certs = set()

    for attempt in range(retries):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            certs = json.loads(response.text)

            if not isinstance(certs, list):
                with open(LOG_FILE, 'a') as log:
                    log.write(f"[{time.ctime()}] Invalid crt.sh response for {domain}: {certs}\n")
                logger.error(f"Invalid crt.sh response for {domain}: {certs}")
                return []

            # Check certificates from the last 24 hours for daily runs
            cutoff = datetime.now(ZoneInfo("UTC")) - timedelta(hours=24)
            for cert in certs:
                try:
                    issued_date = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                    issued_date = issued_date.replace(tzinfo=ZoneInfo("UTC"))
                    if issued_date >= cutoff:
                        cert_info = {
                            'domain': cert['name_value'],
                            'issuer': cert['issuer_name'],
                            'issued': cert['not_before'],
                            'id': cert['id']
                        }
                        new_certs.append(cert_info)
                except (ValueError, KeyError):
                    continue

            with open(cert_file, 'w') as f:
                for cert in new_certs:
                    f.write(f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}\n")

            if os.path.exists(cert_file):
                with open(cert_file, 'r') as f:
                    current_certs = set(f.read().splitlines())
            else:
                current_certs = set()

            if os.path.exists(prev_cert_file):
                with open(prev_cert_file, 'r') as f:
                    prev_certs = set(f.read().splitlines())
                new_certs = [cert for cert in new_certs if f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}" in current_certs - prev_certs]
            else:
                new_certs = new_certs

            with open(LOG_FILE, 'a') as log:
                log.write(f"[{time.ctime()}] Found {len(new_certs)} new certificates for {domain}\n")
            logger.info(f"Found {len(new_certs)} new certificates for {domain}")

            if os.path.exists(cert_file):
                os.replace(cert_file, prev_cert_file)

            return new_certs

        except requests.RequestException as e:
            logger.error(f"Certificate check failed for {domain} (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(backoff * (2 ** attempt))
            continue
        except Exception as e:
            logger.error(f"Unexpected error in certificate check for {domain}: {e}")
            return []

    logger.error(f"All retries failed for certificate check for {domain}")
    return []

def generate_combined_report(all_domain_data, timestamp):
    report = f"Daily Website Certificate Report - {timestamp}\n"
    report += "=" * 80 + "\n\n"

    total_new_certs = 0

    csv_file = os.path.join(OUTPUT_DIR, f"cert_report_{timestamp.replace(' ', '_').replace(':', '-')}.csv")
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Certificate Domain", "Issuer", "Issued", "ID"])
        for domain_data in all_domain_data:
            domain = domain_data['domain']
            certificates = domain_data['certificates']
            for cert in certificates:
                writer.writerow([domain, cert['domain'], cert['issuer'], cert['issued'], cert['id']])

    for domain_data in all_domain_data:
        domain = domain_data['domain']
        certificates = domain_data['certificates']

        max_cert_domain = max([len(cert['domain']) for cert in certificates] + [6]) if certificates else 6
        max_issuer = max([len(cert['issuer']) for cert in certificates] + [6]) if certificates else 6
        max_issued = max([len(cert['issued']) for cert in certificates] + [6]) if certificates else 6
        max_id = max([len(str(cert['id'])) for cert in certificates] + [2]) if certificates else 2

        report += f"Domain: {domain}\n"
        report += "-" * 50 + "\n\n"
        report += "New Certificates (Last 24 Hours):\n"
        cert_header = f"{'Domain':<{max_cert_domain}}  {'Issuer':<{max_issuer}}  {'Issued':<{max_issued}}  {'ID':<{max_id}}\n"
        report += cert_header
        report += "-" * (max_cert_domain + max_issuer + max_issued + max_id + 9) + "\n"
        if certificates:
            for cert in certificates:
                report += f"{cert['domain']:<{max_cert_domain}}  {cert['issuer']:<{max_issuer}}  {cert['issued']:<{max_issued}}  {cert['id']:<{max_id}}\n"
                total_new_certs += 1
        else:
            report += "None\n"
        report += "\n"

    report += "Summary:\n"
    report += "-" * 50 + "\n"
    report += f"- Total domains scanned: {len(all_domain_data)}\n"
    report += f"- Total new certificates: {total_new_certs}\n"
    report += f"- Report generated: {timestamp}\n"

    return report, csv_file

def cleanup_old_files(domains):
    patterns = [
        "*.txt",
        "*.csv"
    ]
    for domain in domains:
        patterns.extend([
            f"{domain}_certs.txt",
            f"{domain}_certs_prev.txt",
            f"cert_report_*.csv"
        ])
    for pattern in patterns:
        files = glob.glob(os.path.join(OUTPUT_DIR, pattern))
        for file in files:
            if "cert_report_" not in file:  # Preserve final report files
                try:
                    os.remove(file)
                    logger.info(f"Deleted intermediate file: {file}")
                except Exception as e:
                    logger.error(f"Failed to delete {file}: {e}")

def process_domain(domain):
    logger.info(f"Scanning certificates for {domain}")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    certificates = check_new_certificates(domain)
    return {
        'domain': domain,
        'certificates': certificates
    }

def main():
    parser = argparse.ArgumentParser(description="Daily certificate checker for multiple domains")
    parser.add_argument('--domain-file', type=str, default="/opt/certificate_checker/domains.txt", help="Path to file containing domains, one per line")
    args = parser.parse_args()

    if not os.path.exists(args.domain_file):
        logger.error(f"Domain file {args.domain_file} not found")
        sys.exit(1)

    try:
        with open(args.domain_file, 'r') as file:
            domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except Exception as e:
        logger.error(f"Error reading domain file {args.domain_file}: {e}")
        sys.exit(1)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    all_domain_data = []
    for domain in domains:
        print(f"\n[!] Scanning certificates for {domain}")
        domain_data = process_domain(domain)
        if domain_data:
            all_domain_data.append(domain_data)

    timestamp = datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
    report, csv_file = generate_combined_report(all_domain_data, timestamp)
    txt_file = os.path.join(OUTPUT_DIR, f"cert_report_{timestamp.replace(' ', '_').replace(':', '-')}.txt")
    with open(txt_file, 'w') as file:
        file.write(report)

    cleanup_old_files(domains)

    if any(data['certificates'] for data in all_domain_data):
        email_body = f"Daily Website Certificate Report - {timestamp}\n\nPlease see the attached CSV file for the detailed report.\nThe plain text file is also attached for reference.\n"
        attachments = [csv_file, txt_file]
        send_email(f"Daily Website Certificate Report - {timestamp}", email_body, attachments)
    else:
        logger.info("No new certificates found across all domains")

if __name__ == "__main__":
    main()

import sublist3r
from collections import Counter
import os
import sys
import asyncio
import aiohttp
from aiohttp import ClientSession, ClientConnectorError, ClientOSError, ServerDisconnectedError, TooManyRedirects, ServerTimeoutError
import dns.resolver
import smtplib
from email.message import EmailMessage
import argparse
import time
import requests
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import glob
import shutil
import logging
import ipaddress
import csv
import socket

try:
    import colorama
    colorama.init()
except ImportError:
    print("[!] Warning: colorama not installed, console output will not be colored")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
OUTPUT_DIR = "/opt/domainsentry/output"
AWS_RANGES_FILE = os.path.join(OUTPUT_DIR, 'aws_ip_ranges.json')
AWS_RANGES_CACHE_DAYS = 1
SMTP_HOST = "relay.yoursmtpserver.net"
SMTP_PORT = 25
LOG_FILE = os.path.join(OUTPUT_DIR, "log.txt")
# List of email recipients
EMAIL_RECIPIENTS = [
    "youremail@outlook.com",
    # Add more email addresses here, e.g.:
    # "another@example.com",
    # "team@company.com"
]

def load_aws_ranges():
    if os.path.exists(AWS_RANGES_FILE):
        mtime = datetime.fromtimestamp(os.path.getmtime(AWS_RANGES_FILE), tz=ZoneInfo("UTC"))
        if (datetime.now(ZoneInfo("UTC")) - mtime).days < AWS_RANGES_CACHE_DAYS:
            with open(AWS_RANGES_FILE, 'r') as f:
                data = json.load(f)
                return [ipaddress.IPv4Network(prefix['ip_prefix']) for prefix in data['prefixes'] if 'ip_prefix' in prefix], \
                       [ipaddress.IPv6Network(prefix['ipv6_prefix']) for prefix in data['ipv6_prefixes'] if 'ipv6_prefix' in prefix]
    
    try:
        url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        with open(AWS_RANGES_FILE, 'w') as f:
            json.dump(data, f)
        return [ipaddress.IPv4Network(prefix['ip_prefix']) for prefix in data['prefixes'] if 'ip_prefix' in prefix], \
               [ipaddress.IPv6Network(prefix['ipv6_prefix']) for prefix in data['ipv6_prefixes'] if 'ipv6_prefix' in prefix]
    except Exception as e:
        logger.error(f"Failed to fetch AWS IP ranges: {e}")
        return [], []

def is_aws_ip(ip, ipv4_ranges, ipv6_ranges):
    try:
        ip_obj = ipaddress.ip_address(ip)
        ranges = ipv4_ranges if ip_obj.version == 4 else ipv6_ranges
        for net in ranges:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False

def get_dns_records(subdomain):
    records = {'A': [], 'CNAME': [], 'MX': []}
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(subdomain, 'A')
        records['A'] = [str(rdata) for rdata in answers]
    except Exception:
        pass
    try:
        answers = resolver.resolve(subdomain, 'CNAME')
        records['CNAME'] = [str(rdata.target) for rdata in answers]
    except Exception:
        pass
    try:
        answers = resolver.resolve(subdomain, 'MX')
        records['MX'] = [str(rdata.exchange) for rdata in answers]
    except Exception:
        pass
    return records

def check_spoofable(subdomain):
    services = {
        'AWS': '.amazonaws.com',
        'Shopify': 'shopify.com',
        'Zendesk': 'zendesk.com',
        'GitHub': 'github.io',
        'Heroku': 'herokuapp.com'
    }
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).lower()
            for service, domain in services.items():
                if domain in cname:
                    return f"{service} (CNAME: {cname})"
    except Exception:
        pass
    return None

def is_aws(subdomain, records, ipv4_ranges, ipv6_ranges):
    if records['CNAME']:
        for cname in records['CNAME']:
            if cname.lower().endswith('.amazonaws.com'):
                return True
    if records['A']:
        for ip in records['A']:
            if is_aws_ip(ip, ipv4_ranges, ipv6_ranges):
                return True
    return False

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def check_iis_page(response, headers):
    if (response and (
        "iisstart.htm" in response.lower() or 
        "iisstart.png" in response.lower() or 
        "Internet Information Services" in response or 
        "Welcome.*IIS" in response or 
        "IIS Windows Server" in response or 
        "<title>IIS[0-9.]*</title>" in response.lower()
    )) or (headers and "Server: Microsoft-IIS" in headers):
        return "Yes"
    return "No"

def check_port_25(domain):
    try:
        socket.setdefaulttimeout(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((domain, 25))
        sock.close()
        return "Open" if result == 0 else "Closed"
    except Exception:
        return "Closed"

def send_email(subject, body, attachments):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = "youremail@email.com" #Set your email
    msg['To'] = ", ".join(EMAIL_RECIPIENTS)  # Join multiple recipients with commas

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

async def fetch_html(domain_data, url: str, session: aiohttp.ClientSession) -> tuple:
    try:
        async with session.get(url, timeout=15, allow_redirects=True, ssl=False) as resp:
            status = resp.status
            headers = str(resp.headers)
            response_text = await resp.text()
            if status == 200:
                with open(os.path.join(OUTPUT_DIR, f"{domain_data}-200.txt"), "a") as file:
                    file.write(f"{url}\n")
                print(f"\u001b[32;1m[{status}] {url}\u001b[0m" if 'colorama' in sys.modules else f"[{status}] {url}")
            else:
                with open(os.path.join(OUTPUT_DIR, f"{domain_data}-other.txt"), "a") as file:
                    file.write(f"{url} - {status}\n")
                print(f"\u001b[31;1m[{status}] {url}\u001b[0m" if 'colorama' in sys.modules else f"[{status}] {url}")
            return (url, status, response_text, headers)
    except (ClientConnectorError, ClientOSError, ServerDisconnectedError, asyncio.TimeoutError, TooManyRedirects, ServerTimeoutError) as error:
        with open(os.path.join(OUTPUT_DIR, f"{domain_data}-other.txt"), "a") as file:
            file.write(f"{url} - Error: {str(error)}\n")
        print(f"\u001b[31;1m[Error] {url} - {str(error)}\u001b[0m" if 'colorama' in sys.modules else f"[Error] {url} - {str(error)}")
        return (url, 500, "", "")
    except Exception as error:
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Fetch error for {url}: {error}\n")
        logger.error(f"Fetch error for {url}: {error}")
        return (url, 500, "", "")

async def make_requests(domain, urls):
    async with ClientSession() as session:
        tasks = [fetch_html(domain, url, session) for url in urls]
        print(f"\n[+] Checking URLs for {domain}")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [(url, status, text, headers) for url, status, text, headers in results if not isinstance((url, status, text, headers), Exception)]

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

            cutoff = datetime.now(ZoneInfo("UTC")) - timedelta(hours=72)
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

            with open(cert_file, 'w') as file:
                for cert in new_certs:
                    file.write(f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}\n")

            if os.path.exists(cert_file):
                with open(cert_file, 'r') as file:
                    current_certs = set(file.read().splitlines())
            else:
                current_certs = set()

            if os.path.exists(prev_cert_file):
                with open(prev_cert_file, 'r') as file:
                    prev_certs = set(file.read().splitlines())
                new_certs = [cert for cert in new_certs if f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}" in current_certs - prev_certs]
            else:
                new_certs = new_certs

            logger.info(f"Found {len(new_certs)} new certificates for {domain}")
            return new_certs
        except requests.RequestException as error:
            logger.error(f"Certificate check failed for {domain} (attempt {attempt+1}/{retries}): {error}")
            if attempt < retries - 1:
                time.sleep(backoff * (2 ** attempt))
            continue
        except Exception as error:
            logger.error(f"Unexpected error in certificate check for {domain}: {error}")
            return []

    logger.error(f"All retries failed for certificate check for {domain}")
    return []

def generate_combined_report(all_domain_data, timestamp):
    report = f"Combined Security Report - {timestamp}\n"
    report += "=" * 80 + "\n\n"
    report += "Note: Spoofable subdomains have CNAME records pointing to third-party services (e.g., AWS, Shopify) that may be vulnerable to subdomain takeover if unclaimed or misconfigured.\n\n"

    total_subdomains = 0
    total_new_certs = 0
    spoofable_count = 0
    aws_count = 0
    live_count = 0
    iis_count = 0
    port_25_open = 0

    csv_file = os.path.join(OUTPUT_DIR, f"combined_report_{timestamp.replace(' ', '_').replace(':', '-')}.csv")
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Domain", "Subdomain", "A Records", "CNAME", "MX Records", "Spoofable", "Lander", "Final URL", "Port 25", "IIS Page", "Error"])
        for domain_data in all_domain_data:
            domain = domain_data['domain']
            subdomains = domain_data['subdomains']
            for sub in subdomains:
                a_records = ", ".join(sub['A']) if sub['A'] else "None"
                cname = ", ".join(sub['CNAME']) if sub['CNAME'] else "None"
                mx_records = ", ".join(sub['MX']) if sub['MX'] else "None"
                spoofable = sub['spoofable_service'] if sub['spoofable_service'] else "No"
                lander = sub['lander_status'] if sub['lander_status'] else "Not Found"
                final_url = sub['final_url'] if sub['final_url'] else "Unknown"
                port_status = sub['port_status'] if sub['port_status'] else "Unknown"
                iis_page = sub['iis_page'] if sub['iis_page'] else "No"
                error = sub['error'] if sub['error'] else ""
                writer.writerow([domain, sub['name'], a_records, cname, mx_records, spoofable, lander, final_url, port_status, iis_page, error])
        writer.writerow([])
        writer.writerow(["Domain", "Certificate Domain", "Issuer", "Issued", "ID"])
        for domain_data in all_domain_data:
            domain = domain_data['domain']
            certificates = domain_data['certificates']
            for cert in certificates:
                writer.writerow([domain, cert['domain'], cert['issuer'], cert['issued'], cert['id']])

    for domain_data in all_domain_data:
        domain = domain_data['domain']
        subdomains = domain_data['subdomains']
        certificates = domain_data['certificates']

        max_name = max([len(sub['name']) for sub in subdomains] + [4]) if subdomains else 4
        max_a = max([len(", ".join(sub['A']) if sub['A'] else "None") for sub in subdomains] + [9]) if subdomains else 9
        max_cname = max([len(", ".join(sub['CNAME']) if sub['CNAME'] else "None") for sub in subdomains] + [5]) if subdomains else 5
        max_mx = max([len(", ".join(sub['MX']) if sub['MX'] else "None") for sub in subdomains] + [9]) if subdomains else 9
        max_spoof = max([len(sub['spoofable_service'] if sub['spoofable_service'] else "No") for sub in subdomains] + [9]) if subdomains else 9
        max_lander = max([len(sub['lander_status'] if sub['lander_status'] else "Not Found") for sub in subdomains] + [6]) if subdomains else 6
        max_url = max([len(sub['final_url'] if sub['final_url'] else "Unknown") for sub in subdomains] + [9]) if subdomains else 9
        max_port = max([len(sub['port_status'] if sub['port_status'] else "Unknown") for sub in subdomains] + [7]) if subdomains else 7
        max_iis = max([len(sub['iis_page'] if sub['iis_page'] else "No") for sub in subdomains] + [8]) if subdomains else 8

        report += f"Domain: {domain}\n"
        report += "-" * 50 + "\n\n"
        report += "Subdomains:\n"
        header = f"{'Name':<{max_name}}  {'A Records':<{max_a}}  {'CNAME':<{max_cname}}  {'MX Records':<{max_mx}}  {'Spoofable':<{max_spoof}}  {'Lander':<{max_lander}}  {'Final URL':<{max_url}}  {'Port 25':<{max_port}}  {'IIS Page':<{max_iis}}\n"
        report += header
        report += "-" * (max_name + max_a + max_cname + max_mx + max_spoof + max_lander + max_url + max_port + max_iis + 16) + "\n"
        for sub in subdomains:
            a_records = ", ".join(sub['A']) if sub['A'] else "None"
            cname = ", ".join(sub['CNAME']) if sub['CNAME'] else "None"
            mx_records = ", ".join(sub['MX']) if sub['MX'] else "None"
            spoofable = sub['spoofable_service'] if sub['spoofable_service'] else "No"
            lander = sub['lander_status'] if sub['lander_status'] else "Not Found"
            final_url = sub['final_url'] if sub['final_url'] else "Unknown"
            port_status = sub['port_status'] if sub['port_status'] else "Unknown"
            iis_page = sub['iis_page'] if sub['iis_page'] else "No"
            report += f"{sub['name']:<{max_name}}  {a_records:<{max_a}}  {cname:<{max_cname}}  {mx_records:<{max_mx}}  {spoofable:<{max_spoof}}  {lander:<{max_lander}}  {final_url:<{max_url}}  {port_status:<{max_port}}  {iis_page:<{max_iis}}\n"
            total_subdomains += 1
            if sub['spoofable_service']:
                spoofable_count += 1
            if sub['aws']:
                aws_count += 1
            if sub['lander_status'] == "Found":
                live_count += 1
            if sub['iis_page'] == "Yes":
                iis_count += 1
            if sub['port_status'] == "Open":
                port_25_open += 1

        report += "\nNew Certificates (Last 72 Hours):\n"
        max_cert_domain = max([len(cert['domain']) for cert in certificates] + [6]) if certificates else 6
        max_issuer = max([len(cert['issuer']) for cert in certificates] + [6]) if certificates else 6
        max_issued = max([len(cert['issued']) for cert in certificates] + [6]) if certificates else 6
        max_id = max([len(str(cert['id'])) for cert in certificates] + [2]) if certificates else 2
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
    report += f"- Total subdomains found: {total_subdomains}\n"
    report += f"- Live subdomains (Lander Found): {live_count}\n"
    report += f"- Spoofable subdomains: {spoofable_count}\n"
    report += f"- Subdomains pointing to AWS: {aws_count}\n"
    report += f"- Subdomains with IIS default page: {iis_count}\n"
    report += f"- Subdomains with port 25 open: {port_25_open}\n"
    report += f"- Total new certificates: {total_new_certs}\n"
    report += f"- Report generated: {timestamp}\n"

    return report, csv_file

def cleanup_intermediate_files(domains):
    patterns = [
        "*.txt",
        "*.json"
    ]
    for domain in domains:
        patterns.extend([
            f"{domain}.txt",
            f"{domain}-200.txt",
            f"{domain}-other.txt",
            f"{domain}_certs.txt",
            f"{domain}_prev.txt",
            f"{domain}_certs_prev.txt"
        ])
    for pattern in patterns:
        files = glob.glob(os.path.join(OUTPUT_DIR, pattern))
        for file in files:
            if "combined_report" not in file:  # Preserve final report files
                try:
                    os.remove(file)
                    logger.info(f"Deleted intermediate file: {file}")
                except Exception as error:
                    logger.error(f"Failed to delete {file}: {error}")

def process_domain(domain, ipv4_ranges, ipv6_ranges):
    domain = domain.strip()
    if not domain:
        return None

    logger.info(f"Scanning {domain}")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Subdomain enumeration
    try:
        subdomains = sublist3r.main(
            domain,
            threads=10,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines="google,bing,yahoo,virustotal,netcraft,ssl"
        )
    except Exception as error:
        logger.error(f"Sublist3r error for {domain}: {error}")
        subdomains = []

    if not subdomains:
        logger.info(f"Falling back to DNS enumeration for {domain}")
        common_subs = [
            'www', 'mail', 'api', 'dev', 'staging', 'test', 'shop', 'crm', 'vpn', 'blog',
            'app', 'portal', 'secure', 'admin', 'login', 'webmail', 'ftp', 'smtp', 'pop',
            'imap', 'm', 'mobile', 'stage', 'prod', 'qa', 'demo', 'support', 'help'
        ]
        subdomains = []
        resolver = dns.resolver.Resolver()
        for sub in common_subs:
            try:
                answers = resolver.resolve(f"{sub}.{domain}", 'A')
                subdomains.append(f"{sub}.{domain}")
            except Exception:
                try:
                    answers = resolver.resolve(f"{sub}.{domain}", 'CNAME')
                    subdomains.append(f"{sub}.{domain}")
                except Exception:
                    pass

    cnt = Counter(subdomains)
    logger.info(f"Found {len(cnt)} subdomains for {domain}")
    subdomain_file = os.path.join(OUTPUT_DIR, f"{domain}.txt")
    with open(subdomain_file, 'w') as file:
        for subdomain in cnt:
            file.write(f"{subdomain}\n")

    urls = []
    for subdomain in cnt:
        urls.append(f"https://{subdomain}")
        urls.append(f"http://{subdomain}")

    with open(os.path.join(OUTPUT_DIR, f"{domain}-200.txt"), 'w') as file:
        file.write("")
    with open(os.path.join(OUTPUT_DIR, f"{domain}-other.txt"), 'w') as file:
        file.write("")

    prev_file = os.path.join(OUTPUT_DIR, f"{domain}_prev.txt")
    new_subdomains = []
    if os.path.exists(prev_file):
        with open(prev_file, 'r') as file:
            prev_domains = set(file.read().splitlines())
        with open(subdomain_file, 'r') as file:
            current_domains = set(file.read().splitlines())
        new_subdomains = list(current_domains - prev_domains)
        if new_subdomains:
            logger.info(f"New subdomains found for {domain}: {new_subdomains}")
        else:
            logger.info(f"No new subdomains found for {domain}")
    else:
        new_subdomains = list(cnt.keys())

    new_urls = [f"https://{sub}" for sub in new_subdomains] + [f"http://{sub}" for sub in new_subdomains]
    results = asyncio.run(make_requests(domain, new_urls))

    os.replace(subdomain_file, prev_file)

    subdomain_data = []
    for sub in new_subdomains:
        records = get_dns_records(sub)
        spoofable_service = check_spoofable(sub)
        aws = is_aws(sub, records, ipv4_ranges, ipv6_ranges)
        port_status = check_port_25(sub)
        
        lander_status = "Not Found"
        final_url = "Unknown"
        iis_page = "No"
        error = ""
        
        for url, status, response_text, headers in results:
            if sub in url:
                if status == 200:
                    final_url = url
                    if "/lander" in response_text.lower() or "/lander" in url.lower():
                        lander_status = "Found"
                    iis_page = check_iis_page(response_text, headers)
                elif status == 500:
                    error = f"Request failed for {url}"
                else:
                    error = f"HTTP {status} for {url}"
                break

        subdomain_data.append({
            'name': sub,
            'A': records['A'],
            'CNAME': records['CNAME'],
            'MX': records['MX'],
            'spoofable_service': spoofable_service,
            'aws': aws,
            'lander_status': lander_status,
            'final_url': final_url,
            'port_status': port_status,
            'iis_page': iis_page,
            'error': error
        })

    certificates = check_new_certificates(domain)

    return {
        'domain': domain,
        'subdomains': subdomain_data,
        'certificates': certificates
    }

def main():
    parser = argparse.ArgumentParser(description="Comprehensive domain and subdomain scanner")
    parser.add_argument('--domain-file', type=str, default="/opt/domain_scanner/domains.txt", help="Path to file containing domains, one per line")
    args = parser.parse_args()

    if not os.path.exists(args.domain_file):
        logger.error(f"Domain file {args.domain_file} not found")
        sys.exit(1)

    try:
        with open(args.domain_file, 'r') as file:
            domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except Exception as error:
        logger.error(f"Error reading domain file {args.domain_file}: {error}")
        sys.exit(1)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    ipv4_ranges, ipv6_ranges = load_aws_ranges()

    all_domain_data = []
    for domain in domains:
        print(f"\n[!] Scanning {domain}")
        domain_data = process_domain(domain, ipv4_ranges, ipv6_ranges)
        if domain_data:
            all_domain_data.append(domain_data)

    timestamp = datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
    report, csv_file = generate_combined_report(all_domain_data, timestamp)
    txt_file = os.path.join(OUTPUT_DIR, f"combined_report_{timestamp.replace(' ', '')}.txt")
    with open(txt_file, 'w') as file:
        file.write(report)

    # Clean up all intermediate files, keeping only the final report
    cleanup_intermediate_files(domains)

    if any(data['subdomains'] or data['certificates'] for data in all_domain_data):
        email_body = f"Combined Security Report - {timestamp}\n\nPlease see the attached CSV file (combined_report.csv) for the detailed report.\nThe plain text file is also attached (combined_report.txt) for reference.\n"
        attachments = [csv_file, txt_file]
        send_email(f"Combined Security Report - {timestamp}", email_body, attachments)
    else:
        logger.info("No new findings across all domains")

if __name__ == "__main__":
    main()
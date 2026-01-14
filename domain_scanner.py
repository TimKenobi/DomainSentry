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
import schedule
import signal
import subprocess

try:
    import colorama
    colorama.init()
except ImportError:
    print("[!] Warning: colorama not installed, console output will not be colored")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration - use environment variables for sensitive settings
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", os.path.join(SCRIPT_DIR, "output"))
AWS_RANGES_FILE = os.path.join(OUTPUT_DIR, 'aws_ip_ranges.json')
AWS_RANGES_CACHE_DAYS = 1
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
LOG_FILE = os.path.join(OUTPUT_DIR, "log.txt")

# Email configuration - set via environment variable (comma-separated)
EMAIL_RECIPIENTS = [e.strip() for e in os.getenv("EMAIL_RECIPIENTS", "").split(",") if e.strip()]
EMAIL_FROM = os.getenv("EMAIL_FROM", "domainsentry@example.com")

# ============= CLOUD PROVIDER PATTERNS FOR SUBDOMAIN TAKEOVER DETECTION =============
# These CNAME patterns indicate cloud services that may be vulnerable to takeover
VULNERABLE_CNAME_PATTERNS = {
    # Azure
    'azurewebsites.net': 'Azure App Service',
    'cloudapp.azure.com': 'Azure Cloud App',
    'azure-api.net': 'Azure API Management',
    'azurefd.net': 'Azure Front Door',
    'blob.core.windows.net': 'Azure Blob Storage',
    'cloudapp.net': 'Azure Cloud Service',
    'azureedge.net': 'Azure CDN',
    'trafficmanager.net': 'Azure Traffic Manager',
    # AWS
    's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3 Website',
    'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
    'cloudfront.net': 'AWS CloudFront',
    'elb.amazonaws.com': 'AWS ELB',
    'alb.amazonaws.com': 'AWS ALB',
    'execute-api': 'AWS API Gateway',
    'amazonaws.com': 'AWS',
    # Platform Services
    'herokuapp.com': 'Heroku',
    'herokudns.com': 'Heroku',
    'github.io': 'GitHub Pages',
    'gitbook.io': 'GitBook',
    'ghost.io': 'Ghost',
    'pantheonsite.io': 'Pantheon',
    'zendesk.com': 'Zendesk',
    'shopify.com': 'Shopify',
    'fastly.net': 'Fastly',
    'helpjuice.com': 'Helpjuice',
    'helpscoutdocs.com': 'HelpScout',
    'cargo.site': 'Cargo',
    'statuspage.io': 'Statuspage',
    'tumblr.com': 'Tumblr',
    'wpengine.com': 'WP Engine',
    'desk.com': 'Desk.com',
    'readme.io': 'ReadMe',
    'bitbucket.io': 'Bitbucket',
    # Modern Platforms
    'netlify.app': 'Netlify',
    'netlify.com': 'Netlify',
    'vercel.app': 'Vercel',
    'now.sh': 'Vercel',
    'surge.sh': 'Surge',
    'unbouncepages.com': 'Unbounce',
    'cargocollective.com': 'Cargo Collective',
    'fly.dev': 'Fly.io',
    'render.com': 'Render',
    'onrender.com': 'Render',
    'pages.dev': 'Cloudflare Pages',
    'workers.dev': 'Cloudflare Workers',
}

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
    records = {'A': [], 'CNAME': [], 'MX': [], 'NS': [], 'TXT': []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
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
    try:
        answers = resolver.resolve(subdomain, 'NS')
        records['NS'] = [str(rdata) for rdata in answers]
    except Exception:
        pass
    try:
        answers = resolver.resolve(subdomain, 'TXT')
        records['TXT'] = [str(rdata) for rdata in answers]
    except Exception:
        pass
    return records

# ============= DANGLING DNS DETECTION =============

def get_cname_via_dig(subdomain):
    """Use dig command to get CNAME record, works even for dangling records"""
    try:
        result = subprocess.run(
            ['dig', '+short', 'CNAME', subdomain],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip()
        if cname and not cname.startswith(';'):
            return cname.rstrip('.')
        return None
    except Exception:
        return None

def check_cname_resolves(cname_target):
    """Check if a CNAME target resolves to an IP address"""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    try:
        answers = resolver.resolve(cname_target.rstrip('.'), 'A')
        return True, [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return False, []
    except dns.resolver.NoAnswer:
        # Has DNS but no A record - might have other records
        return True, []
    except dns.resolver.NoNameservers:
        return False, []
    except Exception:
        return False, []

def identify_cloud_provider(cname_target):
    """Identify which cloud provider a CNAME points to"""
    cname_lower = cname_target.lower()
    for pattern, provider in VULNERABLE_CNAME_PATTERNS.items():
        if pattern in cname_lower:
            return provider
    return None

def check_dangling_cname(subdomain):
    """
    Check if a subdomain has a dangling CNAME record.
    Returns: (is_dangling, cname_target, provider, status)
    """
    cname_target = get_cname_via_dig(subdomain)
    
    if not cname_target:
        return False, None, None, "No CNAME"
    
    provider = identify_cloud_provider(cname_target)
    resolves, ips = check_cname_resolves(cname_target)
    
    if not resolves:
        severity = "CRITICAL" if provider else "HIGH"
        return True, cname_target, provider, f"{severity} - Dangling CNAME (target does not resolve)"
    
    # CNAME resolves - check for known takeover patterns
    if provider:
        # Even if it resolves, cloud CNAMEs should be monitored
        return False, cname_target, provider, f"INFO - Cloud Provider ({provider})"
    
    return False, cname_target, None, "OK - CNAME resolves"

def check_orphaned_ip(ip_address):
    """
    Check if an IP address appears to be orphaned/unresponsive.
    Returns: (is_orphaned, status)
    """
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return False, "Private IP"
        if ip_obj.is_reserved:
            return False, "Reserved IP"
    except ValueError:
        return False, "Invalid IP"
    
    # Try to connect on common ports
    for port in [80, 443]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result == 0:
                return False, "Responsive"
        except Exception:
            pass
    
    return True, "Unresponsive (ports 80/443 closed)"

def check_dns_health(subdomain, records):
    """
    Comprehensive DNS health check for a subdomain.
    Returns: (dns_status, details_dict)
    """
    details = {
        'dangling_cname': False,
        'cname_target': None,
        'cloud_provider': None,
        'orphaned_ips': [],
        'status': 'OK',
        'severity': 'INFO'
    }
    
    # Check for dangling CNAME
    is_dangling, cname_target, provider, cname_status = check_dangling_cname(subdomain)
    
    if is_dangling:
        details['dangling_cname'] = True
        details['cname_target'] = cname_target
        details['cloud_provider'] = provider or 'Unknown'
        details['status'] = cname_status
        details['severity'] = 'CRITICAL' if provider else 'HIGH'
        return details
    
    if cname_target:
        details['cname_target'] = cname_target
        details['cloud_provider'] = provider
        details['status'] = cname_status
    
    # Check for orphaned A records (only if no CNAME)
    if records.get('A') and not records.get('CNAME'):
        orphaned = []
        for ip in records['A']:
            is_orphaned, ip_status = check_orphaned_ip(ip)
            if is_orphaned:
                orphaned.append(f"{ip} ({ip_status})")
        
        if orphaned:
            details['orphaned_ips'] = orphaned
            details['status'] = f"WARNING - Unresponsive IPs: {', '.join(orphaned)}"
            details['severity'] = 'MEDIUM'
    
    return details

def check_spoofable(subdomain):
    """Enhanced spoofable check using expanded cloud provider patterns"""
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).lower()
            provider = identify_cloud_provider(cname)
            if provider:
                return f"{provider} (CNAME: {cname})"
    except Exception:
        pass
    
    # Also check via dig for dangling CNAMEs
    cname = get_cname_via_dig(subdomain)
    if cname:
        provider = identify_cloud_provider(cname)
        if provider:
            return f"{provider} (CNAME: {cname})"
    
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
    if not EMAIL_RECIPIENTS:
        logger.warning("No email recipients configured - skipping email")
        return
    
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
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
    report = f"Website, DNS, and Certificate Combined Security Report - {timestamp}\n"
    report += "=" * 80 + "\n\n"
    report += """SECURITY NOTES:
- Spoofable: Subdomains with CNAME records pointing to third-party cloud services
- Dangling CNAME: CNAME points to a target that no longer exists (CRITICAL vulnerability)
- DNS Health: Overall DNS configuration status for the subdomain
- Cloud Provider: Identified cloud service provider from CNAME target

SEVERITY LEVELS:
- CRITICAL: Dangling CNAME to known cloud provider - immediate takeover risk
- HIGH: Dangling CNAME to unknown provider - potential takeover risk
- MEDIUM: Unresponsive IP addresses - may indicate orphaned resources
- WARNING: Cloud provider CNAME - should be monitored
- INFO/OK: Normal configuration

"""
    
    total_subdomains = 0
    total_new_certs = 0
    spoofable_count = 0
    aws_count = 0
    live_count = 0
    iis_count = 0
    port_25_open = 0
    dangling_cname_count = 0
    orphaned_ip_count = 0
    cloud_provider_count = 0

    # Collect all DNS vulnerabilities for a separate section
    dns_vulnerabilities = []

    csv_file = os.path.join(OUTPUT_DIR, f"combined_report_{timestamp.replace(' ', '_').replace(':', '-')}.csv")
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Domain", "Subdomain", "A Records", "CNAME", "MX Records", "Spoofable", 
                        "DNS Health", "Cloud Provider", "CNAME Target", "Lander", "Final URL", 
                        "Port 25", "IIS Page", "Errors"])
        
        for domain_data in all_domain_data:
            domain = domain_data['domain']
            subdomains = domain_data['subdomains']
            for sub in subdomains:
                a_records = ", ".join(sub['A']) if sub['A'] else "None"
                cname = ", ".join(sub['CNAME']) if sub['CNAME'] else "None"
                mx_records = ", ".join(sub['MX']) if sub['MX'] else "None"
                spoofable = sub['spoofable_service'] if sub['spoofable_service'] else "No"
                dns_health = sub.get('dns_health', {}).get('status', 'Unknown')
                cloud_provider = sub.get('dns_health', {}).get('cloud_provider', '') or ''
                cname_target = sub.get('dns_health', {}).get('cname_target', '') or ''
                lander = sub['lander_status'] if sub['lander_status'] else "Not Found"
                final_url = sub['final_url'] if sub['final_url'] else "Unknown"
                port_status = sub['port_status'] if sub['port_status'] else "Unknown"
                iis_page = sub['iis_page'] if sub['iis_page'] else "No"
                error = sub['error'] if sub['error'] else ""
                
                writer.writerow([domain, sub['name'], a_records, cname, mx_records, spoofable,
                               dns_health, cloud_provider, cname_target, lander, final_url, 
                               port_status, iis_page, error])
        
        writer.writerow([])
        writer.writerow(["Domain", "Certificate Domain", "Issuer", "Issued", "ID"])
        for domain_data in all_domain_data:
            domain = domain_data['domain']
            certificates = domain_data['certificates']
            for cert in certificates:
                writer.writerow([domain, cert['domain'], cert['issuer'], cert['issued'], cert['id']])

    # Generate text report
    for domain_data in all_domain_data:
        domain = domain_data['domain']
        subdomains = domain_data['subdomains']
        certificates = domain_data['certificates']

        report += f"Domain: {domain}\n"
        report += "-" * 50 + "\n\n"
        
        # Check for DNS vulnerabilities in this domain
        domain_vulns = []
        for sub in subdomains:
            dns_health = sub.get('dns_health', {})
            if dns_health.get('dangling_cname') or dns_health.get('orphaned_ips'):
                domain_vulns.append(sub)
                dns_vulnerabilities.append({
                    'domain': domain,
                    'subdomain': sub['name'],
                    'details': dns_health
                })
        
        if domain_vulns:
            report += "⚠️  DNS VULNERABILITIES DETECTED:\n"
            for sub in domain_vulns:
                dns_health = sub.get('dns_health', {})
                severity = dns_health.get('severity', 'UNKNOWN')
                status = dns_health.get('status', 'Unknown')
                report += f"  [{severity}] {sub['name']}: {status}\n"
                if dns_health.get('cname_target'):
                    report += f"           CNAME Target: {dns_health['cname_target']}\n"
                if dns_health.get('cloud_provider'):
                    report += f"           Cloud Provider: {dns_health['cloud_provider']}\n"
            report += "\n"
        
        report += "Subdomains:\n"
        if subdomains:
            for sub in subdomains:
                total_subdomains += 1
                a_records = ", ".join(sub['A']) if sub['A'] else "None"
                cname = ", ".join(sub['CNAME']) if sub['CNAME'] else "None"
                spoofable = sub['spoofable_service'] if sub['spoofable_service'] else "No"
                dns_status = sub.get('dns_health', {}).get('status', 'Unknown')
                
                report += f"  {sub['name']}\n"
                report += f"    A Records: {a_records}\n"
                report += f"    CNAME: {cname}\n"
                report += f"    DNS Health: {dns_status}\n"
                if sub['spoofable_service']:
                    report += f"    Spoofable: {spoofable}\n"
                    spoofable_count += 1
                if sub['aws']:
                    aws_count += 1
                if sub['lander_status'] == "Found":
                    live_count += 1
                if sub['iis_page'] == "Yes":
                    iis_count += 1
                if sub['port_status'] == "Open":
                    port_25_open += 1
                if sub.get('dns_health', {}).get('dangling_cname'):
                    dangling_cname_count += 1
                if sub.get('dns_health', {}).get('orphaned_ips'):
                    orphaned_ip_count += 1
                if sub.get('dns_health', {}).get('cloud_provider'):
                    cloud_provider_count += 1
                report += "\n"
        else:
            report += "  None found\n\n"

        report += "New Certificates (Last 72 Hours):\n"
        if certificates:
            for cert in certificates:
                report += f"  {cert['domain']} - Issuer: {cert['issuer']}, Issued: {cert['issued']}\n"
                total_new_certs += 1
        else:
            report += "  None\n"
        report += "\n"

    # DNS Vulnerabilities Summary Section
    if dns_vulnerabilities:
        report += "\n" + "=" * 80 + "\n"
        report += "🚨 DNS VULNERABILITIES SUMMARY\n"
        report += "=" * 80 + "\n\n"
        
        critical = [v for v in dns_vulnerabilities if v['details'].get('severity') == 'CRITICAL']
        high = [v for v in dns_vulnerabilities if v['details'].get('severity') == 'HIGH']
        medium = [v for v in dns_vulnerabilities if v['details'].get('severity') == 'MEDIUM']
        
        if critical:
            report += "CRITICAL (Immediate Action Required):\n"
            for v in critical:
                report += f"  • {v['subdomain']}\n"
                report += f"    Status: {v['details'].get('status')}\n"
                report += f"    CNAME Target: {v['details'].get('cname_target')}\n"
                report += f"    Cloud Provider: {v['details'].get('cloud_provider')}\n"
                report += f"    Action: Remove dangling CNAME or reclaim cloud resource\n\n"
        
        if high:
            report += "HIGH (Action Recommended):\n"
            for v in high:
                report += f"  • {v['subdomain']}\n"
                report += f"    Status: {v['details'].get('status')}\n"
                report += f"    CNAME Target: {v['details'].get('cname_target')}\n\n"
        
        if medium:
            report += "MEDIUM (Review Recommended):\n"
            for v in medium:
                report += f"  • {v['subdomain']}\n"
                report += f"    Status: {v['details'].get('status')}\n"
                if v['details'].get('orphaned_ips'):
                    report += f"    Orphaned IPs: {', '.join(v['details']['orphaned_ips'])}\n\n"

    report += "\n" + "=" * 80 + "\n"
    report += "SUMMARY\n"
    report += "=" * 80 + "\n"
    report += f"- Total domains scanned: {len(all_domain_data)}\n"
    report += f"- Total subdomains found: {total_subdomains}\n"
    report += f"- Live subdomains (Lander Found): {live_count}\n"
    report += f"- Spoofable subdomains: {spoofable_count}\n"
    report += f"- Subdomains pointing to AWS: {aws_count}\n"
    report += f"- Subdomains with cloud provider CNAMEs: {cloud_provider_count}\n"
    report += f"- Dangling CNAME records (CRITICAL): {dangling_cname_count}\n"
    report += f"- Orphaned IP addresses: {orphaned_ip_count}\n"
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
            if "combined_report" not in file:
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
            'imap', 'm', 'mobile', 'stage', 'prod', 'qa', 'demo', 'support', 'help',
            'cdn', 'static', 'assets', 'images', 'img', 'media', 'video', 'docs',
            'wiki', 'status', 'monitor', 'metrics', 'grafana', 'kibana', 'elastic'
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
        
        # Enhanced DNS health check
        dns_health = check_dns_health(sub, records)
        
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
            'dns_health': dns_health,
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

def run_scan(domain_file):
    """Run a single scan of all domains"""
    logger.info("Starting scheduled domain scan...")

    if not os.path.exists(domain_file):
        logger.error(f"Domain file {domain_file} not found")
        return

    try:
        with open(domain_file, 'r') as file:
            domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except Exception as error:
        logger.error(f"Error reading domain file {domain_file}: {error}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    ipv4_ranges, ipv6_ranges = load_aws_ranges()

    all_domain_data = []
    for domain in domains:
        logger.info(f"Scanning {domain}")
        domain_data = process_domain(domain, ipv4_ranges, ipv6_ranges)
        if domain_data:
            all_domain_data.append(domain_data)

    timestamp = datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
    report, csv_file = generate_combined_report(all_domain_data, timestamp)
    txt_file = os.path.join(OUTPUT_DIR, f"combined_report_{timestamp.replace(' ', '')}.txt")
    with open(txt_file, 'w') as file:
        file.write(report)

    cleanup_intermediate_files(domains)

    if any(data['subdomains'] or data['certificates'] for data in all_domain_data):
        # Check for critical vulnerabilities
        critical_count = sum(1 for d in all_domain_data for s in d['subdomains'] 
                            if s.get('dns_health', {}).get('severity') == 'CRITICAL')
        
        if critical_count > 0:
            subject = f"🚨 CRITICAL: {critical_count} Dangling DNS Records Found - Security Report {timestamp}"
        else:
            subject = f"Website, DNS, and Certificate Combined Security Report - {timestamp}"
        
        email_body = f"""Website, DNS, and Certificate Combined Security Report - {timestamp}

Please see the attached CSV file (combined_report.csv) for the detailed report.
The plain text file is also attached (combined_report.txt) for reference.

"""
        if critical_count > 0:
            email_body += f"""
⚠️  CRITICAL VULNERABILITIES DETECTED: {critical_count} dangling CNAME records found!

Dangling CNAME records point to cloud resources that no longer exist.
This allows attackers to claim those resources and serve malicious content
from your trusted domains.

IMMEDIATE ACTION REQUIRED: Review the attached report and either:
1. Remove the dangling DNS records
2. Reclaim the cloud resources they point to

"""
        attachments = [csv_file, txt_file]
        send_email(subject, email_body, attachments)
        logger.info("Email sent with scan results")
    else:
        logger.info("No new findings across all domains")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive domain and subdomain scanner")
    parser.add_argument('--domain-file', type=str, default="domains.txt", help="Path to file containing domains, one per line")
    parser.add_argument('--daemon', action='store_true', help="Run as daemon with monthly scheduled scans")
    parser.add_argument('--scan-day', type=int, default=1, help="Day of month to run scan (1-28)")
    parser.add_argument('--scan-time', type=str, default="09:00", help="Time to run monthly scan (HH:MM format, UTC)")
    args = parser.parse_args()

    if args.daemon:
        logger.info(f"Starting domain scanner in daemon mode. Monthly scan scheduled on day {args.scan_day} at {args.scan_time} UTC")
        
        def check_and_run():
            from datetime import datetime
            if datetime.now().day == args.scan_day:
                run_scan(args.domain_file)
        
        schedule.every().day.at(args.scan_time).do(check_and_run)
        
        if datetime.now().day == args.scan_day:
            logger.info("Running initial scan (scheduled day)...")
            run_scan(args.domain_file)
        else:
            logger.info(f"Daemon started. Next scan scheduled for day {args.scan_day} at {args.scan_time} UTC")        

        def signal_handler(signum, frame):
            logger.info("Received shutdown signal. Exiting gracefully...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        while True:
            schedule.run_pending()
            time.sleep(3600)
    else:
        run_scan(args.domain_file)

if __name__ == "__main__":
    main()

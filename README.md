# Domain Scanner - Docker Deployment

Comprehensive domain and subdomain security scanner with dangling DNS detection and email reporting.

## Features

### Subdomain Enumeration
- **Multiple discovery sources**: Google, Bing, Yahoo, VirusTotal, Netcraft, SSL certificates
- **DNS fallback**: Checks common subdomain patterns if sources fail
- **Persistent tracking**: Detects new subdomains since last scan

### DNS Security Analysis
- **Dangling CNAME Detection**: Identifies CNAMEs pointing to non-existent resources
- **Orphaned IP Detection**: Finds A records pointing to unresponsive hosts
- **Cloud Provider Identification**: 48+ patterns including:
  - AWS (S3, CloudFront, Elastic Beanstalk, ELB, API Gateway)
  - Azure (App Service, Blob Storage, CDN, Traffic Manager, Front Door)
  - Platform services (Heroku, GitHub Pages, Netlify, Vercel, Shopify, Zendesk)
  - Modern platforms (Cloudflare Pages/Workers, Fly.io, Render)

### Vulnerability Severity Levels
| Severity | Description |
|----------|-------------|
| CRITICAL | Dangling CNAME to known cloud provider - immediate takeover risk |
| HIGH | Dangling CNAME to unknown provider - potential takeover risk |
| MEDIUM | Unresponsive IP addresses - may indicate orphaned resources |
| INFO/OK | Normal configuration |

### Additional Checks
- **AWS hosting detection** via IP range matching
- **IIS default page detection** 
- **Port 25 (SMTP) status checking**
- **SSL certificate monitoring** (last 72 hours)
- **HTTP/HTTPS endpoint testing**

### Reporting
- **Monthly automated scans** on the 1st at 09:00 UTC (configurable)
- **Email reports** with CSV and text attachments
- **Critical vulnerability alerts** in email subject when dangling CNAMEs found
- **DNS Vulnerabilities Summary** section in reports

## Quick Start

### Build and run the container:
```bash
cd /opt/domain_scanner
sudo docker compose up -d
```

### View logs:
```bash
sudo docker compose logs -f
```

### Stop the container:
```bash
sudo docker compose down
```

### Rebuild after code changes:
```bash
sudo docker compose down
sudo docker compose build --no-cache
sudo docker compose up -d
```

## Configuration

### Change scan schedule:
Edit the Dockerfile CMD or docker-compose.yml:
```bash
# Run on the 15th of each month at 14:00 UTC
CMD ["python", "domain_scanner.py", "--daemon", "--scan-day", "15", "--scan-time", "14:00", "--domain-file", "/app/domains.txt"]
```

### Update domains:
Edit `domains.txt` and rebuild:
```bash
sudo docker compose down
sudo docker compose build
sudo docker compose up -d
```

### Update email recipients:
Edit `domain_scanner.py` and find the `EMAIL_RECIPIENTS` list:
```python
EMAIL_RECIPIENTS = [
    "tim.branson@stahls.com",
    "joseph.paul@stahls.com",
    "mike.karr@stahls.com",
]
```

## Manual Scan

Run a manual scan without waiting for schedule:
```bash
sudo docker exec domain_scanner python domain_scanner.py
```

## Output Files

All reports are saved to the `output/` directory:
- `combined_report_*.txt` - Text reports with vulnerability summary
- `combined_report_*.csv` - CSV reports with columns:
  - Domain, Subdomain, A Records, CNAME, MX Records
  - Spoofable, DNS Health, Cloud Provider, CNAME Target
  - Lander, Final URL, Port 25, IIS Page, Errors
- `log.txt` - Application logs

## CSV Report Columns

| Column | Description |
|--------|-------------|
| Domain | Parent domain |
| Subdomain | Discovered subdomain |
| A Records | IP addresses |
| CNAME | CNAME record target |
| MX Records | Mail exchange servers |
| Spoofable | Cloud service if takeover-vulnerable |
| DNS Health | OK, WARNING, HIGH, or CRITICAL status |
| Cloud Provider | Identified cloud service (AWS, Azure, etc.) |
| CNAME Target | Full CNAME target hostname |
| Lander | Whether /lander path was found |
| Final URL | Resolved URL after redirects |
| Port 25 | SMTP port status (Open/Closed) |
| IIS Page | Default IIS page detected |
| Errors | Any errors during scanning |

## How It Works

1. Container starts in daemon mode
2. Scheduler runs monthly scans on configured day/time
3. For each domain:
   - Enumerates subdomains using Sublist3r + DNS fallback
   - Gets DNS records (A, CNAME, MX, NS, TXT)
   - **Checks for dangling CNAMEs** using dig + resolution verification
   - **Identifies cloud providers** from CNAME patterns
   - **Detects orphaned IPs** by testing port 80/443 connectivity
   - Tests HTTP/HTTPS endpoints
   - Checks for IIS default pages
   - Monitors SSL certificates
4. Generates reports with vulnerability summary
5. Sends email with attachments (CRITICAL alert if dangling CNAMEs found)

## Email Alerts

When CRITICAL vulnerabilities are found, email subject includes:
```
🚨 CRITICAL: X Dangling DNS Records Found - Security Report
```

Email body explains:
- What dangling CNAME records are
- Why they're dangerous (subdomain takeover)
- Required actions (remove DNS or reclaim resource)

## Dependencies

- Python 3.11
- Sublist3r, dnspython, aiohttp, requests, schedule
- dnsutils (for dig command)
- Docker with compose

## Repository

https://gitea.stahlsitsec.local/bransont/domain_scanner

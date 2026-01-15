# DomainSentry 🛡️

Comprehensive domain and subdomain security scanner with dangling DNS detection, subdomain takeover vulnerability identification, and email alerting.

## Features

### 🔍 Subdomain Enumeration
- **Multiple discovery sources**: Google, Bing, Yahoo, VirusTotal, Netcraft, SSL certificates
- **DNS fallback**: Checks common subdomain patterns if sources fail
- **Persistent tracking**: Detects new subdomains since last scan

### 🚨 DNS Security Analysis
- **Dangling CNAME Detection**: Identifies CNAMEs pointing to non-existent resources
- **Orphaned IP Detection**: Finds A records pointing to unresponsive hosts
- **Cloud Provider Identification**: 48+ patterns including:
  - AWS (S3, CloudFront, Elastic Beanstalk, ELB, API Gateway)
  - Azure (App Service, Blob Storage, CDN, Traffic Manager, Front Door)
  - Platform services (Heroku, GitHub Pages, Netlify, Vercel, Shopify, Zendesk)
  - Modern platforms (Cloudflare Pages/Workers, Fly.io, Render)

### ⚠️ Vulnerability Severity Levels
| Severity | Description |
|----------|-------------|
| CRITICAL | Dangling CNAME to known cloud provider - immediate takeover risk |
| HIGH | Dangling CNAME to unknown provider - potential takeover risk |
| MEDIUM | Unresponsive IP addresses - may indicate orphaned resources |
| INFO/OK | Normal configuration |

### 📊 Additional Checks
- **AWS hosting detection** via IP range matching
- **IIS default page detection** 
- **Port 25 (SMTP) status checking**
- **SSL certificate monitoring** (last 72 hours via crt.sh)
- **HTTP/HTTPS endpoint testing**

### 📧 Reporting
- **Scheduled automated scans** (configurable day/time)
- **Email reports** with CSV and text attachments
- **Critical vulnerability alerts** in email subject when dangling CNAMEs found
- **DNS Vulnerabilities Summary** section in reports

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/TimKenobi/DomainSentry.git
cd DomainSentry
```

### 2. Create your configuration
```bash
# Copy the example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

### 3. Add your domains
```bash
# Edit domains.txt with your domains (one per line)
nano domains.txt
```

### 4. Run with Docker
```bash
# Build and start the container
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | `localhost` |
| `SMTP_PORT` | SMTP server port | `25` |
| `EMAIL_FROM` | Sender email address | `domainsentry@example.com` |
| `EMAIL_RECIPIENTS` | Comma-separated recipient emails | (empty) |
| `OUTPUT_DIR` | Output directory for reports | `./output` |
| `TZ` | Timezone | `UTC` |

### Scan Schedule

Modify the schedule in `docker-compose.yml` or via command line arguments:

```bash
# Run on the 15th of each month at 14:00 UTC
python domain_scanner.py --daemon --scan-day 15 --scan-time 14:00 --domain-file domains.txt
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--domain-file` | Path to domain list file | `domains.txt` |
| `--daemon` | Run as daemon with scheduled scans | false |
| `--scan-day` | Day of month for scheduled scan (1-28) | `1` |
| `--scan-time` | Time for scan in HH:MM format (UTC) | `09:00` |

## Manual Scan

Run a one-time scan without waiting for the schedule:

```bash
# With Docker
docker exec domainsentry python domain_scanner.py --domain-file /app/domains.txt

# Without Docker (in virtual environment)
python domain_scanner.py --domain-file domains.txt
```

## Output Files

Reports are saved to the `output/` directory:
- `combined_report_*.csv` - Detailed CSV report
- `combined_report_*.txt` - Text summary report
- `log.txt` - Application logs

## Domain File Format

Create a `domains.txt` file with one domain per line:

```
example.com
example.org
mycompany.com
```

Lines starting with `#` are treated as comments.

## Security Recommendations

When dangling CNAMEs are detected:

1. **Verify**: Confirm the subdomain is no longer needed
2. **Remove**: Delete the DNS record from your DNS provider
3. **Or Reclaim**: If still needed, reclaim the cloud resource
4. **Monitor**: Re-run DomainSentry to verify the fix

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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

https://github.com/TimKenobi/DomainSentry

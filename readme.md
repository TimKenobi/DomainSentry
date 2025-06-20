# DomainSentry

**DomainSentry** is a robust, Python-based security tool crafted to diligently monitor and analyze domains for a spectrum of potential security risks. It conducts thorough scans of domains and their associated subdomains, meticulously checking for:

-   Subdomain enumeration
-   Newly issued SSL/TLS certificates
-   HTTP/HTTPS status and landing pages
-   MX records for potential spoofing
-   Open SMTP ports (port 25)
-   Default IIS pages indicating misconfigurations

The tool culminates its analysis by generating comprehensive reports in both text and CSV formats. These reports are then automatically dispatched via email to a designated list of recipients, positioning DomainSentry as an indispensable asset for security teams tasked with overseeing domain configurations and preempting potential vulnerabilities.

----------

## ✨ Features

-   **Subdomain Enumeration**: Leverages `Sublist3r` to unearth subdomains through an array of search engines (including Google, Bing, and Yahoo), with a fallback to common subdomain checks for comprehensive discovery.
-   **Certificate Monitoring**: Diligently queries `crt.sh` to detect any new SSL/TLS certificates issued within the last 72 hours for each specified domain.
-   **HTTP/HTTPS Status Checks**: Systematically tests subdomains for both HTTP and HTTPS accessibility, adeptly identifying landing pages.
-   **DNS Record Analysis**: Retrieves A, CNAME, and MX records to pinpoint potentially spoofable services (e.g., AWS, Shopify) that could be susceptible to subdomain takeover.
-   **Port 25 Scanning**: Actively checks for open SMTP ports (port 25) on subdomains, flagging potential mail server exposure.
-   **IIS Detection**: Skillfully identifies subdomains that are serving default IIS pages, a common indicator of misconfigured servers.
-   **Automated Reporting**: Generates consolidated and easy-to-digest text and CSV reports that summarize all findings across the scanned domains.
-   **Email Notifications**: Seamlessly sends detailed reports to multiple email recipients via a pre-configured SMTP server.
-   **File Cleanup**: Intelligently removes all intermediate files, ensuring a clean operational environment by retaining only the final, crucial reports.
-   **Cron Support**: Designed for effortless scheduling as a monthly cron job, enabling fully automated and continuous monitoring.

----------

## ⚙️ How It Works

DomainSentry systematically processes a list of domains from a `domains.txt` file, executing the following sequence of actions for each domain:

1.  **Subdomain Discovery**: Initiates the process by enumerating subdomains using the power of `Sublist3r` and conducting DNS queries for a curated list of common subdomains (e.g., `www`, `mail`, `api`).
2.  **DNS Analysis**: Proceeds to retrieve A, CNAME, and MX records, meticulously checking for third-party services like AWS and Shopify that may be vulnerable to spoofing.
3.  **Certificate Checking**: Queries `crt.sh` to identify any certificates issued within the preceding 72 hours, thereby highlighting new or potentially unauthorized certificates.
4.  **HTTP/HTTPS Probes**: Conducts tests on each discovered subdomain over both HTTP and HTTPS, logging status codes and checking for the presence of landing pages or default IIS pages.
5.  **Port Scanning**: Performs a scan to determine if port 25 is open on subdomains, a key step in detecting exposed SMTP services.
6.  **AWS Detection**: Identifies if subdomains are pointing to AWS infrastructure through IP ranges or CNAMEs.
7.  **Reporting**: Generates a detailed and comprehensive report that summarizes all discovered subdomains, associated DNS records, certificate details, HTTP/HTTPS status, port status, and any IIS findings.
8.  **Email Delivery**: Dispatches the generated report to the configured recipients if any new findings, such as new subdomains or certificates, are detected.
9.  **Cleanup**: Concludes by deleting all intermediate files, ensuring that only the final text and CSV reports are retained.

The tool is optimized for execution within a Python virtual environment on an Ubuntu server and fully supports scheduling via cron for automated monthly scans.

----------

## 📋 Requirements

### Operating System

-   Ubuntu (tested on 22.04+)

### System Dependencies

-   `python3`
-   `python3-venv`
-   `python3-pip`
-   `dnsutils` (for `dig`)
-   `curl` (for HTTP checks)

### Python Dependencies

(as listed in `requirements.txt`)

-   `aiohttp==3.9.5`
-   `colorama==0.4.6`
-   `dnspython==2.6.1`
-   `requests==2.32.3`
-   `sublist3r==1.0`

### Network Access

-   Internet access for DNS queries, HTTP/HTTPS requests, and `crt.sh` API calls.
-   SMTP server access (e.g., `relay.yoursmtpserver.net:25`) for email notifications.

----------

## 🚀 Installation

1.  **Clone the Repository:**
    
    Bash
    
    ```
    git clone https://github.com/<your-username>/DomainSentry.git /opt/domain_scanner
    cd /opt/domain_scanner
    
    ```
    
2.  **Install System Dependencies:**
    
    Bash
    
    ```
    sudo apt-get update
    sudo apt-get install python3 python3-venv python3-pip dnsutils curl
    
    ```
    
3.  **Set Up a Virtual Environment:**
    
    Bash
    
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    deactivate
    
    ```
    
4.  **Configure Permissions:**
    
    Bash
    
    ```
    sudo chown $(whoami):$(whoami) /opt/domain_scanner -R
    sudo chmod -R u+rw /opt/domain_scanner
    
    ```
    
5.  Create a Domains File:
    
    Create /opt/domain_scanner/domains.txt with one domain per line:
    
    ```
    example.com
    yoursite.com
    
    ```
    
6.  Configure Email Recipients:
    
    Edit /opt/domain_scanner/domainsentry.py and update the EMAIL_RECIPIENTS list:
    
    Python
    
    ```
    EMAIL_RECIPIENTS = [
        "youremail@yourcompany.com",
        "another@example.com",
        "team@yourcompany.com"
    ]
    
    ```
    

----------

## ▶️ Usage

### Run Manually

Activate the virtual environment and execute the script:

Bash

```
source /opt/domainsentry/venv/bin/activate
python3 /opt/domainsentry/domainsentry.py
deactivate

```

The script will read domains from `/opt/domainsentry/domains.txt`, generate reports in `/opt/domainsentry/output/`, and email them if new findings are detected.

### Schedule as a Monthly Cron Job

1.  **Create a shell script to run the tool:**
    
    Bash
    
    ```
    nano /opt/domain_scanner/run_domainsentry.sh
    
    ```
    
    Add the following content:
    
    Bash
    
    ```
    #!/bin/bash
    source /opt/domain_scanner/venv/bin/activate
    python3 /opt/domain_scanner/domainsentry.py >> /opt/domain_scanner/output/cron.log 2>&1
    deactivate
    
    ```
    
2.  **Make it executable:**
    
    Bash
    
    ```
    chmod +x /opt/domain_scanner/run_domainsentry.sh
    
    ```
    
3.  **Schedule the cron job** to run on the 1st of each month at 2:00 AM:
    
    Bash
    
    ```
    crontab -e
    
    ```
    
    Add the following line:
    
    ```
    0 2 1 * * /bin/bash /opt/domain_scanner/run_domainsentry.sh
    
    ```
    

----------

## 📄 Output

-   **Reports**: Generated in `/opt/domainsentry/output/` as:
    -   `combined_report_<timestamp>.txt`: A text summary of the findings.
    -   `combined_report_<timestamp>.csv`: A detailed CSV report.
-   **Logs**: Errors and execution details are logged to `/opt/domainsentry/output/log.txt` and `/opt/domainsentry/output/cron.log` (for cron runs).
-   **Email**: Reports are emailed to the recipients listed in `EMAIL_RECIPIENTS` if new subdomains or certificates are found.

----------

## 🛠️ Troubleshooting

-   **Cron Job Issues**:
    -   Check cron logs: `grep CRON /var/log/syslog`
    -   Verify script output: `cat /opt/domain_scanner/output/cron.log`
-   **SMTP Errors**:
    -   Test SMTP connectivity: `nc -zv relay.yourcompany.net 25`
    -   Check `/opt/domainsentry/output/log.txt` for any email-related errors.
-   **Dependency Issues**:
    -   Ensure all dependencies are correctly installed within the virtual environment.
    -   Reinstall if necessary: `source /opt/domainsentry/venv/bin/activate && pip install -r requirements.txt`
-   **Permissions**:
    -   Verify directory permissions: `ls -ld /opt/domainsentry`
    -   Fix if needed: `sudo chown $(whoami):$(whoami) /opt/domainsentry -R`

----------

## 🤝 Contributing

Contributions are warmly welcomed! Please feel free to submit issues or pull requests to the GitHub repository. Kindly ensure that any changes are thoroughly tested in a virtual environment and maintain compatibility with Ubuntu.

----------

## 📜 License

This project is licensed under the MIT License. Please see the `LICENSE` file for more details.

----------

## ☕ Support the Project

If you find this tool helpful, consider buying me a coffee!
[![](data:image/png;base64,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) ](https://coff.ee/timkenobi)
----------

## 📧 Contact

For support or any questions, please open an issue on the GitHub repository or drop me a note at [My Website](https://pixelspacetech.com)
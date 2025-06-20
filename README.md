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
    git clone https://github.com/<your-username>/DomainSentry.git /opt/domainsentry
    cd /opt/domainsentry
    
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
    sudo chown $(whoami):$(whoami) /opt/domainsentry -R
    sudo chmod -R u+rw /opt/domainsentry
    
    ```
    
5.  Create a Domains File:
    
    Create /opt/domainsentry/domains.txt with one domain per line:
    
    ```
    example.com
    yoursite.com
    
    ```
    
6.  Configure Email Recipients:
    
    Edit /opt/domainsentry/domainsentry.py and update the EMAIL_RECIPIENTS list:
    
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
    nano /opt/domainsentry/run_domainsentry.sh
    
    ```
    
    Add the following content:
    
    Bash
    
    ```
    #!/bin/bash
    source /opt/domainsentry/venv/bin/activate
    python3 /opt/domainsentry/domainsentry.py >> /opt/domainsentry/output/cron.log 2>&1
    deactivate
    
    ```
    
2.  **Make it executable:**
    
    Bash
    
    ```
    chmod +x /opt/domainsentry/run_domainsentry.sh
    
    ```
    
3.  **Schedule the cron job** to run on the 1st of each month at 2:00 AM:
    
    Bash
    
    ```
    crontab -e
    
    ```
    
    Add the following line:
    
    ```
    0 2 1 * * /bin/bash /opt/domainsentry/run_domainsentry.sh
    
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
    -   Verify script output: `cat /opt/domainsentry/output/cron.log`
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
[![image](https://github.com/user-attachments/assets/bcd2f077-633c-4bd9-9c7c-e5861e3d887f)
](https://coff.ee/timkenobi)
----------

## 📧 Contact

For support or any questions, please open an issue on the GitHub repository or drop me a note at [My Website](https://pixelspacetech.com)# DomainSentry

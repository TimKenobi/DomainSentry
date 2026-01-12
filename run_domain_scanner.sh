#!/bin/bash
source /opt/domain_scanner/venv/bin/activate
python3 /opt/domain_scanner/domain_scanner.py >> /opt/domain_scanner/output/cron.log 2>&1
deactivate

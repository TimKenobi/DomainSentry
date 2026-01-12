FROM python:3.11-slim

# Install system dependencies including dnsutils for dig command
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY domain_scanner.py .
COPY domains.txt .

# Create output directory
RUN mkdir -p output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Run the application in daemon mode with monthly schedule
CMD ["python", "domain_scanner.py", "--daemon", "--scan-day", "1", "--scan-time", "09:00", "--domain-file", "/app/domains.txt"]

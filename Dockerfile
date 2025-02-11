FROM python:3.13.2-slim

EXPOSE 9999

# Install system dependencies
RUN apt-get update \
    && apt-get install -y \
    curl \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Rust and Cargo using curl with IPv4 only
RUN CURL_IPRESOLVE=4 curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /usr/src/app

# Set PYTHONPATH to include /usr/src/app
ENV PYTHONPATH=/usr/src/app

# Copy the zerto exporter into the container
COPY app /usr/src/app/

# Delete uuid.txt file if it exists
RUN [ -f uuid.txt ] && rm uuid.txt || echo "No uuid.txt file to delete"

# Install Python dependencies
# Set environment variable for PyO3 compatibility
ENV PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Entry point for the container
CMD ["python", "python-node-exporter.py"]

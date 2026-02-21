FROM python:3.14.3-slim

EXPOSE 9999

# Install system dependencies
RUN apt-get update \
    && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /usr/src/app

# Set PYTHONPATH to include /usr/src/app
ENV PYTHONPATH=/usr/src/app
# Disable stdout buffering so logs appear immediately in the container console
ENV PYTHONUNBUFFERED=1

# Copy the zerto exporter into the container
COPY app /usr/src/app/

# Delete uuid.txt file if it exists
RUN [ -f uuid.txt ] && rm uuid.txt || echo "No uuid.txt file to delete"

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Entry point for the container
CMD ["python", "python-node-exporter.py"]

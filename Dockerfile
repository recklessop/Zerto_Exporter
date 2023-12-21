FROM python:3.12-slim

EXPOSE 9999

WORKDIR /usr/src/app

# Set PYTHONPATH to include /usr/src/app
ENV PYTHONPATH=/usr/src/app

# Copy the zerto exporter into the container
COPY app /usr/src/app/

# Delete uuid.txt file if it exists
RUN [ -f uuid.txt ] && rm uuid.txt || echo "No uuid.txt file to delete"

RUN pip install --no-cache-dir -r requirements.txt

# Entry point for the container
CMD ["python", "python-node-exporter.py"]
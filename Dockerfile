FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY wp_migration_common.py .
COPY finder.py .
COPY ffufinder.py .

# Make scripts executable
RUN chmod +x finder.py ffufinder.py

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default to finder.py, but allow override
ENTRYPOINT ["python3", "finder.py", "-u"]

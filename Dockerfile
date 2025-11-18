# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Make entrypoint script executable
RUN chmod +x docker-entrypoint.sh

# Create necessary directories
RUN mkdir -p instance flask_session emails

# Set environment variables
ENV FLASK_ENV=development
ENV PYTHONPATH=/app

# Expose the port the app runs on
EXPOSE 5001

# Create a non-root user for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Run the application using entrypoint script
CMD ["./docker-entrypoint.sh"]
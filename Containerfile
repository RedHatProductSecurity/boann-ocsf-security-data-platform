FROM python:3.12-slim

WORKDIR /app

# Copy requirements files
COPY requirements.txt .

# Install system dependencies and Python packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash boann \
    && chown -R boann:boann /app

# Copy application files
COPY --chown=boann:boann scripts ./scripts/
COPY --chown=boann:boann docs ./docs/
COPY --chown=boann:boann dbt_project ./dbt_project/

# Switch to non-root user
USER boann

# Set Python path to find modules
ENV PYTHONPATH=/app
ENV DBT_PROFILES_DIR=/app/dbt_project

# Keep container running for development
CMD ["tail", "-f", "/dev/null"]


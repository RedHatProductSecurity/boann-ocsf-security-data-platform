#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE_PATH="$PROJECT_ROOT/.env"
COMPOSE_FILE_PATH="$PROJECT_ROOT/podman-compose.yaml"

echo "Script directory: $SCRIPT_DIR"
echo "Project root directory: $PROJECT_ROOT"
echo "Looking for .env at: $ENV_FILE_PATH"
echo "Looking for podman-compose.yaml at: $COMPOSE_FILE_PATH"

if [ -f "$ENV_FILE_PATH" ]; then
    source "$ENV_FILE_PATH"
else
    echo "Error: .env file not found at '$ENV_FILE_PATH'!"
    echo "Please ensure .env is in the project root: $PROJECT_ROOT"
    echo "You can copy .env.example to .env and modify the values as needed."
    exit 1
fi

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not found in '$ENV_FILE_PATH'!"
    exit 1
fi

echo "Parsing DATABASE_URL: $DATABASE_URL"

URL_NO_PREFIX=$(echo "$DATABASE_URL" | sed 's/^postgresql:\/\///')

AUTH_PART=$(echo "$URL_NO_PREFIX" | cut -d'@' -f1)
export POSTGRES_USER=$(echo "$AUTH_PART" | cut -d':' -f1)
export POSTGRES_PASSWORD=$(echo "$AUTH_PART" | cut -d':' -f2)

HOST_PORT_DB_PART=$(echo "$URL_NO_PREFIX" | cut -d'@' -f2)

HOST_PORT=$(echo "$HOST_PORT_DB_PART" | cut -d'/' -f1)
export POSTGRES_HOST=$(echo "$HOST_PORT" | cut -d':' -f1)
export POSTGRES_PORT=$(echo "$HOST_PORT" | cut -d':' -f2)

export POSTGRES_DB=$(echo "$HOST_PORT_DB_PART" | cut -d'/' -f2)

echo "Extracted Variables:"
echo "  POSTGRES_USER: $POSTGRES_USER"
echo "  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:0:3}..." # Mask password for display
echo "  POSTGRES_HOST: $POSTGRES_HOST"
echo "  POSTGRES_PORT: $POSTGRES_PORT"
echo "  POSTGRES_DB: $POSTGRES_DB"

echo "Changing directory to project root: $PROJECT_ROOT"
cd "$PROJECT_ROOT" || { echo "Failed to change directory to $PROJECT_ROOT"; exit 1; }

echo "Building and starting containers..."
podman-compose -f "$COMPOSE_FILE_PATH" up -d --build

echo "Podman Compose command finished."
echo ""

# Wait for containers to be fully ready
echo "Waiting for containers to be ready..."
sleep 3

# Run dbt setup to create database schema
echo ""
echo "Setting up database schema using dbt..."
podman exec -it boann-app bash -c "cd /app/dbt_project && dbt deps && dbt run"

echo ""
echo "================================"
echo "✅ Environment is ready!"
echo "================================"
echo ""
echo "Database schemas created:"
echo "  - boann_landing.raw_ocsf_findings (landing table for raw OCSF JSON)"
echo "  - boann_staging.stg_ocsf_findings (staging table with extracted fields)"
echo ""
echo "You can:"
echo "  - Connect to PostgreSQL: psql -h localhost -p 5432 -U $POSTGRES_USER -d $POSTGRES_DB"
echo "  - Execute commands in the app container: podman exec -it boann-app bash"
echo "  - View logs: podman-compose logs -f"
echo "  - Stop containers: podman-compose down"


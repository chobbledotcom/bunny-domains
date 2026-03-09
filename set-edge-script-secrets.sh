#!/usr/bin/env nix-shell
#!nix-shell -i bash -p curl jq openssl

# Script to manage secrets for Bunny CDN edge scripts (tickets-*)
# Uses .env file for API key and some secret values

set -euo pipefail

# Colors for nice output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Pretty print functions
print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${CYAN}→${NC} $1"
}

print_skip() {
    echo -e "  ${DIM}○${NC} $1"
}

print_step() {
    echo -e "${YELLOW}▶${NC} $1"
}

# Load environment variables
if [[ ! -f "$ENV_FILE" ]]; then
    print_header "Configuration Error"
    print_error ".env file not found at $ENV_FILE"
    echo ""
    echo "  Please create a .env file with:"
    echo -e "    ${CYAN}BUNNY_API_KEY=your_api_key${NC}"
    echo -e "    ${CYAN}WEBHOOK_URL=...${NC}"
    echo -e "    ${CYAN}STORAGE_ZONE_NAME=...${NC}"
    echo -e "    ${CYAN}STORAGE_ZONE_KEY=...${NC}"
    echo -e "    ${CYAN}HOST_EMAIL_PROVIDER=...${NC}"
    echo -e "    ${CYAN}HOST_EMAIL_API_KEY=...${NC}"
    echo -e "    ${CYAN}HOST_EMAIL_FROM_ADDRESS=...${NC}"
    echo ""
    exit 1
fi

source "$ENV_FILE"

if [[ -z "${BUNNY_API_KEY:-}" ]]; then
    print_header "Configuration Error"
    print_error "BUNNY_API_KEY not set in .env"
    exit 1
fi

API_BASE="https://api.bunny.net"

print_header "Bunny Edge Script Secrets Manager"

echo -e -n "  ${CYAN}→${NC} Enter edge script ID: "
read -r SCRIPT_ID

if ! [[ "$SCRIPT_ID" =~ ^[0-9]+$ ]]; then
    print_error "Invalid script ID"
    exit 1
fi

# Fetch existing secrets for this script
print_header "Checking Existing Secrets"

echo -e "  Edge Script ID: ${BOLD}${CYAN}$SCRIPT_ID${NC}"
echo ""

print_step "Fetching existing secrets..."

response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_BASE}/compute/script/${SCRIPT_ID}/secrets" \
    -H "AccessKey: ${BUNNY_API_KEY}" \
    -H "Accept: application/json")

http_code=$(echo "$response" | tail -n1)
secrets_body=$(echo "$response" | sed '$d')

if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    print_error "Failed to fetch secrets (HTTP $http_code)"
    echo "$secrets_body"
    exit 1
fi

# Build a list of existing secret names
existing_secrets=$(echo "$secrets_body" | jq -r '.Secrets[].Name // empty')

secret_exists() {
    local name="$1"
    echo "$existing_secrets" | grep -qx "$name"
}

# Function to set a secret via API
set_secret() {
    local name="$1"
    local value="$2"

    local payload
    payload=$(jq -n --arg n "$name" --arg s "$value" '{Name: $n, Secret: $s}')

    local response
    response=$(curl -s -w "\n%{http_code}" -X PUT \
        "${API_BASE}/compute/script/${SCRIPT_ID}/secrets" \
        -H "AccessKey: ${BUNNY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "$payload")

    local http_code
    http_code=$(echo "$response" | tail -n1)

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        print_success "${BOLD}$name${NC} set"
        return 0
    else
        local resp_body
        resp_body=$(echo "$response" | sed '$d')
        print_error "${BOLD}$name${NC} failed (HTTP $http_code)"
        echo -e "      ${RED}$resp_body${NC}"
        return 1
    fi
}

# Process each secret
print_header "Setting Secrets"

success_count=0
skip_count=0
fail_count=0

echo -e "  ${DIM}Existing secrets will be skipped (not overwritten).${NC}"
echo ""

# --- DB_URL: ask user ---
if secret_exists "DB_URL"; then
    print_skip "${BOLD}DB_URL${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    echo -e -n "  ${CYAN}→${NC} Enter ${BOLD}DB_URL${NC}: "
    read -r db_url
    if [[ -n "$db_url" ]]; then
        if set_secret "DB_URL" "$db_url"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    else
        print_error "DB_URL cannot be empty, skipping"
        fail_count=$((fail_count + 1))
    fi
fi

# --- DB_TOKEN: ask user ---
if secret_exists "DB_TOKEN"; then
    print_skip "${BOLD}DB_TOKEN${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    echo -e -n "  ${CYAN}→${NC} Enter ${BOLD}DB_TOKEN${NC}: "
    read -r db_token
    if [[ -n "$db_token" ]]; then
        if set_secret "DB_TOKEN" "$db_token"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    else
        print_error "DB_TOKEN cannot be empty, skipping"
        fail_count=$((fail_count + 1))
    fi
fi

# --- DB_ENCRYPTION_KEY: generate ---
if secret_exists "DB_ENCRYPTION_KEY"; then
    print_skip "${BOLD}DB_ENCRYPTION_KEY${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    encryption_key=$(openssl rand -base64 32)
    print_info "Generated ${BOLD}DB_ENCRYPTION_KEY${NC}: ${DIM}$encryption_key${NC}"
    if set_secret "DB_ENCRYPTION_KEY" "$encryption_key"; then
        success_count=$((success_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
fi

# --- NTFY_URL: read from .env ---
if secret_exists "NTFY_URL"; then
    print_skip "${BOLD}NTFY_URL${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${NTFY_URL:-}" ]]; then
        print_error "${BOLD}NTFY_URL${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}NTFY_URL${NC} from .env"
        if set_secret "NTFY_URL" "$NTFY_URL"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- ALLOWED_DOMAIN: ask user ---
if secret_exists "ALLOWED_DOMAIN"; then
    print_skip "${BOLD}ALLOWED_DOMAIN${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    echo -e -n "  ${CYAN}→${NC} Enter ${BOLD}ALLOWED_DOMAIN${NC}: "
    read -r allowed_domain
    if [[ -n "$allowed_domain" ]]; then
        if set_secret "ALLOWED_DOMAIN" "$allowed_domain"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    else
        print_error "ALLOWED_DOMAIN cannot be empty, skipping"
        fail_count=$((fail_count + 1))
    fi
fi

# --- WEBHOOK_URL: read from .env ---
if secret_exists "WEBHOOK_URL"; then
    print_skip "${BOLD}WEBHOOK_URL${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${WEBHOOK_URL:-}" ]]; then
        print_error "${BOLD}WEBHOOK_URL${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}WEBHOOK_URL${NC} from .env"
        if set_secret "WEBHOOK_URL" "$WEBHOOK_URL"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- STORAGE_ZONE_NAME: read from .env ---
if secret_exists "STORAGE_ZONE_NAME"; then
    print_skip "${BOLD}STORAGE_ZONE_NAME${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${STORAGE_ZONE_NAME:-}" ]]; then
        print_error "${BOLD}STORAGE_ZONE_NAME${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}STORAGE_ZONE_NAME${NC} from .env"
        if set_secret "STORAGE_ZONE_NAME" "$STORAGE_ZONE_NAME"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- STORAGE_ZONE_KEY: read from .env ---
if secret_exists "STORAGE_ZONE_KEY"; then
    print_skip "${BOLD}STORAGE_ZONE_KEY${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${STORAGE_ZONE_KEY:-}" ]]; then
        print_error "${BOLD}STORAGE_ZONE_KEY${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}STORAGE_ZONE_KEY${NC} from .env"
        if set_secret "STORAGE_ZONE_KEY" "$STORAGE_ZONE_KEY"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- HOST_EMAIL_PROVIDER: read from .env ---
if secret_exists "HOST_EMAIL_PROVIDER"; then
    print_skip "${BOLD}HOST_EMAIL_PROVIDER${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${HOST_EMAIL_PROVIDER:-}" ]]; then
        print_error "${BOLD}HOST_EMAIL_PROVIDER${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}HOST_EMAIL_PROVIDER${NC} from .env"
        if set_secret "HOST_EMAIL_PROVIDER" "$HOST_EMAIL_PROVIDER"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- HOST_EMAIL_API_KEY: read from .env ---
if secret_exists "HOST_EMAIL_API_KEY"; then
    print_skip "${BOLD}HOST_EMAIL_API_KEY${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${HOST_EMAIL_API_KEY:-}" ]]; then
        print_error "${BOLD}HOST_EMAIL_API_KEY${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}HOST_EMAIL_API_KEY${NC} from .env"
        if set_secret "HOST_EMAIL_API_KEY" "$HOST_EMAIL_API_KEY"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- HOST_EMAIL_FROM_ADDRESS: read from .env ---
if secret_exists "HOST_EMAIL_FROM_ADDRESS"; then
    print_skip "${BOLD}HOST_EMAIL_FROM_ADDRESS${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    if [[ -z "${HOST_EMAIL_FROM_ADDRESS:-}" ]]; then
        print_error "${BOLD}HOST_EMAIL_FROM_ADDRESS${NC} not found in .env, skipping"
        fail_count=$((fail_count + 1))
    else
        print_info "Using ${BOLD}HOST_EMAIL_FROM_ADDRESS${NC} from .env"
        if set_secret "HOST_EMAIL_FROM_ADDRESS" "$HOST_EMAIL_FROM_ADDRESS"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    fi
fi

# --- BUNNY_API_KEY: read from .env ---
if secret_exists "BUNNY_API_KEY"; then
    print_skip "${BOLD}BUNNY_API_KEY${NC} already exists, skipping"
    skip_count=$((skip_count + 1))
else
    print_info "Using ${BOLD}BUNNY_API_KEY${NC} from .env"
    if set_secret "BUNNY_API_KEY" "$BUNNY_API_KEY"; then
        success_count=$((success_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
fi

# Summary
print_header "Summary"

echo -e "  Edge Script ID: ${BOLD}${CYAN}$SCRIPT_ID${NC}"
echo ""

if [[ $success_count -gt 0 ]]; then
    echo -e "  ${GREEN}✓${NC} $success_count secret(s) set"
fi
if [[ $skip_count -gt 0 ]]; then
    echo -e "  ${DIM}○${NC} $skip_count secret(s) already existed (skipped)"
fi
if [[ $fail_count -gt 0 ]]; then
    echo -e "  ${RED}✗${NC} $fail_count secret(s) failed"
fi

echo ""

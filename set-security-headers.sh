#!/usr/bin/env nix-shell
#!nix-shell -i bash -p curl jq

# Script to set security headers on a Bunny CDN pull zone
# Uses .env file for API key

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

print_update() {
    echo -e "  ${YELLOW}↻${NC} $1"
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

# Fetch and display pull zones
print_header "Bunny CDN Security Headers Setup"

print_step "Fetching pull zones..."
echo ""

response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_BASE}/pullzone" \
    -H "AccessKey: ${BUNNY_API_KEY}" \
    -H "Content-Type: application/json")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    print_error "Failed to fetch pull zones (HTTP $http_code)"
    echo "$body"
    exit 1
fi

# Parse pull zones and display them
# API returns array directly, not wrapped in Items
zones="$body"
zone_count=$(echo "$zones" | jq 'length')

if [[ "$zone_count" -eq 0 ]]; then
    print_error "No pull zones found in your account"
    exit 1
fi

echo -e "  ${BOLD}Found $zone_count pull zone(s):${NC}"
echo ""

# Build arrays for selection
declare -a zone_ids
declare -a zone_names

for i in $(seq 0 $((zone_count - 1))); do
    id=$(echo "$zones" | jq -r ".[$i].Id")
    name=$(echo "$zones" | jq -r ".[$i].Name")
    hostnames=$(echo "$zones" | jq -r ".[$i].Hostnames[].Value" 2>/dev/null | head -2 | tr '\n' ', ' | sed 's/,$//')
    edge_rules_count=$(echo "$zones" | jq ".[$i].EdgeRules | length // 0")
    
    zone_ids+=("$id")
    zone_names+=("$name")
    
    # Build the info line
    info_parts=""
    if [[ "$edge_rules_count" -gt 0 ]]; then
        info_parts="${DIM}${edge_rules_count} edge rule(s)${NC}"
    fi
    
    echo -e "  ${BOLD}${YELLOW}[$((i + 1))]${NC} ${BOLD}$name${NC} (ID: $id)"
    if [[ -n "$hostnames" || -n "$info_parts" ]]; then
        echo -n "      "
        [[ -n "$hostnames" ]] && echo -n -e "${CYAN}$hostnames${NC}"
        [[ -n "$hostnames" && -n "$info_parts" ]] && echo -n " · "
        [[ -n "$info_parts" ]] && echo -n -e "$info_parts"
        echo ""
    fi
    echo ""
done

# Get user selection
echo -e -n "${BOLD}Select a pull zone [1-$zone_count]:${NC} "
read -r selection

# Validate selection
if ! [[ "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -gt "$zone_count" ]]; then
    print_error "Invalid selection"
    exit 1
fi

selected_index=$((selection - 1))
PULL_ZONE_ID="${zone_ids[$selected_index]}"
PULL_ZONE_NAME="${zone_names[$selected_index]}"

# Fetch existing edge rules for this pull zone
print_header "Checking Existing Edge Rules"

echo -e "  Pull Zone: ${BOLD}${CYAN}$PULL_ZONE_NAME${NC} (ID: $PULL_ZONE_ID)"
echo ""

print_step "Fetching existing edge rules..."

# Get pull zone details which includes edge rules
response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_BASE}/pullzone/${PULL_ZONE_ID}" \
    -H "AccessKey: ${BUNNY_API_KEY}" \
    -H "Content-Type: application/json")

http_code=$(echo "$response" | tail -n1)
pullzone_data=$(echo "$response" | sed '$d')

if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    print_error "Failed to fetch pull zone details (HTTP $http_code)"
    echo "$pullzone_data"
    exit 1
fi

# Extract the primary hostname (first non-b-cdn.net hostname)
PRIMARY_HOST=$(echo "$pullzone_data" | jq -r '[.Hostnames[].Value | select(endswith(".b-cdn.net") | not)] | first // empty')

# Extract base/registrable domain from hostname
# Handles common multi-part TLDs like .co.uk, .com.au, .org.uk, etc.
get_base_domain() {
    local host="$1"
    
    # Common two-part TLDs (note: .uk is also two-part since 2014)
    local two_part_tlds="co.uk|org.uk|me.uk|net.uk|ac.uk|gov.uk|ltd.uk|plc.uk|com.au|net.au|org.au|co.nz|net.nz|org.nz|co.za|com.br|co.jp|ne.jp|or.jp|co.in|net.in|org.in|com.mx|co.il|org.il"
    
    # Direct .uk domains (example.uk) - treat as two parts
    if echo "$host" | grep -qE "^[^.]+\.uk$"; then
        echo "$host"
        return
    fi
    
    if echo "$host" | grep -qE "\.($two_part_tlds)$"; then
        # For two-part TLDs: extract last 3 parts (e.g., example.co.uk)
        echo "$host" | rev | cut -d. -f1-3 | rev
    else
        # For single TLDs: extract last 2 parts (e.g., example.com)
        echo "$host" | rev | cut -d. -f1-2 | rev
    fi
}

BASE_DOMAIN=$(get_base_domain "$PRIMARY_HOST")

if [[ -n "$PRIMARY_HOST" ]]; then
    echo -e "  Primary host: ${BOLD}${CYAN}https://$PRIMARY_HOST${NC}"
    if [[ "$PRIMARY_HOST" != "$BASE_DOMAIN" ]]; then
        echo -e "  Base domain:  ${BOLD}${CYAN}https://$BASE_DOMAIN${NC} ${DIM}(for wildcard matching)${NC}"
    fi
else
    echo -e "  ${YELLOW}Warning: No custom hostname found, using 'self' only${NC}"
fi

# Extract existing edge rules - look for SetResponseHeader (ActionType 5) rules
existing_rules=$(echo "$pullzone_data" | jq '[.EdgeRules[] | select(.ActionType == 5)]')
existing_count=$(echo "$existing_rules" | jq 'length')

echo ""

# Collect existing rule GUIDs for deletion
declare -a existing_rule_guids

if [[ "$existing_count" -gt 0 ]]; then
    echo -e "  ${BOLD}Found $existing_count existing response header rule(s):${NC}"
    echo ""
    
    for i in $(seq 0 $((existing_count - 1))); do
        rule_guid=$(echo "$existing_rules" | jq -r ".[$i].Guid")
        header_name=$(echo "$existing_rules" | jq -r ".[$i].ActionParameter1")
        header_value=$(echo "$existing_rules" | jq -r ".[$i].ActionParameter2")
        enabled=$(echo "$existing_rules" | jq -r ".[$i].Enabled")
        
        existing_rule_guids+=("$rule_guid")
        
        if [[ "$enabled" == "true" ]]; then
            echo -e "    ${GREEN}●${NC} ${BOLD}$header_name${NC}"
        else
            echo -e "    ${DIM}○${NC} ${BOLD}$header_name${NC} ${DIM}(disabled)${NC}"
        fi
        echo -e "      ${DIM}$header_value${NC}"
    done
    echo ""
    
    # Ask to delete existing rules
    echo -e -n "  ${YELLOW}Delete existing response header rules before applying new ones? [y/N]:${NC} "
    read -r delete_confirm
    
    if [[ "$delete_confirm" =~ ^[Yy]$ ]]; then
        print_header "Removing Existing Rules"
        
        for guid in "${existing_rule_guids[@]}"; do
            response=$(curl -s -w "\n%{http_code}" -X DELETE \
                "${API_BASE}/pullzone/${PULL_ZONE_ID}/edgerules/${guid}" \
                -H "AccessKey: ${BUNNY_API_KEY}" \
                -H "Accept: application/json")
            
            http_code=$(echo "$response" | tail -n1)
            
            if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
                print_success "Deleted rule ${DIM}$guid${NC}"
            else
                print_error "Failed to delete rule $guid (HTTP $http_code)"
            fi
        done
        echo ""
    fi
else
    echo -e "  ${DIM}No existing response header rules found${NC}"
    echo ""
fi

# Function to add an edge rule for a response header
add_header_rule() {
    local header_name="$1"
    local header_value="$2"
    local description="$3"

    # ActionType 5 = SetResponseHeader
    # TriggerMatchingType 0 = MatchAny
    # Trigger: PatternMatchingType 0 = MatchAny, Type 0 = URL
    local payload=$(jq -n \
        --arg desc "$description" \
        --arg name "$header_name" \
        --arg value "$header_value" \
        '{
            ActionType: 5,
            ActionParameter1: $name,
            ActionParameter2: $value,
            Triggers: [
                {
                    Type: 0,
                    PatternMatchingType: 0,
                    PatternMatches: ["*"]
                }
            ],
            TriggerMatchingType: 0,
            Description: $desc,
            Enabled: true
        }')

    local response
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${API_BASE}/pullzone/${PULL_ZONE_ID}/edgerules/addOrUpdate" \
        -H "AccessKey: ${BUNNY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "$payload")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        print_success "${BOLD}$header_name${NC}"
        echo -e "      ${CYAN}$header_value${NC}"
        return 0
    else
        print_error "${BOLD}$header_name${NC} (HTTP $http_code)"
        echo -e "      ${RED}$body${NC}"
        return 1
    fi
}

print_header "Setting Security Headers"

success_count=0
fail_count=0

# Build CSP with dynamic host
# Allow: self, unsafe-inline for scripts/styles, the base domain's subdomains, *.chobble.com, and trusted third parties
TRUSTED_HOSTS="https://*.chobble.com https://api.botpoison.com"

if [[ -n "$BASE_DOMAIN" ]]; then
    if [[ "$BASE_DOMAIN" == "chobble.com" ]]; then
        # Already a chobble.com domain
        CSP_HOSTS="$TRUSTED_HOSTS"
    else
        # Different domain: allow its subdomains plus trusted hosts
        CSP_HOSTS="https://*.$BASE_DOMAIN $TRUSTED_HOSTS"
    fi
else
    CSP_HOSTS="$TRUSTED_HOSTS"
fi

CSP_VALUE="default-src 'self'; script-src 'self' 'unsafe-inline' $CSP_HOSTS; style-src 'self' 'unsafe-inline'; img-src 'self' data: $CSP_HOSTS; font-src 'self'; connect-src 'self' $CSP_HOSTS; frame-src https://*.google.com; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://submit-form.com https://*.chobble.com"

# Define headers to set
declare -a headers=(
    "Content-Security-Policy|$CSP_VALUE|Content Security Policy"
    "X-Content-Type-Options|nosniff|Prevent MIME type sniffing"
    "X-Frame-Options|DENY|Prevent clickjacking"
    "X-XSS-Protection|1; mode=block|XSS Protection"
    "Referrer-Policy|strict-origin-when-cross-origin|Referrer Policy"
    "Permissions-Policy|accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()|Permissions Policy"
    "Strict-Transport-Security|max-age=31536000; includeSubDomains|HTTP Strict Transport Security"
)

total=${#headers[@]}
current=0

for header_def in "${headers[@]}"; do
    current=$((current + 1))
    IFS='|' read -r name value desc <<< "$header_def"
    
    echo -e "${YELLOW}[$current/$total]${NC} $desc"
    
    if add_header_rule "$name" "$value" "$desc"; then
        success_count=$((success_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
    echo ""
done

# Summary
print_header "Summary"

if [[ $fail_count -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All $success_count security headers configured successfully!${NC}"
else
    echo -e "  ${RED}Some headers failed to configure${NC}"
fi

echo ""
if [[ $success_count -gt 0 ]]; then
    echo -e "  ${GREEN}✓${NC} $success_count headers created"
fi
if [[ $fail_count -gt 0 ]]; then
    echo -e "  ${RED}✗${NC} $fail_count failed"
fi

echo ""
echo -e "  ${CYAN}Verify your headers at:${NC}"
echo -e "  ${BOLD}https://securityheaders.com${NC}"
echo ""

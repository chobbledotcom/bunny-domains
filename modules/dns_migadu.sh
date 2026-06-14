#!/bin/bash
# DNS / Migadu module: list Bunny DNS zones, inspect their records, and
# point a zone's mail (MX/SPF/DKIM/DMARC/verification) at Migadu.
#
# Migadu publishes the exact records a domain needs from
#   GET https://api.migadu.com/v1/domains/{domain}/records
# (HTTP Basic auth: username = account email, password = API key).
# We translate those into Bunny DNS records, editing any matching record
# that already exists instead of creating a duplicate.

MIGADU_API_BASE="https://api.migadu.com/v1"
MIGADU_KEY_FILE="/run/secrets/migadu_api_key"

# _migadu_records runs in command substitution, so (like bunny_api) it can't
# return the HTTP status via a normal variable — a subshell assignment is lost.
# Stash it in a temp file and read it back with migadu_http_code.
# (No EXIT trap here — common.sh already owns one, and a second would replace
# it. The temp file is tiny and the OS reclaims it.)
MIGADU_HTTP_CODE_FILE="$(mktemp)"
migadu_http_code() { cat "$MIGADU_HTTP_CODE_FILE" 2>/dev/null || echo 000; }

# Map a Bunny numeric record type to its human name (for display).
_bunny_type_name() {
    case "$1" in
        0) echo "A" ;;        1) echo "AAAA" ;;   2) echo "CNAME" ;;
        3) echo "TXT" ;;      4) echo "MX" ;;     5) echo "Redirect" ;;
        6) echo "Flatten" ;;  7) echo "PullZone" ;; 8) echo "SRV" ;;
        9) echo "CAA" ;;      11) echo "Script" ;; 12) echo "NS" ;;
        *) echo "Type$1" ;;
    esac
}

# Map a DNS record type name (as Migadu reports it) to Bunny's numeric type.
_bunny_type_id() {
    case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
        a) echo 0 ;;     aaaa) echo 1 ;;  cname) echo 2 ;;
        txt) echo 3 ;;   mx) echo 4 ;;    srv) echo 8 ;;
        caa) echo 9 ;;   ns) echo 12 ;;   *) echo -1 ;;
    esac
}

# Bunny stores apex records with an empty Name; Migadu (and humans) write "@".
_norm_name() { [[ "$1" == "@" ]] && echo "" || echo "$1"; }

# Load Migadu credentials. Email comes from MIGADU_EMAIL in .env; the API key
# is read from the secrets file, falling back to MIGADU_API_KEY in .env.
# Sets MIGADU_EMAIL and MIGADU_API_KEY; returns non-zero on missing config.
_load_migadu_creds() {
    if [[ -z "${MIGADU_EMAIL:-}" ]]; then
        print_error "MIGADU_EMAIL not set in .env (your Migadu account email)" >&2
        return 1
    fi

    if [[ -r "$MIGADU_KEY_FILE" ]]; then
        MIGADU_API_KEY="$(cat "$MIGADU_KEY_FILE")"
    elif [[ -n "${MIGADU_API_KEY:-}" ]]; then
        : # use the value already in the environment
    else
        print_error "Migadu API key not found at $MIGADU_KEY_FILE (and MIGADU_API_KEY unset)" >&2
        return 1
    fi

    [[ -n "$MIGADU_API_KEY" ]] || { print_error "Migadu API key is empty" >&2; return 1; }
}

# GET a Migadu API path. Echoes the response body, records the HTTP status
# (read it back with migadu_http_code), and returns non-zero on a non-2xx.
# Usage: _migadu_get <path>
_migadu_get() {
    local path="$1"
    local response code
    response=$(curl -s -w "\n%{http_code}" \
        -u "${MIGADU_EMAIL}:${MIGADU_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        "${MIGADU_API_BASE}${path}")
    code=$(echo "$response" | tail -n1)
    echo "$code" > "$MIGADU_HTTP_CODE_FILE"
    echo "$response" | sed '$d'
    [[ "$code" -ge 200 && "$code" -lt 300 ]]
}

# Fetch a domain's recommended records from Migadu.
_migadu_records() { _migadu_get "/domains/$1/records"; }

# Load every domain in the Migadu account into MIGADU_DOMAINS_JSON so we can
# show activation state without an API call per zone. Falls back to an empty
# set on failure (the state column then reads "unknown").
_load_migadu_domains() {
    MIGADU_DOMAINS_JSON=$(_migadu_get "/domains") || MIGADU_DOMAINS_JSON='{"domains":[]}'
}

# Echo a domain's Migadu activation state: active, inactive, or "not added".
_migadu_state() {
    echo "${MIGADU_DOMAINS_JSON:-{\}}" | jq -r --arg d "$1" \
        '(.domains // []) | map(select(.name==$d)) | .[0].state // "not added"'
}

# Add a domain to the Migadu account. DNS stays on Bunny, so hosted_dns=false.
# Usage: _migadu_add_domain <domain>
_migadu_add_domain() {
    local domain="$1"
    local payload response code
    payload=$(jq -n --arg name "$domain" '{name:$name, hosted_dns:"false"}')
    response=$(curl -s -w "\n%{http_code}" \
        -u "${MIGADU_EMAIL}:${MIGADU_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST -d "$payload" \
        "${MIGADU_API_BASE}/domains")
    code=$(echo "$response" | tail -n1)
    [[ "$code" -ge 200 && "$code" -lt 300 ]]
}

# Prompt the user to pick a DNS zone. On success sets ZONE_ID and ZONE_DOMAIN.
# Returns non-zero if none are available.
select_dns_zone() {
    print_step "Fetching DNS zones..." >&2

    # Page through /dnszone, accumulating Items into one JSON array.
    local page=1 all="[]"
    while true; do
        local resp; resp=$(bunny_api GET "/dnszone?page=${page}&perPage=1000") || {
            print_error "Failed to fetch DNS zones (HTTP $(http_code))" >&2
            return 1
        }
        all=$(jq -s '.[0] + (.[1].Items // [])' <(echo "$all") <(echo "$resp"))
        [[ "$(echo "$resp" | jq -r '.HasMoreItems')" == "true" ]] || break
        page=$((page + 1))
    done

    local count; count=$(echo "$all" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_error "No DNS zones found in your account" >&2
        return 1
    fi

    local labels=() ids=() domains=()
    local i
    for i in $(seq 0 $((count - 1))); do
        local id domain recs state
        id=$(echo "$all" | jq -r ".[$i].Id")
        domain=$(echo "$all" | jq -r ".[$i].Domain")
        recs=$(echo "$all" | jq -r ".[$i].Records | length")
        state=$(_migadu_state "$domain")
        ids+=("$id")
        domains+=("$domain")
        labels+=("$domain  (${recs} records)  [migadu: ${state}]")
    done

    local choice; choice=$(list_paged "Select a DNS zone" "${labels[@]}")
    ZONE_ID="${ids[$choice]}"
    ZONE_DOMAIN="${domains[$choice]}"
}

# Fetch the chosen zone fresh and cache its Records array in RECORDS_JSON.
_load_zone_records() {
    local zone; zone=$(bunny_api GET "/dnszone/${ZONE_ID}") || {
        print_error "Failed to fetch zone $ZONE_ID (HTTP $(http_code))"
        return 1
    }
    RECORDS_JSON=$(echo "$zone" | jq '.Records')
}

# Print the cached records as a simple table.
_show_records() {
    local count; count=$(echo "$RECORDS_JSON" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_info "This zone has no records."
        return
    fi

    printf "  ${BOLD}%-7s %-26s %-40s %5s${NC}\n" "TYPE" "NAME" "VALUE" "PRIO"
    local i
    for i in $(seq 0 $((count - 1))); do
        local t name value prio tname
        t=$(echo "$RECORDS_JSON" | jq -r ".[$i].Type")
        name=$(echo "$RECORDS_JSON" | jq -r ".[$i].Name")
        value=$(echo "$RECORDS_JSON" | jq -r ".[$i].Value")
        prio=$(echo "$RECORDS_JSON" | jq -r ".[$i].Priority")
        tname=$(_bunny_type_name "$t")
        [[ -z "$name" ]] && name="@"
        printf "  ${CYAN}%-7s${NC} %-26s %-40.40s %5s\n" "$tname" "$name" "$value" "$prio"
    done
}

# Find an existing record's Id in RECORDS_JSON, or echo nothing if absent.
# Usage: _find_record <type_id> <name> <mode> <value>
#   mode=name  : match on Type + Name (first such record)
#   mode=exact : match on Type + Name + Value
#   mode=spf   : match Type + Name where Value begins "v=spf1"
_find_record() {
    local t="$1" name="$2" mode="$3" value="$4"
    case "$mode" in
        name)
            echo "$RECORDS_JSON" | jq -r --argjson t "$t" --arg n "$name" \
                'map(select(.Type==$t and .Name==$n)) | .[0].Id // empty' ;;
        exact)
            echo "$RECORDS_JSON" | jq -r --argjson t "$t" --arg n "$name" --arg v "$value" \
                'map(select(.Type==$t and .Name==$n and .Value==$v)) | .[0].Id // empty' ;;
        spf)
            echo "$RECORDS_JSON" | jq -r --argjson t "$t" --arg n "$name" \
                'map(select(.Type==$t and .Name==$n and (.Value|startswith("v=spf1")))) | .[0].Id // empty' ;;
    esac
}

# Create or update one record. Skips the write if a matching record already
# carries the same value, priority, weight and port.
# Usage: _apply_record <label> <type_id> <name> <value> <priority> <mode> [weight] [port]
# weight/port are only meaningful for SRV records; omit them otherwise.
_apply_record() {
    local label="$1" t="$2" name="$3" value="$4" priority="${5:-0}" mode="$6"
    local weight="${7:-}" port="${8:-}"

    local payload
    payload=$(jq -n --argjson type "$t" --arg name "$name" --arg value "$value" \
        --argjson ttl 3600 --argjson priority "$priority" \
        --arg weight "$weight" --arg port "$port" \
        '{Type:$type, Name:$name, Value:$value, Ttl:$ttl, Priority:$priority}
         + (if $weight != "" then {Weight: ($weight|tonumber)} else {} end)
         + (if $port   != "" then {Port:   ($port|tonumber)}   else {} end)')

    local id; id=$(_find_record "$t" "$name" "$mode" "$value")

    if [[ -n "$id" ]]; then
        local cur
        cur=$(echo "$RECORDS_JSON" | jq -r --argjson i "$id" \
            'map(select(.Id==$i))[0] | "\(.Value)|\(.Priority)|\(.Weight)|\(.Port)"')
        if [[ "$cur" == "${value}|${priority}|${weight:-0}|${port:-0}" ]]; then
            print_skip "$label — already up to date"
        elif bunny_api POST "/dnszone/${ZONE_ID}/records/${id}" "$payload" >/dev/null; then
            print_update "$label — updated"
        else
            print_error "$label — update failed (HTTP $(http_code))"
        fi
    elif bunny_api PUT "/dnszone/${ZONE_ID}/records" "$payload" >/dev/null; then
        print_success "$label — created"
    else
        print_error "$label — create failed (HTTP $(http_code))"
    fi
}

# Delete records of a given type whose host is not Migadu's (doesn't end in
# .migadu.com). Used to strip foreign MX records and unsupported SRV services
# (e.g. caldav/carddav). Operates on the records cached in RECORDS_JSON.
# Usage: _delete_foreign <type_id> <type_label>
_delete_foreign() {
    local t="$1" label="$2"
    local rows
    rows=$(echo "$RECORDS_JSON" | jq -r --argjson t "$t" \
        '.[] | select(.Type==$t and (.Value | endswith(".migadu.com") | not))
             | "\(.Id)\t\(.Name)\t\(.Value)"')
    [[ -z "$rows" ]] && return 0

    local id name value
    while IFS=$'\t' read -r id name value; do
        [[ -z "$id" ]] && continue
        [[ -z "$name" ]] && name="@"
        if bunny_api DELETE "/dnszone/${ZONE_ID}/records/${id}" >/dev/null; then
            print_update "${label} ${name} → ${value} — removed (not Migadu)"
        else
            print_error "${label} ${name} → ${value} — delete failed (HTTP $(http_code))"
        fi
    done <<< "$rows"
}

# Migadu's autoconfiguration records (autoconfig CNAME + SRV service records)
# are identical for every domain and are NOT returned by /records, so they're
# applied from this fixed list. Each entry: "name|value|port".
MIGADU_SRV_RECORDS=(
    "_autodiscover._tcp|autodiscover.migadu.com|443"
    "_submissions._tcp|smtp.migadu.com|465"
    "_imaps._tcp|imap.migadu.com|993"
    "_pop3s._tcp|pop.migadu.com|995"
)

# Apply Migadu's full mail record set (MX, SPF, DKIM, DMARC, verification,
# autoconfig CNAME, SRV service records) to the selected zone, and remove any
# non-Migadu MX records.
_apply_migadu_mail() {
    print_step "Fetching Migadu records for ${ZONE_DOMAIN}..."
    local m
    if ! m=$(_migadu_records "$ZONE_DOMAIN"); then
        # 404 means the domain isn't in the account yet — add it and retry.
        if [[ "$(migadu_http_code)" == "404" ]]; then
            print_info "${ZONE_DOMAIN} is not in your Migadu account — adding it..."
            if ! _migadu_add_domain "$ZONE_DOMAIN"; then
                print_error "Failed to add ${ZONE_DOMAIN} to Migadu"
                return 1
            fi
            print_success "Added ${ZONE_DOMAIN} to Migadu"
            if ! m=$(_migadu_records "$ZONE_DOMAIN"); then
                print_error "Migadu request still failed (HTTP $(migadu_http_code))"
                return 1
            fi
        else
            print_error "Migadu request failed for ${ZONE_DOMAIN} (HTTP $(migadu_http_code))"
            return 1
        fi
    fi

    echo ""
    print_header "Applying Migadu mail records"

    local mx_t; mx_t=$(_bunny_type_id mx)
    local txt_t; txt_t=$(_bunny_type_id txt)
    local cname_t; cname_t=$(_bunny_type_id cname)

    # MX records — match on host so multiple MX entries stay distinct.
    local n
    n=$(echo "$m" | jq '.mx_records | length')
    local i
    for i in $(seq 0 $((n - 1))); do
        local name value prio
        name=$(_norm_name "$(echo "$m" | jq -r ".mx_records[$i].name")")
        value=$(echo "$m" | jq -r ".mx_records[$i].value")
        prio=$(echo "$m" | jq -r ".mx_records[$i].priority")
        _apply_record "MX ${value}" "$mx_t" "$name" "$value" "$prio" exact
    done

    # SPF — the apex TXT record beginning "v=spf1".
    if [[ "$(echo "$m" | jq 'has("spf")')" == "true" ]]; then
        local name value
        name=$(_norm_name "$(echo "$m" | jq -r '.spf.name')")
        value=$(echo "$m" | jq -r '.spf.value')
        _apply_record "SPF" "$txt_t" "$name" "$value" 0 spf
    fi

    # DKIM — three CNAME records, matched by name.
    n=$(echo "$m" | jq '.dkim | length')
    for i in $(seq 0 $((n - 1))); do
        local name value
        name=$(_norm_name "$(echo "$m" | jq -r ".dkim[$i].name")")
        value=$(echo "$m" | jq -r ".dkim[$i].value")
        _apply_record "DKIM ${name}" "$cname_t" "$name" "$value" 0 name
    done

    # DMARC — TXT at _dmarc, matched by name.
    if [[ "$(echo "$m" | jq 'has("dmarc")')" == "true" ]]; then
        local name value
        name=$(_norm_name "$(echo "$m" | jq -r '.dmarc.name')")
        value=$(echo "$m" | jq -r '.dmarc.value')
        _apply_record "DMARC" "$txt_t" "$name" "$value" 0 name
    fi

    # DNS verification — apex TXT; matched on its exact value to avoid clobbering SPF.
    if [[ "$(echo "$m" | jq 'has("dns_verification")')" == "true" ]]; then
        local name value
        name=$(_norm_name "$(echo "$m" | jq -r '.dns_verification.name')")
        value=$(echo "$m" | jq -r '.dns_verification.value')
        _apply_record "Verification TXT" "$txt_t" "$name" "$value" 0 exact
    fi

    # autoconfig — CNAME used by mail clients for auto-setup, matched by name.
    _apply_record "autoconfig" "$cname_t" "autoconfig" "autoconfig.migadu.com" 0 name

    # SRV service records (priority 0, weight 1), matched by name.
    local srv_t; srv_t=$(_bunny_type_id srv)
    local srv_def srv_name srv_value srv_port
    for srv_def in "${MIGADU_SRV_RECORDS[@]}"; do
        IFS='|' read -r srv_name srv_value srv_port <<< "$srv_def"
        _apply_record "SRV ${srv_name}" "$srv_t" "$srv_name" "$srv_value" 0 name 1 "$srv_port"
    done

    # Remove any leftover MX/SRV records pointing somewhere other than Migadu
    # (foreign mail hosts, and unsupported SRV services like caldav/carddav).
    _delete_foreign "$mx_t" "MX"
    _delete_foreign "$srv_t" "SRV"

    echo ""
    print_success "Done. Mail delivery changes can take time to propagate."
}

# Run Migadu's DNS diagnostics for the current zone and print the result.
_migadu_diagnostics() {
    print_step "Running Migadu diagnostics for ${ZONE_DOMAIN}..."
    local out
    if out=$(_migadu_get "/domains/${ZONE_DOMAIN}/diagnostics"); then
        echo "$out" | jq . 2>/dev/null || echo "$out"
    else
        print_error "Diagnostics failed (HTTP $(migadu_http_code))"
        echo "$out" | jq -r '.message // .error // empty' 2>/dev/null
    fi
}

# Activate the current zone's domain in Migadu. Refreshes the domain cache so
# the displayed state updates. Returns non-zero on failure (e.g. 422 dns_check_failed).
_migadu_activate() {
    print_step "Activating ${ZONE_DOMAIN} in Migadu..."
    local out
    if out=$(_migadu_get "/domains/${ZONE_DOMAIN}/activate"); then
        print_success "${ZONE_DOMAIN} is now active."
    else
        print_error "Activation failed (HTTP $(migadu_http_code))"
        echo "$out" | jq -r '"  " + (.message // .error // "Unknown error")' 2>/dev/null
        _load_migadu_domains
        return 1
    fi
    _load_migadu_domains
}

# Entry point wired into the main menu.
run_dns_migadu() {
    print_header "DNS / Migadu Mail"

    _load_migadu_creds || return 1
    # Preload Migadu domains so the zone list can show activation state.
    print_step "Loading Migadu domains..."
    _load_migadu_domains
    select_dns_zone || return 1

    while true; do
        echo ""
        print_header "Zone: ${ZONE_DOMAIN}  [migadu: $(_migadu_state "$ZONE_DOMAIN")]"
        _load_zone_records || return 1
        _show_records

        echo ""
        local choice
        choice=$(list "Action for ${ZONE_DOMAIN}" \
            "Set mail records to Migadu" \
            "Run Migadu diagnostics" \
            "Activate Migadu domain" \
            "Refresh" \
            "Pick a different zone" \
            "Back to main menu")

        case "$choice" in
            0)
                echo ""
                if [[ "$(confirm "Write Migadu mail records into ${ZONE_DOMAIN}?")" -eq 1 ]]; then
                    _apply_migadu_mail
                else
                    print_info "Cancelled."
                fi
                ;;
            1) echo ""; _migadu_diagnostics ;;
            2)
                echo ""
                if [[ "$(confirm "Activate ${ZONE_DOMAIN} in Migadu?")" -eq 1 ]]; then
                    _migadu_activate
                else
                    print_info "Cancelled."
                fi
                ;;
            3) _load_migadu_domains ;; # refresh records (loop top) + domain state
            4) select_dns_zone || return 1 ;;
            5) break ;;
        esac
    done
}

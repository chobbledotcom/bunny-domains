#!/bin/bash
# New Domain module: add a brand-new DNS zone to Bunny and seed it with the
# records that already exist in public DNS for that domain.
#
# Flow:
#   1. Ask for the domain and refuse if it's already a zone in this account.
#   2. Create the zone (POST /dnszone) to get a ZoneId.
#   3. Trigger a background record scan (POST /dnszone/records/scan) for the
#      new zone, then poll GET /dnszone/{id}/records/scan until it completes.
#   4. Show the discovered records, let the user pick which to keep, and add
#      the chosen ones to the zone.
#
# The scan result can only be polled by ZoneId, so we create the zone first
# (rather than scanning the bare domain) and add records into it afterwards.

# How long to wait for the background scan before giving up.
SCAN_POLL_INTERVAL=2   # seconds between polls
SCAN_POLL_MAX=30       # max polls (≈ 60s total)

# Map a DNS record type name to Bunny's numeric type. Echoes -1 for unknown
# or unsupported-on-create types (e.g. SOA, which Bunny manages itself).
_nd_type_id() {
    case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
        a)        echo 0 ;;   aaaa)   echo 1 ;;    cname) echo 2 ;;
        txt)      echo 3 ;;   mx)     echo 4 ;;    redirect) echo 5 ;;
        flatten)  echo 6 ;;   pullzone) echo 7 ;;  srv)   echo 8 ;;
        caa)      echo 9 ;;   ptr)    echo 10 ;;   script) echo 11 ;;
        ns)       echo 12 ;;  svcb)   echo 13 ;;   https) echo 14 ;;
        tlsa)     echo 15 ;;  *)      echo -1 ;;
    esac
}

# Map either a numeric Bunny type or a type name to its human-readable name.
_nd_type_name() {
    case "$1" in
        0|a|A) echo "A" ;;              1|aaaa|AAAA) echo "AAAA" ;;
        2|cname|CNAME) echo "CNAME" ;;  3|txt|TXT) echo "TXT" ;;
        4|mx|MX) echo "MX" ;;           5) echo "Redirect" ;;
        6) echo "Flatten" ;;            7) echo "PullZone" ;;
        8|srv|SRV) echo "SRV" ;;        9|caa|CAA) echo "CAA" ;;
        10|ptr|PTR) echo "PTR" ;;       11) echo "Script" ;;
        12|ns|NS) echo "NS" ;;          13|svcb|SVCB) echo "SVCB" ;;
        14|https|HTTPS) echo "HTTPS" ;; 15|tlsa|TLSA) echo "TLSA" ;;
        *) echo "$1" ;;
    esac
}

# Bunny stores apex records with an empty Name; scans report apex as "@".
_nd_norm_name() { [[ "$1" == "@" || -z "$1" ]] && echo "" || echo "$1"; }

# Return 0 if the domain is already a DNS zone in this account.
# Pages through /dnszone and matches on Domain (case-insensitive).
_nd_zone_exists() {
    local want; want=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    local page=1
    while true; do
        local resp; resp=$(bunny_api GET "/dnszone?page=${page}&perPage=1000") || {
            print_error "Failed to fetch DNS zones (HTTP $(http_code))" >&2
            return 2
        }
        if echo "$resp" | jq -e --arg d "$want" \
            '(.Items // []) | any(.Domain | ascii_downcase == $d)' >/dev/null; then
            return 0
        fi
        [[ "$(echo "$resp" | jq -r '.HasMoreItems')" == "true" ]] || break
        page=$((page + 1))
    done
    return 1
}

# Create a DNS zone for the domain and echo the new ZoneId on success.
_nd_create_zone() {
    local domain="$1"
    local payload; payload=$(jq -n --arg d "$domain" '{Domain:$d}')
    local resp; resp=$(bunny_api POST "/dnszone" "$payload") || {
        print_error "Failed to create zone (HTTP $(http_code))" >&2
        echo "$resp" | jq -r '"  " + (.Message // empty)' 2>/dev/null >&2
        return 1
    }
    echo "$resp" | jq -r '.Id'
}

# Trigger a record scan for a zone and poll until it completes.
# Echoes the discovered Records array (JSON) on success.
_nd_scan_records() {
    local zone_id="$1"
    local payload; payload=$(jq -n --argjson z "$zone_id" '{ZoneId:$z}')
    bunny_api POST "/dnszone/records/scan" "$payload" >/dev/null || {
        print_error "Failed to start record scan (HTTP $(http_code))" >&2
        return 1
    }

    local i status resp
    for ((i = 0; i < SCAN_POLL_MAX; i++)); do
        sleep "$SCAN_POLL_INTERVAL"
        resp=$(bunny_api GET "/dnszone/${zone_id}/records/scan") || {
            print_error "Failed to read scan result (HTTP $(http_code))" >&2
            return 1
        }
        status=$(echo "$resp" | jq -r '.Status')
        case "$status" in
            2)  # Completed
                echo "$resp" | jq -c '.Records // []'
                return 0 ;;
            3)  # Failed
                print_error "Scan failed: $(echo "$resp" | jq -r '.Error // "unknown error"')" >&2
                return 1 ;;
            *)  # 0 Pending / 1 InProgress — keep waiting
                print_step "Scanning DNS records... (status ${status})" >&2 ;;
        esac
    done

    print_error "Scan did not complete within $((SCAN_POLL_INTERVAL * SCAN_POLL_MAX))s" >&2
    return 1
}

# Add one scanned record to the zone via PUT. Returns non-zero on failure.
# Usage: _nd_add_record <zone_id> <record_json>
_nd_add_record() {
    local zone_id="$1" rec="$2"
    local type_raw; type_raw=$(echo "$rec" | jq -r '.Type')
    local t; t=$(_nd_type_id "$(_nd_type_name "$type_raw")")
    [[ "$t" -lt 0 ]] && return 0  # skip unsupported types (e.g. SOA)

    local name value ttl prio weight port
    name=$(_nd_norm_name "$(echo "$rec" | jq -r '.Name')")
    value=$(echo "$rec" | jq -r '.Value // ""')
    ttl=$(echo "$rec" | jq -r '.Ttl // 3600')
    prio=$(echo "$rec" | jq -r '.Priority // 0')
    weight=$(echo "$rec" | jq -r '.Weight // empty')
    port=$(echo "$rec" | jq -r '.Port // empty')

    local payload
    payload=$(jq -n --argjson type "$t" --arg name "$name" --arg value "$value" \
        --argjson ttl "$ttl" --argjson priority "$prio" \
        --arg weight "$weight" --arg port "$port" \
        '{Type:$type, Name:$name, Value:$value, Ttl:$ttl, Priority:$priority}
         + (if $weight != "" then {Weight: ($weight|tonumber)} else {} end)
         + (if $port   != "" then {Port:   ($port|tonumber)}   else {} end)')

    bunny_api PUT "/dnszone/${zone_id}/records" "$payload" >/dev/null
}

# Entry point wired into the main menu.
run_new_domain() {
    print_header "Add New Domain"

    local domain; domain=$(input "Domain to add (e.g. example.com)")
    domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [[ -z "$domain" ]]; then
        print_error "No domain entered."
        return 1
    fi

    print_step "Checking whether ${domain} is already in your account..."
    _nd_zone_exists "$domain"
    case "$?" in
        0) print_error "${domain} already exists as a DNS zone in this account."; return 1 ;;
        2) return 1 ;;  # API error (already reported)
    esac

    echo ""
    if [[ "$(confirm "Create DNS zone for ${domain}?")" -ne 1 ]]; then
        print_info "Cancelled."
        return 0
    fi

    print_step "Creating zone for ${domain}..."
    local zone_id; zone_id=$(_nd_create_zone "$domain") || return 1
    print_success "Created zone ${domain} (id ${zone_id})"

    print_step "Scanning for existing DNS records..."
    local records; records=$(_nd_scan_records "$zone_id") || {
        print_info "Zone created, but no records were imported. You can add them manually."
        return 0
    }

    local count; count=$(echo "$records" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_success "Scan complete — no pre-existing records found for ${domain}."
        return 0
    fi

    # Build the candidate list, skipping records Bunny manages itself (SOA, and
    # the apex NS delegation, which is replaced by Bunny's own nameservers).
    local labels=() recs=()
    local i
    for i in $(seq 0 $((count - 1))); do
        local rec tname name value prio t
        rec=$(echo "$records" | jq -c ".[$i]")
        tname=$(_nd_type_name "$(echo "$rec" | jq -r '.Type')")
        name=$(echo "$rec" | jq -r '.Name')
        value=$(echo "$rec" | jq -r '.Value // ""')
        prio=$(echo "$rec" | jq -r '.Priority // 0')

        t=$(_nd_type_id "$tname")
        [[ "$t" -lt 0 ]] && continue                          # unsupported (SOA, etc.)
        if [[ "$tname" == "NS" && ( "$name" == "@" || -z "$name" ) ]]; then
            continue                                          # apex NS — Bunny owns this
        fi

        [[ -z "$name" ]] && name="@"
        recs+=("$rec")
        labels+=("$(printf '%-7s %-24s %-36.36s %s' "$tname" "$name" "$value" "$prio")")
    done

    if [[ "${#recs[@]}" -eq 0 ]]; then
        print_success "Scan complete — no importable records found for ${domain}."
        return 0
    fi

    echo ""
    print_header "Discovered ${#recs[@]} record(s) for ${domain}"
    printf "  ${BOLD}%-7s %-24s %-36s %s${NC}\n" "TYPE" "NAME" "VALUE" "PRIO"

    # Pre-check everything; the user can deselect any they don't want.
    local preselect; preselect=$(seq -s ' ' 0 $((${#recs[@]} - 1)))
    local chosen; chosen=$(checklist_paged "Select records to add to ${domain}" "$preselect" "${labels[@]}")

    if [[ -z "$chosen" ]]; then
        print_info "No records selected. Zone created without imported records."
        return 0
    fi

    echo ""
    print_header "Adding records to ${domain}"
    local idx ok=0 fail=0
    for idx in $chosen; do
        local rec; rec="${recs[$idx]}"
        if _nd_add_record "$zone_id" "$rec"; then
            print_success "${labels[$idx]} — added"
            ok=$((ok + 1))
        else
            print_error "${labels[$idx]} — failed (HTTP $(http_code))"
            fail=$((fail + 1))
        fi
    done

    echo ""
    print_success "Done. Added ${ok} record(s) to ${domain}."
    [[ "$fail" -gt 0 ]] && print_error "${fail} record(s) failed to add."
}

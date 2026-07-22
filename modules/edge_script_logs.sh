#!/bin/bash
# Edge Script log reader: fetch retained errors from Bunny's logging WebSocket
# and show only entries inside a recent time window.

EDGE_LOG_HISTORY_LIMIT=10000
EDGE_LOG_COLLECTION_SECONDS=5

_esl_fetch_scripts() {
    local page=1 all='[]'

    while true; do
        local response
        response=$(bunny_api GET "/compute/script?page=${page}&perPage=1000") || {
            print_error "Failed to fetch Edge Scripts (HTTP $(http_code))" >&2
            return 1
        }

        all=$(jq -c -s '.[0] + (.[1].Items // [])' \
            <(echo "$all") <(echo "$response"))
        [[ "$(echo "$response" | jq -r '.HasMoreItems // false')" == "true" ]] || break
        page=$((page + 1))
    done

    echo "$all"
}

_esl_select_script() {
    print_step "Fetching Edge Scripts..." >&2

    local scripts
    scripts=$(_esl_fetch_scripts) || return 1

    local count
    count=$(echo "$scripts" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_error "No Edge Scripts found in your account" >&2
        return 1
    fi

    local labels=() ids=() names=() i
    for ((i = 0; i < count; i++)); do
        local id name type
        id=$(echo "$scripts" | jq -r ".[$i].Id")
        name=$(echo "$scripts" | jq -r ".[$i].Name")
        type=$(echo "$scripts" | jq -r ".[$i].ScriptType")
        case "$type" in
            0) type="DNS" ;;
            1) type="CDN" ;;
            2) type="Middleware" ;;
            *) type="Unknown" ;;
        esac
        ids+=("$id")
        names+=("$name")
        labels+=("$name  [$id]  ($type)")
    done

    local choice
    choice=$(list_paged "Select an Edge Script" "${labels[@]}")
    EDGE_SCRIPT_ID="${ids[$choice]}"
    EDGE_SCRIPT_NAME="${names[$choice]}"
}

_esl_select_minutes() {
    local choice
    choice=$(list "How far back should errors be shown?" \
        "Last 60 minutes" \
        "Last 15 minutes" \
        "Last 6 hours" \
        "Last 24 hours" \
        "Custom number of minutes")

    case "$choice" in
        0) echo 60 ;;
        1) echo 15 ;;
        2) echo 360 ;;
        3) echo 1440 ;;
        4)
            local minutes
            minutes=$(input "Number of minutes")
            minutes=$(echo "$minutes" | tr -d '[:space:]')
            if [[ ! "$minutes" =~ ^[1-9][0-9]*$ ]]; then
                print_error "Minutes must be a positive whole number." >&2
                return 1
            fi
            echo "$minutes"
            ;;
    esac
}

_esl_log_token() {
    if [[ -n "${BUNNY_EDGE_LOG_TOKEN:-}" ]]; then
        echo "$BUNNY_EDGE_LOG_TOKEN"
        return 0
    fi

    print_info "Bunny's Edge Script log service requires a dashboard session token; the account API key is rejected." >&2
    echo "  Open the Bunny dashboard, then open your browser's developer console and run:" >&2
    echo '  copy(Object.values(localStorage).map(v=>{try{return JSON.parse(v).auth_token}catch{}}).find(Boolean))' >&2
    echo "  Add the copied value to .env as BUNNY_EDGE_LOG_TOKEN, or paste it below for this run." >&2
    echo "" >&2

    local token
    token=$(password "Dashboard auth token (leave blank to cancel)")
    if [[ -z "$token" ]]; then
        print_info "Cancelled." >&2
        return 1
    fi
    echo "$token"
}

# Read retained errors for a script. Arguments are script ID and minutes.
read_edge_script_errors() {
    local script_id="$1" minutes="${2:-60}"
    if [[ ! "$script_id" =~ ^[0-9]+$ || ! "$minutes" =~ ^[1-9][0-9]*$ ]]; then
        print_error "A numeric script ID and positive minute count are required."
        return 1
    fi

    local token
    token=$(_esl_log_token) || return 1
    local encoded_token
    encoded_token=$(jq -rn --arg value "$token" '$value | @uri')

    local url
    url="wss://scripting-logging.bunny.net/${script_id}?history=${EDGE_LOG_HISTORY_LIMIT}&Level=Error&token=${encoded_token}"

    local stderr_file raw status
    stderr_file=$(mktemp)
    raw=$(timeout "$EDGE_LOG_COLLECTION_SECONDS" websocat -n "$url" \
        </dev/null 2>"$stderr_file")
    status=$?

    # The service stays open for live logs, so timeout(1) should end the read.
    # An earlier close indicates a connection or authentication failure.
    if [[ "$status" -ne 124 ]]; then
        local websocket_error=""
        [[ -s "$stderr_file" ]] && websocket_error=$(<"$stderr_file")
        print_error "Failed to read Edge Script logs."
        if [[ -n "$websocket_error" ]]; then
            echo "  $websocket_error" >&2
        fi
        rm -f "$stderr_file"
        if [[ "$websocket_error" == *"403 Forbidden"* ]]; then
            print_info "The dashboard token was rejected or has expired. Copy the current auth token from the Bunny dashboard and update BUNNY_EDGE_LOG_TOKEN."
        fi
        return 1
    fi
    rm -f "$stderr_file"

    local cutoff logs count
    cutoff=$(date -u -d "${minutes} minutes ago" +%s)
    logs=$(printf '%s\n' "$raw" | jq -s -c --argjson cutoff "$cutoff" '
        [ .[]
          | select(type == "object" and (.log? != null))
          | . as $entry
          | (if (.log | type) == "string" then (.log | fromjson?) else .log end) as $log
          | select($log != null and $log.message_type != "Status" and $log.message_type != "Http")
          | ($log.timestamp // "") as $timestamp
          | ($timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601?) as $time
          | select($time != null and $time >= $cutoff)
          | {
                timestamp: $timestamp,
                region: ($entry.labels.ServerZone // "-"),
                message: ($log.message // "")
            }
        ] | sort_by(.timestamp)') || {
            print_error "Bunny returned an unexpected log response."
            return 1
        }

    count=$(echo "$logs" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_success "No errors found in the last ${minutes} minute(s)."
        return 0
    fi

    print_error "${count} error(s) found in the last ${minutes} minute(s):"
    echo ""
    echo "$logs" | jq -r '.[] | "  \(.timestamp)  [\(.region)]  \(.message)"'
}

run_edge_script_logs() {
    print_header "Edge Script Errors"

    _esl_select_script || return 1
    local minutes
    minutes=$(_esl_select_minutes) || return 1

    echo ""
    print_step "Reading errors for ${EDGE_SCRIPT_NAME} from the last ${minutes} minute(s)..."
    read_edge_script_errors "$EDGE_SCRIPT_ID" "$minutes"
}

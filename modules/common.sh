#!/bin/bash
# Shared helpers for the Bunny Domains TUI:
# environment loading, Bunny API access and pretty-printing.

# Colors for nice output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

API_BASE="https://api.bunny.net"

# bunny_api runs inside command substitution, so it can't export the HTTP
# status back to its caller via a normal variable. Stash it in a temp file
# and read it with http_code instead.
BUNNY_HTTP_CODE_FILE="$(mktemp)"
trap 'rm -f "$BUNNY_HTTP_CODE_FILE"' EXIT

# Echo the HTTP status code of the most recent bunny_api call.
http_code() { cat "$BUNNY_HTTP_CODE_FILE" 2>/dev/null || echo 000; }

# Pretty print functions
print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() { echo -e "  ${GREEN}✓${NC} $1"; }
print_error()   { echo -e "  ${RED}✗${NC} $1"; }
print_info()    { echo -e "  ${CYAN}→${NC} $1"; }
print_skip()    { echo -e "  ${DIM}○${NC} $1"; }
print_update()  { echo -e "  ${YELLOW}↻${NC} $1"; }
print_step()    { echo -e "${YELLOW}▶${NC} $1"; }

# Load environment variables from .env next to the entry point.
# Sets BUNNY_API_KEY (and any other configured vars) in the environment.
load_env() {
    local env_file="${ROOT_DIR}/.env"
    if [[ ! -f "$env_file" ]]; then
        print_header "Configuration Error"
        print_error ".env file not found at $env_file"
        echo ""
        echo "  Please create a .env file with:"
        echo -e "    ${CYAN}BUNNY_API_KEY=your_api_key${NC}"
        echo ""
        exit 1
    fi

    # shellcheck disable=SC1090
    source "$env_file"

    if [[ -z "${BUNNY_API_KEY:-}" ]]; then
        print_header "Configuration Error"
        print_error "BUNNY_API_KEY not set in .env"
        exit 1
    fi
}

# Make a Bunny API request.
# Usage: bunny_api METHOD PATH [json_body]
# Echoes the response body on stdout, records the status (see http_code),
# and returns non-zero for non-2xx responses.
bunny_api() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-s -w "\n%{http_code}" -X "$method"
        "${API_BASE}${path}"
        -H "AccessKey: ${BUNNY_API_KEY}"
        -H "Content-Type: application/json"
        -H "Accept: application/json")
    [[ -n "$data" ]] && args+=(-d "$data")

    local response; response=$(curl "${args[@]}")
    local code; code=$(echo "$response" | tail -n1)
    echo "$code" > "$BUNNY_HTTP_CODE_FILE"
    echo "$response" | sed '$d'

    [[ "$code" -ge 200 && "$code" -lt 300 ]]
}

# Extract base/registrable domain from a hostname.
# Handles common multi-part TLDs like .co.uk, .com.au, .org.uk, etc.
get_base_domain() {
    local host="$1"
    local two_part_tlds="co.uk|org.uk|me.uk|net.uk|ac.uk|gov.uk|ltd.uk|plc.uk|com.au|net.au|org.au|co.nz|net.nz|org.nz|co.za|com.br|co.jp|ne.jp|or.jp|co.in|net.in|org.in|com.mx|co.il|org.il"

    # Direct .uk domains (example.uk) - treat as two parts
    if echo "$host" | grep -qE "^[^.]+\.uk$"; then
        echo "$host"
        return
    fi

    if echo "$host" | grep -qE "\.($two_part_tlds)$"; then
        echo "$host" | rev | cut -d. -f1-3 | rev
    else
        echo "$host" | rev | cut -d. -f1-2 | rev
    fi
}

# A paginated replacement for the toolkit's list(). The toolkit positions
# every option on an absolute terminal row, so a list taller than the screen
# scrolls and the row math collapses into garbage. This renders only a
# viewport of items around the selection, redrawing in place (no absolute
# rows), so it scales to hundreds of entries.
#
# Usage: choice=$(list_paged "Prompt" "${labels[@]}")
# Echoes the selected index (0-based) on stdout.
list_paged() {
    local prompt="$1"; shift
    local opts=("$@")
    local count=${#opts[@]}

    # Visible window: terminal height minus a few rows for prompt/help, capped.
    local term_rows; term_rows=$(tput lines 2>/dev/null || echo 24)
    local window=$((term_rows - 4))
    [[ "$window" -lt 1 ]] && window=1
    [[ "$window" -gt "$count" ]] && window=$count

    echo -en "\033[32m?\033[0m\033[1m ${prompt}\033[0m " >&2
    echo -e "${DIM}(↑/↓ to move, enter to select)${NC}" >&2

    trap "_cursor_blink_on; stty echo; exit" 2
    _cursor_blink_off

    local selected=0 top=0 drawn=0
    while true; do
        # Keep the selection inside the visible window.
        if [[ "$selected" -lt "$top" ]]; then top=$selected; fi
        if [[ "$selected" -ge $((top + window)) ]]; then top=$((selected - window + 1)); fi

        # Move cursor back up over the previously drawn block to redraw in place.
        if [[ "$drawn" -gt 0 ]]; then echo -en "\033[${drawn}A" >&2; fi

        local idx
        for ((idx = top; idx < top + window; idx++)); do
            # \033[K clears any leftover characters from a longer prior label.
            if [[ "$idx" -eq "$selected" ]]; then
                printf "\033[2K\033[36m❯ %s\033[0m\n" "${opts[$idx]}" >&2
            else
                printf "\033[2K  %s\n" "${opts[$idx]}" >&2
            fi
        done
        drawn=$window

        case $(_key_input) in
            enter) break ;;
            up)    selected=$(( (selected - 1 + count) % count )) ;;
            down)  selected=$(( (selected + 1) % count )) ;;
        esac
    done

    _cursor_blink_on
    echo -n "$selected"
}

# A paginated multi-select checklist. Like list_paged() but each row is a
# toggleable checkbox (space toggles, enter confirms). Pre-checked rows are
# given via a space-separated list of 0-based indices.
#
# Usage: checked=$(checklist_paged "Prompt" "0 3 4" "${labels[@]}")
# Echoes the chosen indices, space-separated, on stdout.
checklist_paged() {
    local prompt="$1"; shift
    local prechecked="$1"; shift
    local opts=("$@")
    local count=${#opts[@]}

    # Track checked state per index.
    local checked=()
    local i
    for ((i = 0; i < count; i++)); do checked[$i]=0; done
    for i in $prechecked; do checked[$i]=1; done

    local term_rows; term_rows=$(tput lines 2>/dev/null || echo 24)
    local window=$((term_rows - 4))
    [[ "$window" -lt 1 ]] && window=1
    [[ "$window" -gt "$count" ]] && window=$count

    echo -en "\033[32m?\033[0m\033[1m ${prompt}\033[0m " >&2
    echo -e "${DIM}(↑/↓ move, space toggle, enter save)${NC}" >&2

    trap "_cursor_blink_on; stty echo; exit" 2
    _cursor_blink_off

    local selected=0 top=0 drawn=0
    while true; do
        if [[ "$selected" -lt "$top" ]]; then top=$selected; fi
        if [[ "$selected" -ge $((top + window)) ]]; then top=$((selected - window + 1)); fi

        if [[ "$drawn" -gt 0 ]]; then echo -en "\033[${drawn}A" >&2; fi

        local idx icon
        for ((idx = top; idx < top + window; idx++)); do
            if [[ "${checked[$idx]}" -eq 1 ]]; then icon="◉"; else icon="◯"; fi
            if [[ "$idx" -eq "$selected" ]]; then
                printf "\033[2K\033[36m❯ %s %s\033[0m\n" "$icon" "${opts[$idx]}" >&2
            else
                printf "\033[2K  %s %s\n" "$icon" "${opts[$idx]}" >&2
            fi
        done
        drawn=$window

        case $(_key_input) in
            enter) break ;;
            space) checked[$selected]=$(( 1 - ${checked[$selected]} )) ;;
            up)    selected=$(( (selected - 1 + count) % count )) ;;
            down)  selected=$(( (selected + 1) % count )) ;;
        esac
    done

    _cursor_blink_on

    local result=""
    for ((i = 0; i < count; i++)); do
        [[ "${checked[$i]}" -eq 1 ]] && result+="$i "
    done
    echo -n "${result% }"
}

# Prompt the user to pick a pull zone using the toolkit list().
# On success sets PULL_ZONE_ID and PULL_ZONE_NAME and returns 0.
# Returns 1 if no zones are available.
select_pull_zone() {
    print_step "Fetching pull zones..." >&2

    local zones; zones=$(bunny_api GET "/pullzone") || {
        print_error "Failed to fetch pull zones (HTTP $(http_code))" >&2
        return 1
    }

    local zone_count; zone_count=$(echo "$zones" | jq 'length')
    if [[ "$zone_count" -eq 0 ]]; then
        print_error "No pull zones found in your account" >&2
        return 1
    fi

    local labels=() ids=() names=()
    local i
    for i in $(seq 0 $((zone_count - 1))); do
        local id name host
        id=$(echo "$zones" | jq -r ".[$i].Id")
        name=$(echo "$zones" | jq -r ".[$i].Name")
        host=$(echo "$zones" | jq -r ".[$i].Hostnames[].Value" 2>/dev/null | head -1)
        ids+=("$id")
        names+=("$name")
        labels+=("$name  ($host)")
    done

    local choice; choice=$(list_paged "Select a pull zone" "${labels[@]}")
    PULL_ZONE_ID="${ids[$choice]}"
    PULL_ZONE_NAME="${names[$choice]}"
}

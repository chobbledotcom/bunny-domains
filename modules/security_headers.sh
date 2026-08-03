#!/bin/bash
# Security Headers module: set Content-Security-Policy and related
# response headers on a Bunny CDN pull zone via edge rules.

# Extract a single directive's value from a CSP string.
# Usage: _csp_directive "<csp>" script-src
_csp_directive() {
    echo "$1" | tr ';' '\n' | sed 's/^ *//' \
        | awk -v d="$2" '$1 == d { $1 = ""; sub(/^ /, ""); print }'
}

# Decide whether a CSP option is currently enabled, by looking for its
# signature host within the relevant directive of the current policy.
# Usage: _csp_has "<csp>" <option_id> <base_domain>
_csp_has() {
    local csp="$1" id="$2" base="$3"
    local script frame img form
    script=$(_csp_directive "$csp" script-src)
    frame=$(_csp_directive "$csp" frame-src)
    img=$(_csp_directive "$csp" img-src)
    form=$(_csp_directive "$csp" form-action)

    case "$id" in
        own_subdomains)   [[ -n "$base" ]] && echo "$script" | grep -qF "*.$base" ;;
        chobble_hosts)    echo "$script" | grep -qF "*.chobble.com" ;;
        google_frames)    echo "$frame"  | grep -qF "*.google.com" ;;
        youtube)          echo "$frame"  | grep -qF "youtube-nocookie.com" ;;
        ammhub)           echo "$frame"  | grep -qF "s-gfc.ammhub.com" ;;
        bunny_stream)     echo "$frame"  | grep -qF "iframe.mediadelivery.net" ;;
        vimeo)            echo "$frame"  | grep -qF "player.vimeo.com" ;;
        chobble_frames)   echo "$frame"  | grep -qF "*.chobble.com" ;;
        totaldrive)       echo "$frame"  | grep -qF "totaldrive.app" ;;
        freetobook)       echo "$script" | grep -qF "*.freetobook.com" ;;
        clarity)          echo "$script" | grep -qF "clarity.ms" ;;
        google_analytics) echo "$script" | grep -qF "googletagmanager.com" ;;
        pagefind)         echo "$script" | grep -qF "wasm-unsafe-eval" ;;
        osm)              echo "$img"    | grep -qF "tile.openstreetmap.org" ;;
        submit_form)      echo "$form"   | grep -qF "submit-form.com" ;;
        chobble_forms)    echo "$form"   | grep -qF "*.chobble.com" ;;
        *) return 1 ;;
    esac
}

# Add an edge rule for a response header.
# Usage: _add_header_rule NAME VALUE DESCRIPTION
_add_header_rule() {
    local header_name="$1" header_value="$2" description="$3"

    # ActionType 5 = SetResponseHeader; TriggerMatchingType 0 = MatchAny
    local payload
    payload=$(jq -n \
        --arg desc "$description" \
        --arg name "$header_name" \
        --arg value "$header_value" \
        '{
            ActionType: 5,
            ActionParameter1: $name,
            ActionParameter2: $value,
            Triggers: [ { Type: 0, PatternMatchingType: 0, PatternMatches: ["*"] } ],
            TriggerMatchingType: 0,
            Description: $desc,
            Enabled: true
        }')

    local body
    if body=$(bunny_api POST "/pullzone/${PULL_ZONE_ID}/edgerules/addOrUpdate" "$payload"); then
        print_success "${BOLD}$header_name${NC}"
        echo -e "      ${CYAN}$header_value${NC}"
        return 0
    else
        print_error "${BOLD}$header_name${NC} (HTTP $(http_code))"
        echo -e "      ${RED}$body${NC}"
        return 1
    fi
}

# Entry point for the module.
run_security_headers() {
    print_header "Bunny CDN Security Headers Setup"

    select_pull_zone || return 1

    # Fetch pull zone details (includes edge rules + hostnames)
    print_header "Checking Existing Edge Rules"
    echo -e "  Pull Zone: ${BOLD}${CYAN}$PULL_ZONE_NAME${NC} (ID: $PULL_ZONE_ID)"
    echo ""
    print_step "Fetching existing edge rules..."

    local pullzone_data
    pullzone_data=$(bunny_api GET "/pullzone/${PULL_ZONE_ID}") || {
        print_error "Failed to fetch pull zone details (HTTP $(http_code))"
        return 1
    }

    # Extract the primary hostname (first non-b-cdn.net hostname)
    local PRIMARY_HOST BASE_DOMAIN
    PRIMARY_HOST=$(echo "$pullzone_data" | jq -r '[.Hostnames[].Value | select(endswith(".b-cdn.net") | not)] | first // empty')
    BASE_DOMAIN=$(get_base_domain "$PRIMARY_HOST")

    if [[ -n "$PRIMARY_HOST" ]]; then
        echo -e "  Primary host: ${BOLD}${CYAN}https://$PRIMARY_HOST${NC}"
        if [[ "$PRIMARY_HOST" != "$BASE_DOMAIN" ]]; then
            echo -e "  Base domain:  ${BOLD}${CYAN}https://$BASE_DOMAIN${NC} ${DIM}(for wildcard matching)${NC}"
        fi
    else
        echo -e "  ${YELLOW}Warning: No custom hostname found, using 'self' only${NC}"
    fi

    # Existing SetResponseHeader rules (ActionType 5)
    local existing_rules existing_count
    existing_rules=$(echo "$pullzone_data" | jq '[.EdgeRules[] | select(.ActionType == 5)]')
    existing_count=$(echo "$existing_rules" | jq 'length')
    echo ""

    if [[ "$existing_count" -gt 0 ]]; then
        echo -e "  ${BOLD}Found $existing_count existing response header rule(s):${NC}"
        echo ""
        local i
        for i in $(seq 0 $((existing_count - 1))); do
            local header_name enabled
            header_name=$(echo "$existing_rules" | jq -r ".[$i].ActionParameter1")
            enabled=$(echo "$existing_rules" | jq -r ".[$i].Enabled")
            if [[ "$enabled" == "true" ]]; then
                echo -e "    ${GREEN}●${NC} ${BOLD}$header_name${NC}"
            else
                echo -e "    ${DIM}○${NC} ${BOLD}$header_name${NC} ${DIM}(disabled)${NC}"
            fi
        done
        echo ""
    else
        echo -e "  ${DIM}No existing response header rules found${NC}"
        echo ""
    fi

    # Pull the current Content-Security-Policy value (if any) so the checklist
    # below can be pre-ticked to match what's already deployed.
    local CURRENT_CSP
    CURRENT_CSP=$(echo "$existing_rules" \
        | jq -r '[.[] | select(.ActionParameter1 == "Content-Security-Policy")][0].ActionParameter2 // ""')

    # Build CSP from a toggleable checklist
    print_header "Content Security Policy Origins"

    # Each origin option: ID|Label. The build logic below keys off the ID.
    # own_subdomains is only meaningful for non-chobble custom domains.
    local OPT_IDS=() OPT_LABELS=()
    if [[ -n "$BASE_DOMAIN" && "$BASE_DOMAIN" != "chobble.com" ]]; then
        OPT_IDS+=("own_subdomains");  OPT_LABELS+=("*.$BASE_DOMAIN (own domain subdomains)")
    fi
    OPT_IDS+=("chobble_hosts");    OPT_LABELS+=("*.chobble.com (Chobble services: script/img/connect)")
    OPT_IDS+=("google_frames");    OPT_LABELS+=("*.google.com frames (Maps, reCAPTCHA)")
    OPT_IDS+=("youtube");          OPT_LABELS+=("youtube-nocookie.com frames (YouTube embeds)")
    OPT_IDS+=("ammhub");           OPT_LABELS+=("AMMHub enrolment and GoCardless payment frames")
    OPT_IDS+=("bunny_stream");     OPT_LABELS+=("iframe.mediadelivery.net frames (Bunny Stream)")
    OPT_IDS+=("vimeo");            OPT_LABELS+=("player.vimeo.com frames (Vimeo embeds)")
    OPT_IDS+=("chobble_frames");   OPT_LABELS+=("*.chobble.com frames")
    OPT_IDS+=("totaldrive");       OPT_LABELS+=("TotalDrive.app frames (driving instructor widget)")
    OPT_IDS+=("freetobook");       OPT_LABELS+=("*.freetobook.com (booking widget: script/connect/frame/form)")
    OPT_IDS+=("clarity");          OPT_LABELS+=("www.clarity.ms (Microsoft Clarity analytics)")
    OPT_IDS+=("google_analytics"); OPT_LABELS+=("Google Analytics/Ads (GA4, GTM, conversion tracking)")
    OPT_IDS+=("pagefind");         OPT_LABELS+=("Pagefind search (wasm-unsafe-eval in script-src)")
    OPT_IDS+=("osm");              OPT_LABELS+=("OpenStreetMap tiles (*.tile.openstreetmap.org images)")
    OPT_IDS+=("submit_form");      OPT_LABELS+=("submit-form.com (form submissions)")
    OPT_IDS+=("chobble_forms");    OPT_LABELS+=("*.chobble.com form actions")

    # Pre-check options whose signature is already present in the current CSP.
    local prechecked="" oi
    for oi in "${!OPT_IDS[@]}"; do
        if _csp_has "$CURRENT_CSP" "${OPT_IDS[$oi]}" "$BASE_DOMAIN"; then
            prechecked+="$oi "
        fi
    done

    local selected_idx; selected_idx=$(checklist_paged \
        "Toggle CSP origins (pre-ticked to match current policy)" \
        "$prechecked" "${OPT_LABELS[@]}")

    # Membership test against the chosen indices.
    local SELECTED_IDS=" "
    for oi in $selected_idx; do SELECTED_IDS+="${OPT_IDS[$oi]} "; done
    _has() { [[ "$SELECTED_IDS" == *" $1 "* ]]; }

    # -- General hosts (script-src, img-src, connect-src) --
    local CSP_HOSTS="https://api.botpoison.com "
    _has own_subdomains && CSP_HOSTS+="https://*.$BASE_DOMAIN "
    _has chobble_hosts  && CSP_HOSTS+="https://*.chobble.com "

    # -- frame-src origins --
    local FRAME_HOSTS=""
    _has google_frames  && FRAME_HOSTS+="https://*.google.com "
    _has youtube        && FRAME_HOSTS+="https://www.youtube-nocookie.com "
    _has ammhub         && FRAME_HOSTS+="https://s-gfc.ammhub.com https://pay.gocardless.com "
    _has bunny_stream   && FRAME_HOSTS+="https://iframe.mediadelivery.net https://player.mediadelivery.net "
    _has vimeo          && FRAME_HOSTS+="https://player.vimeo.com "
    _has chobble_frames && FRAME_HOSTS+="https://*.chobble.com "
    _has totaldrive     && FRAME_HOSTS+="https://totaldrive.app https://*.totaldrive.app "

    # -- third-party widget bundles (script + connect + frame) --
    local EXTRA_SCRIPT_HOSTS="" EXTRA_CONNECT_HOSTS="" IMG_HOSTS="" FORM_HOSTS=""
    if _has freetobook; then
        EXTRA_SCRIPT_HOSTS+="https://*.freetobook.com https://js.stripe.com https://m.stripe.network "
        EXTRA_CONNECT_HOSTS+="https://*.freetobook.com https://api.stripe.com https://m.stripe.network "
        FRAME_HOSTS+="https://*.freetobook.com https://booking-directly.com https://js.stripe.com https://m.stripe.network "
        FORM_HOSTS+="https://*.freetobook.com "
    fi
    _has clarity && EXTRA_SCRIPT_HOSTS+="https://www.clarity.ms "
    if _has google_analytics; then
        EXTRA_SCRIPT_HOSTS+="https://*.googletagmanager.com https://*.google-analytics.com https://*.googleadservices.com https://*.googlesyndication.com "
        IMG_HOSTS+="https://*.google-analytics.com https://*.googletagmanager.com https://*.google.com https://*.googleadservices.com https://*.doubleclick.net "
        EXTRA_CONNECT_HOSTS+="https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://*.google.com https://*.googleadservices.com https://*.doubleclick.net "
    fi

    # -- site features requiring special CSP keywords --
    local WASM_UNSAFE_EVAL=""
    _has pagefind && WASM_UNSAFE_EVAL="'wasm-unsafe-eval'"
    _has osm      && IMG_HOSTS+="https://*.tile.openstreetmap.org "

    # -- form-action origins --
    _has submit_form    && FORM_HOSTS+="https://submit-form.com "
    _has chobble_forms  && FORM_HOSTS+="https://*.chobble.com "

    # Trim trailing spaces
    CSP_HOSTS=$(echo "$CSP_HOSTS" | xargs)
    FRAME_HOSTS=$(echo "$FRAME_HOSTS" | xargs)
    EXTRA_SCRIPT_HOSTS=$(echo "$EXTRA_SCRIPT_HOSTS" | xargs)
    EXTRA_CONNECT_HOSTS=$(echo "$EXTRA_CONNECT_HOSTS" | xargs)
    IMG_HOSTS=$(echo "$IMG_HOSTS" | xargs)
    FORM_HOSTS=$(echo "$FORM_HOSTS" | xargs)

    # Build the CSP value
    local SCRIPT_SRC="'self' 'unsafe-inline'"
    [[ -n "$WASM_UNSAFE_EVAL" ]] && SCRIPT_SRC+=" $WASM_UNSAFE_EVAL"
    [[ -n "$CSP_HOSTS" ]] && SCRIPT_SRC+=" $CSP_HOSTS"
    [[ -n "$EXTRA_SCRIPT_HOSTS" ]] && SCRIPT_SRC+=" $EXTRA_SCRIPT_HOSTS"

    local IMG_SRC="'self' data:"
    [[ -n "$CSP_HOSTS" ]] && IMG_SRC+=" $CSP_HOSTS"
    [[ -n "$IMG_HOSTS" ]] && IMG_SRC+=" $IMG_HOSTS"

    local CONNECT_SRC="'self'"
    [[ -n "$CSP_HOSTS" ]] && CONNECT_SRC+=" $CSP_HOSTS"
    [[ -n "$EXTRA_CONNECT_HOSTS" ]] && CONNECT_SRC+=" $EXTRA_CONNECT_HOSTS"

    local FORM_ACTION="'self'"
    [[ -n "$FORM_HOSTS" ]] && FORM_ACTION+=" $FORM_HOSTS"

    local CSP_VALUE="default-src 'self'; script-src $SCRIPT_SRC; style-src 'self' 'unsafe-inline'; img-src $IMG_SRC; font-src 'self'; connect-src $CONNECT_SRC"
    [[ -n "$FRAME_HOSTS" ]] && CSP_VALUE+="; frame-src $FRAME_HOSTS"
    CSP_VALUE+="; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action $FORM_ACTION"

    echo ""
    echo -e "  ${BOLD}Resulting CSP:${NC}"
    echo -e "  ${DIM}$CSP_VALUE${NC}"
    echo ""

    if [[ "$(confirm "Apply these security headers to $PULL_ZONE_NAME?")" != "1" ]]; then
        print_info "Cancelled, no changes made."
        return 0
    fi

    # Edge rules addOrUpdate always inserts (no Guid = new rule), so clear the
    # existing response-header rules first to avoid duplicates.
    if [[ "$existing_count" -gt 0 ]]; then
        print_header "Removing Existing Rules"
        local guid
        for guid in $(echo "$existing_rules" | jq -r '.[].Guid'); do
            if bunny_api DELETE "/pullzone/${PULL_ZONE_ID}/edgerules/${guid}" >/dev/null; then
                print_success "Deleted rule ${DIM}$guid${NC}"
            else
                print_error "Failed to delete rule $guid (HTTP $(http_code))"
            fi
        done
        echo ""
    fi

    print_header "Setting Security Headers"

    local headers=(
        "Content-Security-Policy|$CSP_VALUE|Content Security Policy"
        "X-Content-Type-Options|nosniff|Prevent MIME type sniffing"
        "X-Frame-Options|DENY|Prevent clickjacking"
        "X-XSS-Protection|1; mode=block|XSS Protection"
        "Referrer-Policy|strict-origin-when-cross-origin|Referrer Policy"
        "Permissions-Policy|accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()|Permissions Policy"
        "Strict-Transport-Security|max-age=31536000; includeSubDomains|HTTP Strict Transport Security"
    )

    local success_count=0 fail_count=0 total=${#headers[@]} current=0
    local header_def name value desc
    for header_def in "${headers[@]}"; do
        current=$((current + 1))
        IFS='|' read -r name value desc <<< "$header_def"
        echo -e "${YELLOW}[$current/$total]${NC} $desc"
        if _add_header_rule "$name" "$value" "$desc"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
        echo ""
    done

    print_header "Summary"
    if [[ $fail_count -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}All $success_count security headers configured successfully!${NC}"
    else
        echo -e "  ${RED}Some headers failed to configure${NC}"
    fi
    echo ""
    [[ $success_count -gt 0 ]] && echo -e "  ${GREEN}✓${NC} $success_count headers created"
    [[ $fail_count -gt 0 ]] && echo -e "  ${RED}✗${NC} $fail_count failed"
    echo ""
    echo -e "  ${CYAN}Verify your headers at:${NC} ${BOLD}https://securityheaders.com${NC}"
    echo ""
}

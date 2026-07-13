#!/bin/bash
# Database settings module: select a Bunny Database and configure the regions
# that can act as its primary or serve as read replicas.

DB_PAGE_SIZE=100

# Fetch every database in the account and echo one JSON array.
_db_fetch_all() {
    local page=1 all="[]"

    while true; do
        local response
        response=$(bunny_api GET "/database/v2/databases?page=${page}&per_page=${DB_PAGE_SIZE}") || {
            print_error "Failed to fetch databases (HTTP $(http_code))" >&2
            return 1
        }

        all=$(jq -c -s '.[0] + (.[1].databases // [])' \
            <(echo "$all") <(echo "$response"))
        [[ "$(echo "$response" | jq -r '.page_info.has_more_items // false')" == "true" ]] || break
        page=$((page + 1))
    done

    echo "$all"
}

# Prompt for a database. Names are not unique, so every label includes its ID.
select_database() {
    print_step "Fetching databases..." >&2

    local databases
    databases=$(_db_fetch_all) || return 1

    local count
    count=$(echo "$databases" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        print_error "No databases found in your account" >&2
        return 1
    fi

    local labels=() ids=() names=()
    local i
    for ((i = 0; i < count; i++)); do
        local id name primary_count replica_count
        id=$(echo "$databases" | jq -r ".[$i].id")
        name=$(echo "$databases" | jq -r ".[$i].name")
        primary_count=$(echo "$databases" | jq -r ".[$i].primary_regions | length")
        replica_count=$(echo "$databases" | jq -r ".[$i].replicas_regions | length")
        ids+=("$id")
        names+=("$name")
        labels+=("$name  [$id]  (${primary_count} primary, ${replica_count} replication)")
    done

    local choice
    choice=$(list_paged "Select a database" "${labels[@]}")
    DATABASE_ID="${ids[$choice]}"
    DATABASE_NAME="${names[$choice]}"
}

# Load the selected database and the currently available region catalog.
_db_load_settings() {
    local response
    response=$(bunny_api GET "/database/v2/databases/${DATABASE_ID}") || {
        print_error "Failed to fetch ${DATABASE_NAME} (HTTP $(http_code))"
        return 1
    }
    DATABASE_JSON=$(echo "$response" | jq -c '.db // .')

    DATABASE_CONFIG_JSON=$(bunny_api GET "/database/v1/config") || {
        print_error "Failed to fetch database regions (HTTP $(http_code))"
        return 1
    }

    if ! echo "$DATABASE_JSON" | jq -e '.id and (.primary_regions | type == "array") and (.replicas_regions | type == "array")' >/dev/null \
        || ! echo "$DATABASE_CONFIG_JSON" | jq -e '(.primary_regions | type == "array") and (.replica_regions | type == "array")' >/dev/null; then
        print_error "Bunny returned an unexpected database response."
        return 1
    fi
}

_db_group_name() {
    case "$1" in
        EU) echo "Europe" ;;
        NA) echo "North America" ;;
        SA) echo "South America" ;;
        AF) echo "Africa" ;;
        ASIA) echo "Asia" ;;
        OC) echo "Oceania" ;;
        *) echo "$1" ;;
    esac
}

# Populate DB_REGION_IDS, DB_REGION_LABELS and DB_REGION_PRECHECKED for one
# region type. Arguments are the config key and database key respectively.
_db_build_region_options() {
    local config_key="$1" database_key="$2"
    local current
    current=$(echo "$DATABASE_JSON" | jq -r --arg key "$database_key" '.[$key] | join(" ")')

    DB_REGION_IDS=()
    DB_REGION_LABELS=()
    DB_REGION_PRECHECKED=""

    local id name group index=0
    while IFS=$'\t' read -r id name group; do
        [[ -z "$id" ]] && continue
        DB_REGION_IDS+=("$id")
        DB_REGION_LABELS+=("[$(_db_group_name "$group")] ${name} (${id})")
        if [[ " $current " == *" $id "* ]]; then
            DB_REGION_PRECHECKED+="${index} "
        fi
        index=$((index + 1))
    done < <(echo "$DATABASE_CONFIG_JSON" | jq -r --arg key "$config_key" \
        '.[$key][] | [.id, .name, (.group // "Other")] | @tsv')

    DB_REGION_PRECHECKED="${DB_REGION_PRECHECKED% }"
}

# Convert checklist indices to a JSON array of region IDs. Uses the option
# arrays most recently populated by _db_build_region_options.
_db_selected_ids_json() {
    local selected="$1" result="[]" index
    for index in $selected; do
        result=$(echo "$result" | jq -c --arg id "${DB_REGION_IDS[$index]}" '. + [$id]')
    done
    echo "$result"
}

_db_region_summary() {
    local database_key="$1" config_key="$2"
    local ids regions
    ids=$(echo "$DATABASE_JSON" | jq -c --arg key "$database_key" '.[$key]')
    regions=$(echo "$DATABASE_CONFIG_JSON" | jq -c --arg key "$config_key" '.[$key]')

    jq -nr --argjson ids "$ids" --argjson regions "$regions" '
        $ids | map(
            . as $id
            | ([$regions[] | select(.id == $id)][0] // {id: $id, name: $id})
            | if .name == .id then .id else "\(.name) (\(.id))" end
        )
        | if length == 0 then "(none)" else join(", ") end'
}

_db_show_settings() {
    echo -e "  Database:    ${BOLD}${CYAN}${DATABASE_NAME}${NC}"
    echo -e "  ID:          ${DIM}${DATABASE_ID}${NC}"
    echo -e "  Primary:     $(_db_region_summary primary_regions primary_regions)"
    echo -e "  Replication: $(_db_region_summary replicas_regions replica_regions)"
}

# Apply complete primary and replication region arrays to the selected database.
_db_apply_regions() {
    local primary_json="$1" replica_json="$2"
    local primary_count replica_count
    primary_count=$(echo "$primary_json" | jq 'length')
    replica_count=$(echo "$replica_json" | jq 'length')

    if [[ "$primary_count" -eq 0 ]]; then
        print_error "At least one primary region is required."
        return 1
    fi

    if echo "$DATABASE_JSON" | jq -e --argjson primary "$primary_json" --argjson replicas "$replica_json" \
        '(.primary_regions | sort) == ($primary | sort)
         and (.replicas_regions | sort) == ($replicas | sort)' >/dev/null; then
        print_info "No region changes to apply."
        return 0
    fi

    echo ""
    print_info "New configuration: ${primary_count} primary and ${replica_count} replication region(s)."
    echo -e "  ${YELLOW}Enabling more regions may increase database usage costs.${NC}"
    if [[ "$(confirm "Apply this region configuration to ${DATABASE_NAME}?")" -ne 1 ]]; then
        print_info "Cancelled."
        return 0
    fi

    local payload response
    payload=$(jq -n --argjson primary "$primary_json" --argjson replicas "$replica_json" \
        '{primary_regions: $primary, replicas_regions: $replicas}')

    print_step "Updating database regions..."
    response=$(bunny_api PATCH "/database/v2/databases/${DATABASE_ID}" "$payload") || {
        print_error "Failed to update ${DATABASE_NAME} (HTTP $(http_code))"
        echo "$response" | jq -r '"  " + (.error // .message // empty)' 2>/dev/null
        return 1
    }

    print_success "Updated regions for ${DATABASE_NAME}."
}

_db_edit_regions() {
    _db_build_region_options primary_regions primary_regions
    if [[ "${#DB_REGION_IDS[@]}" -eq 0 ]]; then
        print_error "Bunny reported no available primary regions."
        return 1
    fi

    local selected_primary primary_json
    selected_primary=$(checklist_paged \
        "Primary regions (at least one)" "$DB_REGION_PRECHECKED" "${DB_REGION_LABELS[@]}")
    primary_json=$(_db_selected_ids_json "$selected_primary")
    if [[ "$(echo "$primary_json" | jq 'length')" -eq 0 ]]; then
        print_error "At least one primary region is required."
        return 1
    fi

    _db_build_region_options replica_regions replicas_regions
    local selected_replicas="" replica_json="[]"
    if [[ "${#DB_REGION_IDS[@]}" -gt 0 ]]; then
        selected_replicas=$(checklist_paged \
            "Replication regions (optional)" "$DB_REGION_PRECHECKED" "${DB_REGION_LABELS[@]}")
        replica_json=$(_db_selected_ids_json "$selected_replicas")
    fi

    _db_apply_regions "$primary_json" "$replica_json"
}

_db_use_all_regions() {
    local primary_json replica_json
    primary_json=$(echo "$DATABASE_CONFIG_JSON" | jq -c '[.primary_regions[].id]')
    replica_json=$(echo "$DATABASE_CONFIG_JSON" | jq -c '[.replica_regions[].id]')
    _db_apply_regions "$primary_json" "$replica_json"
}

# Set every database that is not already an exact match to every region in the
# current Bunny catalog. One failure does not prevent the remaining updates.
_db_update_all_regions() {
    print_step "Fetching databases and available regions..."

    local databases config
    databases=$(_db_fetch_all) || return 1
    config=$(bunny_api GET "/database/v1/config") || {
        print_error "Failed to fetch database regions (HTTP $(http_code))"
        return 1
    }

    if ! echo "$config" | jq -e '(.primary_regions | type == "array") and (.replica_regions | type == "array")' >/dev/null; then
        print_error "Bunny returned an unexpected database region response."
        return 1
    fi

    local primary_json replica_json primary_count replica_count pending pending_count
    primary_json=$(echo "$config" | jq -c '[.primary_regions[].id]')
    replica_json=$(echo "$config" | jq -c '[.replica_regions[].id]')
    primary_count=$(echo "$primary_json" | jq 'length')
    replica_count=$(echo "$replica_json" | jq 'length')

    if [[ "$primary_count" -eq 0 ]]; then
        print_error "Bunny reported no available primary regions."
        return 1
    fi

    pending=$(echo "$databases" | jq -c \
        --argjson primary "$primary_json" --argjson replicas "$replica_json" '
        [.[] | select(
            ((.primary_regions // []) | sort) != ($primary | sort)
            or ((.replicas_regions // []) | sort) != ($replicas | sort)
        )]')
    pending_count=$(echo "$pending" | jq 'length')

    if [[ "$pending_count" -eq 0 ]]; then
        print_success "All databases already use all available regions."
        return 0
    fi

    echo ""
    print_info "${pending_count} database(s) need updating:"
    local i
    for ((i = 0; i < pending_count; i++)); do
        local name id current_primary current_replicas
        name=$(echo "$pending" | jq -r ".[$i].name")
        id=$(echo "$pending" | jq -r ".[$i].id")
        current_primary=$(echo "$pending" | jq -r ".[$i].primary_regions // [] | length")
        current_replicas=$(echo "$pending" | jq -r ".[$i].replicas_regions // [] | length")
        echo -e "  ${CYAN}${name}${NC} ${DIM}[${id}]${NC} (${current_primary}/${primary_count} primary, ${current_replicas}/${replica_count} replication)"
    done

    echo ""
    print_info "Target: ${primary_count} primary and ${replica_count} replication regions on every database."
    echo -e "  ${YELLOW}Enabling more regions may increase database usage costs.${NC}"
    if [[ "$(confirm "Update all ${pending_count} database(s) listed above?")" -ne 1 ]]; then
        print_info "Cancelled."
        return 0
    fi

    local payload
    payload=$(jq -n --argjson primary "$primary_json" --argjson replicas "$replica_json" \
        '{primary_regions: $primary, replicas_regions: $replicas}')

    echo ""
    print_header "Updating Database Regions"
    local success=0 failed=0
    for ((i = 0; i < pending_count; i++)); do
        local id name response
        id=$(echo "$pending" | jq -r ".[$i].id")
        name=$(echo "$pending" | jq -r ".[$i].name")

        if response=$(bunny_api PATCH "/database/v2/databases/${id}" "$payload"); then
            print_success "${name} [${id}]"
            success=$((success + 1))
        else
            print_error "${name} [${id}] - failed (HTTP $(http_code))"
            echo "$response" | jq -r '"    " + (.error // .message // empty)' 2>/dev/null
            failed=$((failed + 1))
        fi
    done

    echo ""
    print_success "Updated ${success} database(s)."
    if [[ "$failed" -gt 0 ]]; then
        print_error "${failed} database update(s) failed."
        return 1
    fi
}

# Manage the region settings for one selected database.
_db_manage_one() {
    select_database || return 1

    while true; do
        echo ""
        print_header "Database: ${DATABASE_NAME}"
        _db_load_settings || return 1
        _db_show_settings

        echo ""
        local choice
        choice=$(list "Action for ${DATABASE_NAME}" \
            "Use all available primary and replication regions" \
            "Edit primary and replication regions" \
            "Refresh" \
            "Pick a different database" \
            "Back to main menu")

        case "$choice" in
            0) _db_use_all_regions ;;
            1) _db_edit_regions ;;
            2) : ;;
            3) select_database || return 1 ;;
            4) break ;;
        esac
    done
}

# Entry point wired into the main menu. The bulk update is first so pressing
# Enter chooses the requested default job.
run_database_settings() {
    while true; do
        print_header "Database Region Settings"

        local choice
        choice=$(list "Database region action" \
            "Update all databases to use all available regions" \
            "Manage one database" \
            "Back to main menu")

        case "$choice" in
            0) _db_update_all_regions ;;
            1) _db_manage_one ;;
            2) break ;;
        esac

        echo ""
    done
}

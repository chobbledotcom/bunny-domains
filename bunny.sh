#!/usr/bin/env nix-shell
#!nix-shell -i bash -p curl jq

# Bunny Domains TUI
# A menu-driven terminal UI for managing Bunny CDN resources.
# Each task lives in modules/ and is wired into the main menu below.

# NB: no `set -eu`. The bash-tui-toolkit prompts rely on arithmetic like
# `((i++))` (which returns non-zero) and reference conditionally-unset vars,
# so strict mode would abort them. We guard our own code with explicit checks.
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="${ROOT_DIR}/lib/bash-tui-toolkit/src"

if [[ ! -f "${TOOLKIT_DIR}/main.sh" ]]; then
    echo "Toolkit not found. Run: git submodule update --init --recursive" >&2
    exit 1
fi

# The toolkit sources its modules by relative path, so enter its dir to load.
pushd "$TOOLKIT_DIR" >/dev/null
# shellcheck disable=SC1091
source main.sh
popd >/dev/null

# shellcheck disable=SC1091
source "${ROOT_DIR}/modules/common.sh"
# shellcheck disable=SC1091
source "${ROOT_DIR}/modules/security_headers.sh"

load_env

# Module registry: "Menu label|function name".
# Add new modules here as they are built.
MENU_ITEMS=(
    "Set security headers|run_security_headers"
    "Manage DNS records (coming soon)|_not_implemented"
    "Manage storage zones (coming soon)|_not_implemented"
)

_not_implemented() {
    print_info "This module is not implemented yet."
    echo ""
}

main_menu() {
    while true; do
        print_header "Bunny Domains"

        local labels=()
        local item
        for item in "${MENU_ITEMS[@]}"; do
            labels+=("${item%%|*}")
        done
        labels+=("Quit")

        local choice; choice=$(list "What would you like to do?" "${labels[@]}")

        # Last entry is Quit
        if [[ "$choice" -eq "${#MENU_ITEMS[@]}" ]]; then
            echo ""
            print_info "Bye!"
            break
        fi

        local fn="${MENU_ITEMS[$choice]##*|}"
        "$fn" || show_error "Action failed."

        echo ""
        confirm "Return to the main menu?" >/dev/null
    done
}

main_menu

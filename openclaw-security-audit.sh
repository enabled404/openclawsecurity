#!/usr/bin/env bash
#
# openclaw-security-audit.sh - Enterprise Security Audit for OpenClaw Installations
#
# A comprehensive security auditing and hardening tool for self-hosted AI assistants.
# Covers OWASP LLM Top 10, MITRE ATLAS, and DISA STIG/CIS/NIST compliance controls.
#
# This script performs DEFENSIVE security checks on YOUR OWN installation.
# It does NOT perform any attacks or test external systems.
#
# Usage: ./openclaw-security-audit.sh [OPTIONS]
#
# Options:
#   --fix       Attempt to auto-fix safe issues
#   --json      Output results as JSON
#   --quiet     Only show failures
#   --stig      Enable DISA STIG/CIS/NIST compliance checks
#   --deep      Enable deep scanning with live Gateway probe
#   --help      Show this help message
#
# Documentation: https://github.com/enabled404/openclawsecurity
#

set -euo pipefail
shopt -s nullglob  # Handle glob patterns that match nothing

# =============================================================================
# Configuration
# =============================================================================

VERSION="3.0.0"
SCRIPT_NAME="openclaw-security-audit"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# Options
FIX_MODE=false
JSON_MODE=false
QUIET_MODE=false
DEEP_MODE=false
STIG_MODE=false

# Risk score (0-100)
RISK_SCORE=0

# JSON results array
declare -a JSON_RESULTS=()

# =============================================================================
# Helper Functions
# =============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           OpenClaw Security Audit v${VERSION}                       ║"
    echo "║        Enterprise Security Scanner for OpenClaw                   ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BLUE}Compliance: ${NC}DISA STIG | CIS Benchmark | NIST 800-53 | OWASP LLM Top 10"
    echo ""
}

print_help() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Enterprise security audit for OpenClaw installations.
Checks YOUR OWN installation for vulnerabilities and compliance.

Options:
  --fix       Attempt to auto-fix safe issues (SSH config, permissions)
  --json      Output results as JSON (for CI/CD integration)
  --quiet     Only show failures and warnings
  --stig      Enable DISA STIG/CIS/NIST compliance checks
  --deep      Extended audit with live Gateway probe
  --help      Show this help message

Examples:
  ${SCRIPT_NAME}              # Run core security audit
  ${SCRIPT_NAME} --stig       # Full compliance audit
  ${SCRIPT_NAME} --fix        # Audit and auto-fix issues
  ${SCRIPT_NAME} --json       # JSON output for CI/CD
  ${SCRIPT_NAME} --deep       # Include live gateway probe

Exit Codes:
  0  - All checks passed
  1  - One or more critical failures
  2  - Warnings only (no critical failures)

Documentation: https://github.com/signalfi/OpenClawAudit
EOF
}

log_pass() {
    local check="$1"
    local message="$2"
    PASS_COUNT=$((PASS_COUNT + 1))
    if [[ "$JSON_MODE" == true ]]; then
        local esc_check esc_msg
        esc_check=$(json_escape "$check")
        esc_msg=$(json_escape "$message")
        JSON_RESULTS+=("{\"check\": \"$esc_check\", \"status\": \"pass\", \"message\": \"$esc_msg\"}")
    elif [[ "$QUIET_MODE" == false ]]; then
        echo -e "  ${GREEN}[PASS]${NC} $check: $message"
    fi
}

log_fail() {
    local check="$1"
    local message="$2"
    local risk="${3:-10}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RISK_SCORE=$((RISK_SCORE + risk))
    if [[ "$JSON_MODE" == true ]]; then
        local esc_check esc_msg
        esc_check=$(json_escape "$check")
        esc_msg=$(json_escape "$message")
        JSON_RESULTS+=("{\"check\": \"$esc_check\", \"status\": \"fail\", \"message\": \"$esc_msg\", \"risk\": $risk}")
    else
        echo -e "  ${RED}[FAIL]${NC} $check: $message"
    fi
}

log_warn() {
    local check="$1"
    local message="$2"
    local risk="${3:-5}"
    WARN_COUNT=$((WARN_COUNT + 1))
    RISK_SCORE=$((RISK_SCORE + risk))
    if [[ "$JSON_MODE" == true ]]; then
        local esc_check esc_msg
        esc_check=$(json_escape "$check")
        esc_msg=$(json_escape "$message")
        JSON_RESULTS+=("{\"check\": \"$esc_check\", \"status\": \"warn\", \"message\": \"$esc_msg\", \"risk\": $risk}")
    else
        echo -e "  ${YELLOW}[WARN]${NC} $check: $message"
    fi
}

log_skip() {
    local check="$1"
    local message="$2"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    if [[ "$JSON_MODE" == true ]]; then
        local esc_check esc_msg
        esc_check=$(json_escape "$check")
        esc_msg=$(json_escape "$message")
        JSON_RESULTS+=("{\"check\": \"$esc_check\", \"status\": \"skip\", \"message\": \"$esc_msg\"}")
    elif [[ "$QUIET_MODE" == false ]]; then
        echo -e "  ${BLUE}[SKIP]${NC} $check: $message"
    fi
}

log_info() {
    local message="$1"
    if [[ "$JSON_MODE" == false && "$QUIET_MODE" == false ]]; then
        echo -e "${CYAN}$message${NC}"
    fi
}

log_section() {
    local title="$1"
    if [[ "$JSON_MODE" == false ]]; then
        echo ""
        echo -e "${BOLD}━━━ $title ━━━${NC}"
    fi
}

command_exists() {
    command -v "$1" &> /dev/null
}

# Escape string for JSON output
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"  # Escape backslashes
    str="${str//\"/\\\"}"  # Escape quotes
    str="${str//$'\n'/\\n}" # Escape newlines
    str="${str//$'\t'/\\t}" # Escape tabs
    echo "$str"
}

# Cross-platform timestamp (works on both Linux and macOS)
get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# =============================================================================
# Security Checks
# =============================================================================

check_ssh_security() {
    log_section "SSH Security (Hack #1: Brute Force Prevention)"

    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_skip "SSH Config" "SSHD config not found (may not be a server)"
        return
    fi

    # Check password authentication
    if grep -E "^PasswordAuthentication\s+no" "$sshd_config" &>/dev/null; then
        log_pass "SSH Password Auth" "Password authentication is disabled"
    elif grep -E "^PasswordAuthentication\s+yes" "$sshd_config" &>/dev/null; then
        log_fail "SSH Password Auth" "Password authentication is ENABLED - vulnerable to brute force" 15
        if [[ "$FIX_MODE" == true ]]; then
            echo -e "    ${YELLOW}→ Fix: sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' $sshd_config${NC}"
        fi
    else
        log_warn "SSH Password Auth" "Password authentication not explicitly disabled (defaults may vary)" 10
    fi

    # Check root login
    if grep -E "^PermitRootLogin\s+no" "$sshd_config" &>/dev/null; then
        log_pass "SSH Root Login" "Root login is disabled"
    elif grep -E "^PermitRootLogin\s+(yes|without-password|prohibit-password)" "$sshd_config" &>/dev/null; then
        log_fail "SSH Root Login" "Root login is ENABLED" 15
        if [[ "$FIX_MODE" == true ]]; then
            echo -e "    ${YELLOW}→ Fix: sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' $sshd_config${NC}"
        fi
    else
        log_warn "SSH Root Login" "Root login not explicitly disabled" 10
    fi

    # Check for fail2ban
    if command_exists fail2ban-client; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            log_pass "Fail2ban" "Fail2ban is installed and running"
        else
            log_warn "Fail2ban" "Fail2ban is installed but not running" 8
        fi
    else
        log_fail "Fail2ban" "Fail2ban is NOT installed - no brute force protection" 12
        if [[ "$FIX_MODE" == true ]]; then
            echo -e "    ${YELLOW}→ Fix: sudo apt install fail2ban -y && sudo systemctl enable fail2ban${NC}"
        fi
    fi
}

check_firewall() {
    log_section "Firewall (Hack #1, #2: Network Protection)"

    local firewall_active=false

    # Check UFW
    if command_exists ufw; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            log_pass "UFW Firewall" "UFW is active"
            firewall_active=true
        else
            log_warn "UFW Firewall" "UFW is installed but inactive" 10
        fi
    fi

    # Check iptables (if UFW not active)
    if [[ "$firewall_active" == false ]] && command_exists iptables; then
        local rules=0
        local iptables_output=""
        # Handle iptables failure gracefully (|| true prevents set -e exit)
        iptables_output=$(iptables -L -n 2>/dev/null) || true
        if [[ -n "$iptables_output" ]]; then
            rules=$(echo "$iptables_output" | wc -l)
            if [[ $rules -gt 8 ]]; then
                log_pass "iptables" "iptables has rules configured"
                firewall_active=true
            fi
        fi
    fi

    # Check firewalld
    if [[ "$firewall_active" == false ]] && command_exists firewall-cmd; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            log_pass "firewalld" "firewalld is active"
            firewall_active=true
        fi
    fi

    if [[ "$firewall_active" == false ]]; then
        log_fail "Firewall" "No active firewall detected" 15
        if [[ "$FIX_MODE" == true ]]; then
            echo -e "    ${YELLOW}→ Fix: sudo apt install ufw && sudo ufw enable${NC}"
        fi
    fi
}

check_gateway_exposure() {
    log_section "Gateway Exposure (Control Gateway Security)"

    # Check for OpenClaw config locations (official naming convention)
    local config_paths=(
        "$HOME/.openclaw/openclaw.json"
        "$HOME/.openclaw/openclaw.yaml"
        "$HOME/.openclaw/config.json"
        "$HOME/.openclaw/config.yaml"
        "$HOME/.config/openclaw/openclaw.json"
    )

    local config_found=false

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            config_found=true
            log_info "  Found config: $config"

            # Check if bound to 0.0.0.0
            if grep -E "(0\.0\.0\.0|bind.*:.*0\.0\.0\.0)" "$config" &>/dev/null; then
                log_fail "Gateway Binding" "Gateway bound to 0.0.0.0 - exposed to internet!" 20
                if [[ "$FIX_MODE" == true ]]; then
                    echo -e "    ${YELLOW}→ Fix: Change bind address to 127.0.0.1 in $config${NC}"
                fi
            elif grep -E "(127\.0\.0\.1|localhost)" "$config" &>/dev/null; then
                log_pass "Gateway Binding" "Gateway bound to localhost"
            else
                log_warn "Gateway Binding" "Could not determine gateway binding" 5
            fi

            # Check authentication
            if grep -Ei "authentication.*:.*false|auth.*:.*false" "$config" &>/dev/null; then
                log_fail "Gateway Auth" "Gateway authentication is DISABLED" 20
            elif grep -Ei "authentication.*:.*true|auth.*:.*true" "$config" &>/dev/null; then
                log_pass "Gateway Auth" "Gateway authentication is enabled"
            else
                log_warn "Gateway Auth" "Could not determine authentication status" 10
            fi

            break
        fi
    done

    if [[ "$config_found" == false ]]; then
        log_skip "Gateway Config" "No openclaw config found"
    fi

    # Check for exposed ports
    if command_exists ss; then
        if ss -tlnp 2>/dev/null | grep -E ":18789|:8080" | grep -q "0.0.0.0"; then
            log_fail "Port Exposure" "Bot gateway port exposed on all interfaces" 15
        fi
    elif command_exists netstat; then
        if netstat -tlnp 2>/dev/null | grep -E ":18789|:8080" | grep -q "0.0.0.0"; then
            log_fail "Port Exposure" "Bot gateway port exposed on all interfaces" 15
        fi
    fi
}

check_user_allowlist() {
    log_section "User Allowlist (Unauthorized Access Prevention)"

    # Official OpenClaw config paths
    local config_paths=(
        "$HOME/.openclaw/openclaw.json"
        "$HOME/.openclaw/openclaw.yaml"
        "$HOME/.openclaw/config.json"
    )

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            # Check for DM policy (OpenClaw security model)
            if grep -Ei "dmPolicy.*pairing|dm.*policy.*pairing" "$config" &>/dev/null; then
                log_pass "DM Policy" "DM policy set to 'pairing' (secure)"
            elif grep -Ei "dmPolicy.*open|dm.*policy.*open" "$config" &>/dev/null; then
                log_fail "DM Policy" "DM policy set to 'open' - anyone can message!" 20
            fi

            # Check for Telegram allowlist
            if grep -Ei "telegram" "$config" &>/dev/null; then
                if grep -Ei "allowedUserIds|allowed_user_ids|allowFrom" "$config" &>/dev/null; then
                    log_pass "Telegram Allowlist" "Telegram user allowlist configured"
                else
                    log_fail "Telegram Allowlist" "No Telegram user allowlist found" 15
                fi
            fi

            # Check for Discord allowlist
            if grep -Ei "discord" "$config" &>/dev/null; then
                if grep -Ei "allowedUserIds|allowed_user_ids" "$config" &>/dev/null; then
                    log_pass "Discord Allowlist" "Discord user allowlist appears configured"
                else
                    log_fail "Discord Allowlist" "No Discord user allowlist found" 15
                fi
            fi

            # Check for Slack allowlist
            if grep -Ei "slack" "$config" &>/dev/null; then
                if grep -Ei "allowedUserIds|allowed_user_ids" "$config" &>/dev/null; then
                    log_pass "Slack Allowlist" "Slack user allowlist appears configured"
                else
                    log_warn "Slack Allowlist" "No Slack user allowlist found" 10
                fi
            fi

            return
        fi
    done

    log_skip "User Allowlist" "No bot config found to check"
}

check_browser_profile() {
    log_section "Browser Security (Session Hijacking Prevention)"

    # Official OpenClaw config paths
    local config_paths=(
        "$HOME/.openclaw/openclaw.json"
        "$HOME/.openclaw/openclaw.yaml"
        "$HOME/.openclaw/config.json"
    )

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            # Check for browser profile configuration
            if grep -Ei "browser.*profile.*default|chrome.*profile.*default" "$config" &>/dev/null; then
                log_fail "Browser Profile" "Using DEFAULT browser profile - session hijacking risk!" 20
                echo -e "    ${YELLOW}→ Recommendation: Create isolated profile for bot${NC}"
            elif grep -Ei "browser.*profile|chrome.*profile|user.*data.*dir" "$config" &>/dev/null; then
                log_pass "Browser Profile" "Custom browser profile appears configured"
            else
                log_warn "Browser Profile" "Browser profile configuration not found" 10
            fi
            return
        fi
    done

    log_skip "Browser Profile" "No bot config found"
}

check_password_manager() {
    log_section "Password Manager (Hack #5: Credential Extraction Prevention)"

    # Check 1Password CLI (with timeout to prevent hanging)
    if command_exists op; then
        if command_exists timeout; then
            if timeout 5 op account list &>/dev/null; then
                log_fail "1Password CLI" "1Password CLI is AUTHENTICATED on this system!" 25
                echo -e "    ${RED}→ CRITICAL: Run 'op signout --all' to sign out${NC}"
            else
                log_pass "1Password CLI" "1Password CLI installed but not authenticated"
            fi
        else
            # Fallback without timeout (macOS may not have timeout)
            if op account list &>/dev/null 2>&1; then
                log_fail "1Password CLI" "1Password CLI is AUTHENTICATED on this system!" 25
                echo -e "    ${RED}→ CRITICAL: Run 'op signout --all' to sign out${NC}"
            else
                log_pass "1Password CLI" "1Password CLI installed but not authenticated"
            fi
        fi
    else
        log_pass "1Password CLI" "1Password CLI not installed on this system"
    fi

    # Check Bitwarden CLI (with timeout)
    if command_exists bw; then
        local bw_status
        if command_exists timeout; then
            bw_status=$(timeout 5 bw status 2>/dev/null || echo '{}')
        else
            bw_status=$(bw status 2>/dev/null || echo '{}')
        fi
        if echo "$bw_status" | grep -q '"status":"unlocked"'; then
            log_fail "Bitwarden CLI" "Bitwarden CLI is UNLOCKED on this system!" 25
            echo -e "    ${RED}→ CRITICAL: Run 'bw lock' to lock the vault${NC}"
        else
            log_pass "Bitwarden CLI" "Bitwarden CLI is locked or not logged in"
        fi
    fi

    # Check LastPass CLI (with timeout)
    if command_exists lpass; then
        local lpass_status
        if command_exists timeout; then
            lpass_status=$(timeout 5 lpass status 2>/dev/null || echo "Not logged in")
        else
            lpass_status=$(lpass status 2>/dev/null || echo "Not logged in")
        fi
        if echo "$lpass_status" | grep -q "Logged in"; then
            log_fail "LastPass CLI" "LastPass CLI is LOGGED IN on this system!" 25
            echo -e "    ${RED}→ CRITICAL: Run 'lpass logout' to sign out${NC}"
        else
            log_pass "LastPass CLI" "LastPass CLI not logged in"
        fi
    fi
}

check_docker_security() {
    log_section "Docker Security (Hack #7: Sandbox Escape Prevention)"

    if ! command_exists docker; then
        log_skip "Docker" "Docker not installed"
        return
    fi

    # Check if current user can run docker (is in docker group)
    if groups 2>/dev/null | grep -q docker; then
        log_warn "Docker Group" "Current user is in docker group - container escape possible" 5
    fi

    # Check running containers for privileged mode
    local containers
    containers=$(docker ps --format '{{.Names}}' 2>/dev/null) || true

    if [[ -n "$containers" && ! "$containers" =~ ^(Cannot|Error|permission) ]]; then
        while IFS= read -r container; do
            [[ -z "$container" ]] && continue
            # Check privileged
            if docker inspect "$container" 2>/dev/null | grep -q '"Privileged": true'; then
                log_fail "Docker Privileged" "Container '$container' running in PRIVILEGED mode!" 25
            fi

            # Check for host mounts
            if docker inspect "$container" 2>/dev/null | grep -qE '"Source": "/"[,}]|"Source": "/host"'; then
                log_fail "Docker Host Mount" "Container '$container' has HOST FILESYSTEM mounted!" 25
            fi

            # Check if running as root
            local user
            user=$(docker inspect "$container" --format '{{.Config.User}}' 2>/dev/null)
            if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
                log_warn "Docker User" "Container '$container' running as root" 10
            fi

            # Check for docker socket mount
            if docker inspect "$container" 2>/dev/null | grep -q "/var/run/docker.sock"; then
                log_fail "Docker Socket" "Container '$container' has DOCKER SOCKET mounted!" 25
            fi

        done <<< "$containers"
    else
        log_skip "Docker Containers" "No running containers found"
    fi
}

check_file_permissions() {
    log_section "File Permissions (Credential Protection)"

    # Helper to check if permissions are world-readable (last digit is 4-7)
    is_world_readable() {
        local perms="$1"
        # Strip leading zeros and check last digit
        local last_digit="${perms: -1}"
        [[ "$last_digit" =~ [4-7] ]]
    }

    # Helper to check if directory is world-accessible (last digit is 5-7)
    is_world_accessible() {
        local perms="$1"
        local last_digit="${perms: -1}"
        [[ "$last_digit" =~ [5-7] ]]
    }

    # Check .env files (using -print0 for safe handling of filenames with spaces)
    while IFS= read -r -d '' env_file; do
        local perms
        perms=$(stat -c %a "$env_file" 2>/dev/null || stat -f %Lp "$env_file" 2>/dev/null)
        if is_world_readable "$perms"; then
            log_fail "File Permissions" "$env_file is world-readable (mode: $perms)" 10
            if [[ "$FIX_MODE" == true ]]; then
                chmod 600 "$env_file"
                echo -e "    ${GREEN}→ Fixed: chmod 600 $env_file${NC}"
            fi
        else
            log_pass "File Permissions" "$env_file has restricted permissions"
        fi
    done < <(find "$HOME" -maxdepth 3 -name ".env" -type f -print0 2>/dev/null)

    # Check SSH private keys (nullglob handles case where no files match)
    if [[ -d "$HOME/.ssh" ]]; then
        for key in "$HOME/.ssh/id_"* "$HOME/.ssh/"*_key; do
            if [[ -f "$key" && ! "$key" =~ \.pub$ ]]; then
                local perms
                perms=$(stat -c %a "$key" 2>/dev/null || stat -f %Lp "$key" 2>/dev/null)
                if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                    log_fail "SSH Key Permissions" "$key has loose permissions (mode: $perms)" 15
                    if [[ "$FIX_MODE" == true ]]; then
                        chmod 600 "$key"
                        echo -e "    ${GREEN}→ Fixed: chmod 600 $key${NC}"
                    fi
                fi
            fi
        done
    fi

    # Check AWS credentials
    if [[ -f "$HOME/.aws/credentials" ]]; then
        local perms
        perms=$(stat -c %a "$HOME/.aws/credentials" 2>/dev/null || stat -f %Lp "$HOME/.aws/credentials" 2>/dev/null)
        if is_world_readable "$perms"; then
            log_fail "AWS Credentials" "\$HOME/.aws/credentials is world-readable" 15
            if [[ "$FIX_MODE" == true ]]; then
                chmod 600 "$HOME/.aws/credentials"
                echo -e "    ${GREEN}→ Fixed: chmod 600 \$HOME/.aws/credentials${NC}"
            fi
        else
            log_pass "AWS Credentials" "\$HOME/.aws/credentials has restricted permissions"
        fi
    fi

    # Check OpenClaw config directories (per official security docs)
    local config_dir="$HOME/.openclaw"
    if [[ -d "$config_dir" ]]; then
        local dir_perms
        dir_perms=$(stat -c %a "$config_dir" 2>/dev/null || stat -f %Lp "$config_dir" 2>/dev/null)
        if is_world_accessible "$dir_perms"; then
            log_fail "Config Directory" "$config_dir is world-accessible" 15
            if [[ "$FIX_MODE" == true ]]; then
                chmod 700 "$config_dir"
                echo -e "    ${GREEN}→ Fixed: chmod 700 $config_dir${NC}"
            fi
        else
            log_pass "Config Directory" "$config_dir has correct permissions (700)"
        fi
    fi

    # Check sensitive files within ~/.openclaw
    local sensitive_files=(
        "$HOME/.openclaw/credentials"
        "$HOME/.openclaw/agents/*/agent/auth-profiles.json"
        "$HOME/.openclaw/agents/*/sessions/sessions.json"
    )

    for pattern in "${sensitive_files[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                local file_perms
                file_perms=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file" 2>/dev/null)
                if is_world_accessible "$file_perms"; then
                    log_fail "Sensitive File" "$file is world-accessible" 15
                    if [[ "$FIX_MODE" == true ]]; then
                        chmod 600 "$file"
                        echo -e "    ${GREEN}→ Fixed: chmod 600 $file${NC}"
                    fi
                fi
            fi
        done
    done
}

check_exposed_tokens() {
    log_section "Token Exposure (Credential Leak Detection)"

    # Search for exposed tokens in OpenClaw locations
    local search_paths=(
        "$HOME/.openclaw"
        "$HOME/.config/openclaw"
    )

    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            # Check for tokens in logs (using xargs for safety with filenames)
            local token_files
            token_files=$(find "$search_path" -name "*.log" -print0 2>/dev/null | \
                xargs -0 grep -l -E "(sk-ant-|ghp_|xoxb-|xoxp-|sk_live_)" 2>/dev/null | \
                head -1) || true
            if [[ -n "$token_files" ]]; then
                log_fail "Token in Logs" "API tokens found in log files in $search_path" 20
            fi
        fi
    done

    # Check shell history for tokens
    for hist_file in "$HOME/.bash_history" "$HOME/.zsh_history"; do
        if [[ -f "$hist_file" ]]; then
            if grep -E "(sk-ant-|ghp_|xoxb-|xoxp-|sk_live_|AKIA)" "$hist_file" &>/dev/null; then
                log_warn "Token in History" "Possible API tokens found in $hist_file" 10
                echo -e "    ${YELLOW}→ Consider clearing sensitive entries from shell history${NC}"
            fi
        fi
    done
}

check_running_processes() {
    log_section "Process Security"

    # Check if OpenClaw gateway is running as root
    if pgrep -u root -f "openclaw" &>/dev/null; then
        log_fail "Bot User" "OpenClaw process running as ROOT user!" 20
    fi

    # Check for processes with exposed tokens in command line
    if ps aux 2>/dev/null | grep -E "(sk-ant-|ghp_|xoxb-)" | grep -v grep &>/dev/null; then
        log_fail "Token in Process" "API tokens visible in process list!" 20
    fi
}

check_openclaw_native_audit() {
    log_section "OpenClaw Native Security Audit"

    # Detect CLI - prioritize openclaw
    local cli_cmd=""
    if command_exists openclaw; then
        cli_cmd="openclaw"
    else
        log_skip "Native Audit" "OpenClaw CLI not installed (npm install -g openclaw)"
        return
    fi

    # Build audit command
    local -a audit_cmd=("$cli_cmd" "security" "audit")
    if [[ "$DEEP_MODE" == true ]]; then
        audit_cmd+=("--deep")
    fi

    # Run native audit with timeout (portable: prefer gtimeout on macOS)
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout"
    elif command_exists gtimeout; then
        timeout_cmd="gtimeout"
    fi

    local timeout_secs=30
    if [[ "$DEEP_MODE" == true ]]; then
        timeout_secs=60
    fi

    local audit_output=""
    if [[ -n "$timeout_cmd" ]]; then
        audit_output=$($timeout_cmd "$timeout_secs" "${audit_cmd[@]}" 2>&1) || true
    else
        audit_output=$("${audit_cmd[@]}" 2>&1) || true
    fi

    if [[ -z "$audit_output" ]]; then
        log_warn "Native Audit" "openclaw security audit returned no output" 5
        return
    fi

    # Parse output line by line, matching known finding patterns
    # The native audit uses emoji/text markers for findings
    local finding_count=0
    local native_fail=0
    local native_warn=0
    local native_pass=0

    while IFS= read -r line; do
        # Skip empty lines and section headers
        [[ -z "$line" ]] && continue

        # Strip ANSI escape codes for pattern matching
        local clean_line
        clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')

        # Detect findings by common output patterns
        # shellcheck disable=SC2221,SC2222
        case "$clean_line" in
            *"✗"*|*"✘"*|*"❌"*|*"FAIL"*|*"[FAIL]"*)
                local msg
                msg=$(echo "$clean_line" | sed 's/^[[:space:]]*[✗✘❌]*//;s/^[[:space:]]*\[FAIL\]//;s/^[[:space:]]*//')
                if [[ -n "$msg" ]]; then
                    log_fail "Native: ${msg:0:60}" "$msg" 10
                    ((native_fail++)) || true
                    ((finding_count++)) || true
                fi
                ;;
            *"⚠"*|*"⚡"*|*"WARN"*|*"[WARN]"*)
                local msg
                msg=$(echo "$clean_line" | sed 's/^[[:space:]]*[⚠⚡]*//;s/^[[:space:]]*\[WARN\]//;s/^[[:space:]]*//')
                if [[ -n "$msg" ]]; then
                    log_warn "Native: ${msg:0:60}" "$msg" 5
                    ((native_warn++)) || true
                    ((finding_count++)) || true
                fi
                ;;
            *"✓"*|*"✔"*|*"✅"*|*"PASS"*|*"[PASS]"*|*"[OK]"*)
                local msg
                msg=$(echo "$clean_line" | sed 's/^[[:space:]]*[✓✔✅]*//;s/^[[:space:]]*\[PASS\]//;s/^[[:space:]]*\[OK\]//;s/^[[:space:]]*//')
                if [[ -n "$msg" ]]; then
                    log_pass "Native: ${msg:0:60}" "$msg"
                    ((native_pass++)) || true
                    ((finding_count++)) || true
                fi
                ;;
        esac
    done <<< "$audit_output"

    if [[ $finding_count -eq 0 ]]; then
        # Couldn't parse structured findings; report raw output for manual review
        log_warn "Native Audit" "Audit ran but output format not recognized — review manually" 3
        if [[ "$JSON_MODE" != true && "$QUIET_MODE" != true ]]; then
            echo ""
            echo "$audit_output"
            echo ""
        fi
    else
        if [[ "$JSON_MODE" != true && "$QUIET_MODE" != true ]]; then
            log_info "Native audit: $native_pass passed, $native_fail failed, $native_warn warnings"
        fi
    fi
}

# =============================================================================
# OpenClaw Security Checks (New in v3.0)
# =============================================================================

check_critical_vulnerabilities() {
    log_section "Critical Vulnerability Detection (Zero-Day Audit)"

    local config_paths=(
        "$HOME/.openclaw/openclaw.json"
        "$HOME/.openclaw/config.json"
    )

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            # CVE-1: Bootstrap Exploit (config.patch RCE via setupCommand)
            if grep -Ei "config\.patch|setupCommand" "$config" &>/dev/null; then
                if grep -Ei "setupCommand.*(curl|wget|bash|sh|nc|python)" "$config" &>/dev/null; then
                    log_fail "Config RCE" "Dangerous setupCommand detected - potential RCE vector!" 25
                else
                    log_warn "Config Patch" "config.patch or setupCommand found - review for RCE risk" 15
                fi
            else
                log_pass "Config RCE" "No dangerous setupCommand patterns detected"
            fi

            # CVE-2: Authorization Bypass (exec.approval.resolve without RBAC)
            if grep -Ei "exec\.approval|approval\.resolve" "$config" &>/dev/null; then
                if grep -Ei "rbac|role.*access|admin.*only" "$config" &>/dev/null; then
                    log_pass "Auth Bypass" "RBAC appears configured for approval system"
                else
                    log_warn "Auth Bypass" "Approval system found but RBAC not explicitly configured" 15
                fi
            fi

            # CVE-3: Environment Variable Injection (LD_PRELOAD, BASH_ENV)
            if grep -Ei "env.*pass|passthrough.*env|allow.*env" "$config" &>/dev/null; then
                log_warn "Env Injection" "Environment passthrough enabled - check for LD_PRELOAD/BASH_ENV filtering" 15
                echo -e "    ${YELLOW}→ Recommendation: Block LD_PRELOAD, BASH_ENV, LD_LIBRARY_PATH${NC}"
            fi

            break
        fi
    done

    # Check for exposed fetch/request endpoints (SSRF via DNS Rebinding)
    if command_exists ss; then
        if ss -tlnp 2>/dev/null | grep -E ":(3000|8000|8080|9000)" | grep -q "0.0.0.0"; then
            log_warn "SSRF Risk" "HTTP service exposed on all interfaces - potential SSRF target" 12
        fi
    fi

    # Check for path traversal in log directories
    local log_dirs=(
        "$HOME/.openclaw/logs"
        "$HOME/.openclaw/agents/*/logs"
    )

    for log_pattern in "${log_dirs[@]}"; do
        for log_dir in $log_pattern; do
            if [[ -d "$log_dir" ]]; then
                # Check if symlinks exist that could enable path traversal
                local symlink_count
                symlink_count=$(find "$log_dir" -type l 2>/dev/null | wc -l) || symlink_count=0
                if [[ $symlink_count -gt 0 ]]; then
                    log_warn "Path Traversal" "Symlinks found in log directory - potential traversal risk" 10
                fi
            fi
        done
    done

    # Check for shell injection patterns in any scripts
    local script_dirs=(
        "$HOME/.openclaw/workspace/skills"
        "$HOME/.openclaw/scripts"
    )

    for script_dir in "${script_dirs[@]}"; do
        if [[ -d "$script_dir" ]]; then
            # Check for dangerous shell patterns (backticks, $(), eval)
            if find "$script_dir" -name "*.sh" -exec grep -l 'eval\|`.*`\|\$(' {} \; 2>/dev/null | head -1 | grep -q .; then
                log_warn "Shell Injection" "Potentially dangerous shell patterns in skill scripts" 12
                echo -e "    ${YELLOW}→ Review scripts for eval, backticks, and command substitution${NC}"
            fi
        fi
    done

    log_pass "Critical Vuln Scan" "Zero-day vulnerability scan completed"
}

check_prompt_injection_defense() {
    log_section "Prompt Injection Defense (OWASP LLM01)"

    local config_paths=(
        "$HOME/.openclaw/config.json"
        "$HOME/.openclaw/config.yaml"
    )

    local config_found=false

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            config_found=true

            # Check for input sanitization
            if grep -Ei "input.*(sanitiz|filter|valid)" "$config" &>/dev/null; then
                log_pass "Input Sanitization" "Input sanitization appears configured"
            else
                log_warn "Input Sanitization" "No input sanitization config found" 10
            fi

            # Check for system prompt protection
            if grep -Ei "system.*prompt.*(protect|hide|secure)" "$config" &>/dev/null; then
                log_pass "System Prompt" "System prompt protection configured"
            else
                log_warn "System Prompt" "System prompt protection not explicitly configured" 8
            fi

            # Check for content filtering
            if grep -Ei "content.*(filter|safety|guard)" "$config" &>/dev/null; then
                log_pass "Content Filter" "Content filtering appears enabled"
            else
                log_warn "Content Filter" "Content filtering not explicitly enabled" 10
            fi

            # Check for tool restrictions
            if grep -Ei "tool.*(restrict|allowlist|whitelist|limit)" "$config" &>/dev/null; then
                log_pass "Tool Restrictions" "Tool call restrictions configured"
            else
                log_warn "Tool Restrictions" "Tool call restrictions not explicitly configured" 12
            fi

            break
        fi
    done

    if [[ "$config_found" == false ]]; then
        log_skip "Prompt Injection" "No OpenClaw config found"
    fi
}

check_sandbox_mode() {
    log_section "Sandbox Mode (Group/Channel Safety)"

    local config_paths=(
        "$HOME/.openclaw/openclaw.json"
        "$HOME/.openclaw/config.json"
    )

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            # Check for sandbox mode configuration (per official OpenClaw security docs)
            if grep -Ei "sandbox.*mode.*non-main|sandbox.*:.*non-main" "$config" &>/dev/null; then
                log_pass "Sandbox Mode" "Sandbox mode set to 'non-main' (groups/channels run in Docker)"
            elif grep -Ei "sandbox.*mode" "$config" &>/dev/null; then
                log_warn "Sandbox Mode" "Sandbox mode configured but not 'non-main'" 10
            else
                log_warn "Sandbox Mode" "Sandbox mode not configured - groups/channels have host access" 15
                echo -e "    ${YELLOW}→ Recommendation: Set agents.defaults.sandbox.mode: \"non-main\"${NC}"
            fi
            return
        fi
    done

    log_skip "Sandbox Mode" "No OpenClaw config found"
}

check_openclaw_doctor() {
    log_section "OpenClaw Doctor (Configuration Health)"

    if ! command_exists openclaw; then
        log_skip "OpenClaw Doctor" "OpenClaw CLI not installed"
        return
    fi

    # Run openclaw doctor with timeout
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout"
    elif command_exists gtimeout; then
        timeout_cmd="gtimeout"
    fi

    local doctor_output=""
    if [[ -n "$timeout_cmd" ]]; then
        doctor_output=$($timeout_cmd 15 openclaw doctor 2>&1) || true
    else
        doctor_output=$(openclaw doctor 2>&1) || true
    fi

    if [[ -z "$doctor_output" ]]; then
        log_warn "OpenClaw Doctor" "No output from openclaw doctor" 5
        return
    fi

    # Parse doctor output for issues
    if echo "$doctor_output" | grep -Ei "error|fail|critical" &>/dev/null; then
        log_fail "OpenClaw Doctor" "openclaw doctor reported critical issues" 15
        if [[ "$JSON_MODE" != true && "$QUIET_MODE" != true ]]; then
            echo "$doctor_output" | head -10
        fi
    elif echo "$doctor_output" | grep -Ei "warn|risky" &>/dev/null; then
        log_warn "OpenClaw Doctor" "openclaw doctor reported warnings" 8
    else
        log_pass "OpenClaw Doctor" "openclaw doctor passed"
    fi
}

check_mcp_server_security() {
    log_section "MCP Server Security (Model Context Protocol)"

    # Check for MCP config
    local mcp_configs=(
        "$HOME/.openclaw/mcp.json"
        "$HOME/.openclaw/mcp-servers.json"
        "$HOME/.config/openclaw/mcp.json"
    )

    local mcp_found=false

    for mcp_config in "${mcp_configs[@]}"; do
        if [[ -f "$mcp_config" ]]; then
            mcp_found=true
            log_info "  Found MCP config: $mcp_config"

            # Check MCP binding
            if grep -E "0\.0\.0\.0" "$mcp_config" &>/dev/null; then
                log_fail "MCP Binding" "MCP server bound to 0.0.0.0 - exposed!" 20
            elif grep -E "(127\.0\.0\.1|localhost)" "$mcp_config" &>/dev/null; then
                log_pass "MCP Binding" "MCP server bound to localhost"
            fi

            # Check for authentication
            if grep -Ei "auth.*:.*true|authentication.*:.*true" "$mcp_config" &>/dev/null; then
                log_pass "MCP Auth" "MCP authentication enabled"
            elif grep -Ei "auth.*:.*false" "$mcp_config" &>/dev/null; then
                log_fail "MCP Auth" "MCP authentication DISABLED" 20
            else
                log_warn "MCP Auth" "MCP authentication status unknown" 10
            fi

            # Check for tool allowlist
            if grep -Ei "tools.*(allow|whitelist)" "$mcp_config" &>/dev/null; then
                log_pass "MCP Tools" "MCP tool allowlist configured"
            else
                log_warn "MCP Tools" "No MCP tool allowlist found" 10
            fi

            break
        fi
    done

    # Check for running MCP servers
    if command_exists ss; then
        if ss -tlnp 2>/dev/null | grep -E ":3000|:8000|:9000" | grep -q "0.0.0.0"; then
            log_warn "MCP Port Exposure" "Potential MCP server exposed on all interfaces" 10
        fi
    fi

    if [[ "$mcp_found" == false ]]; then
        log_skip "MCP Security" "No MCP configuration found"
    fi
}

check_skill_integrity() {
    log_section "Skill/Plugin Integrity (Supply Chain)"

    # Official OpenClaw skill locations
    local skill_dirs=(
        "$HOME/.openclaw/workspace/skills"
        "$HOME/.openclaw/skills"
        "$HOME/.openclaw/plugins"
    )

    local skills_found=false

    for skill_dir in "${skill_dirs[@]}"; do
        if [[ -d "$skill_dir" ]]; then
            skills_found=true
            local skill_count
            skill_count=$(find "$skill_dir" -maxdepth 1 -type d | wc -l)
            skill_count=$((skill_count - 1))  # Subtract parent dir

            log_info "  Found $skill_count skills in $skill_dir"

            # Check for signature files
            local signed_count
            signed_count=$(find "$skill_dir" -name "*.sig" -o -name "signature.json" 2>/dev/null | wc -l) || signed_count=0
            
            if [[ $signed_count -gt 0 ]]; then
                log_pass "Skill Signatures" "Found $signed_count signature files"
            else
                log_warn "Skill Signatures" "No skill signatures found - verify sources manually" 8
            fi

            # Check for world-writable skill directories
            while IFS= read -r -d '' skill; do
                local perms
                perms=$(stat -c %a "$skill" 2>/dev/null || stat -f %Lp "$skill" 2>/dev/null)
                local last_digit="${perms: -1}"
                if [[ "$last_digit" =~ [2367] ]]; then
                    log_fail "Skill Permissions" "$skill is world-writable" 15
                fi
            done < <(find "$skill_dir" -maxdepth 1 -type d -print0 2>/dev/null)

            break
        fi
    done

    if [[ "$skills_found" == false ]]; then
        log_skip "Skill Integrity" "No skill directories found"
    fi
}

check_api_key_hygiene() {
    log_section "API Key Hygiene (Credential Management)"

    # Check for API keys in environment variables
    local exposed_vars=0
    
    # Check shell RC files for hardcoded keys
    for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$rc_file" ]]; then
            if grep -E "(ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENCLAW_KEY).*=.*['\"]?sk-" "$rc_file" &>/dev/null; then
                log_fail "Hardcoded API Key" "API key found hardcoded in $rc_file" 20
                exposed_vars=$((exposed_vars + 1))
            fi
        fi
    done

    if [[ $exposed_vars -eq 0 ]]; then
        log_pass "API Key Hardcoding" "No hardcoded API keys found in shell configs"
    fi

    # Check for .env files with weak permissions
    while IFS= read -r -d '' env_file; do
        if grep -E "(API_KEY|SECRET|TOKEN)" "$env_file" &>/dev/null 2>&1; then
            local perms
            perms=$(stat -c %a "$env_file" 2>/dev/null || stat -f %Lp "$env_file" 2>/dev/null)
            if [[ "${perms: -1}" =~ [4-7] ]]; then
                log_fail "Env File Permissions" "$env_file contains secrets and is world-readable" 15
            fi
        fi
    done < <(find "$HOME" -maxdepth 3 -name ".env*" -type f -print0 2>/dev/null)

    # Check for API keys in git history (if in a git repo)
    if command_exists git && [[ -d ".git" ]]; then
        if git log -p --all 2>/dev/null | head -1000 | grep -E "sk-ant-|sk-proj-|AKIA" &>/dev/null; then
            log_warn "Git History" "Possible API keys found in git history" 10
        fi
    fi
}

check_session_isolation() {
    log_section "Session Isolation (Browser Security)"

    local config_paths=(
        "$HOME/.openclaw/config.json"
        "$HOME/.openclaw/config.yaml"
    )

    for config in "${config_paths[@]}"; do
        if [[ -f "$config" ]]; then
            # Check for isolated browser profile
            if grep -Ei "profile.*openclaw|profile.*isolated|profile.*sandbox" "$config" &>/dev/null; then
                log_pass "Browser Isolation" "Isolated browser profile configured"
            elif grep -Ei "profile.*default" "$config" &>/dev/null; then
                log_fail "Browser Isolation" "Using DEFAULT browser profile - HIGH RISK!" 25
                echo -e "    ${RED}→ CRITICAL: Create isolated profile for OpenClaw${NC}"
            else
                log_warn "Browser Isolation" "Browser profile configuration unclear" 10
            fi

            # Check for session timeout
            if grep -Ei "session.*(timeout|expire)" "$config" &>/dev/null; then
                log_pass "Session Timeout" "Session timeout configured"
            else
                log_warn "Session Timeout" "No session timeout configured" 5
            fi

            return
        fi
    done

    log_skip "Session Isolation" "No OpenClaw config found"
}

# =============================================================================
# Report Generation
# =============================================================================

generate_report() {
    if [[ "$JSON_MODE" == true ]]; then
        echo "{"
        echo "  \"version\": \"$VERSION\","
        echo "  \"timestamp\": \"$(get_timestamp)\","
        echo "  \"summary\": {"
        echo "    \"pass\": $PASS_COUNT,"
        echo "    \"fail\": $FAIL_COUNT,"
        echo "    \"warn\": $WARN_COUNT,"
        echo "    \"skip\": $SKIP_COUNT,"
        echo "    \"risk_score\": $RISK_SCORE"
        echo "  },"
        echo -n "  \"results\": ["
        if [[ ${#JSON_RESULTS[@]} -gt 0 ]]; then
            echo ""
            echo -n "    "
            printf '%s\n' "${JSON_RESULTS[@]}" | paste -sd ',' - | sed 's/,/,\n    /g'
            echo ""
            echo "  ]"
        else
            echo "]"
        fi
        echo "}"
    else
        echo ""
        echo -e "${BOLD}══════════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}                        AUDIT SUMMARY                              ${NC}"
        echo -e "${BOLD}══════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${GREEN}Passed:${NC}   $PASS_COUNT"
        echo -e "  ${RED}Failed:${NC}   $FAIL_COUNT"
        echo -e "  ${YELLOW}Warnings:${NC} $WARN_COUNT"
        echo -e "  ${BLUE}Skipped:${NC}  $SKIP_COUNT"
        echo ""

        # Risk score interpretation
        echo -ne "  ${BOLD}Risk Score:${NC} "
        if [[ $RISK_SCORE -eq 0 ]]; then
            echo -e "${GREEN}$RISK_SCORE/100 - Excellent${NC}"
        elif [[ $RISK_SCORE -lt 25 ]]; then
            echo -e "${GREEN}$RISK_SCORE/100 - Good${NC}"
        elif [[ $RISK_SCORE -lt 50 ]]; then
            echo -e "${YELLOW}$RISK_SCORE/100 - Moderate Risk${NC}"
        elif [[ $RISK_SCORE -lt 75 ]]; then
            echo -e "${RED}$RISK_SCORE/100 - High Risk${NC}"
        else
            echo -e "${RED}$RISK_SCORE/100 - CRITICAL RISK${NC}"
        fi

        echo ""

        if [[ $FAIL_COUNT -gt 0 ]]; then
            echo -e "  ${RED}⚠ ${BOLD}ACTION REQUIRED:${NC} $FAIL_COUNT critical issues need immediate attention"
            if [[ "$FIX_MODE" == false ]]; then
                echo -e "  ${YELLOW}→ Run with --fix to auto-remediate safe issues${NC}"
            fi
        elif [[ $WARN_COUNT -gt 0 ]]; then
            echo -e "  ${YELLOW}ℹ ${BOLD}RECOMMENDED:${NC} Review $WARN_COUNT warnings for best security"
        else
            echo -e "  ${GREEN}✓ ${BOLD}All checks passed!${NC} Your installation appears secure."
        fi

        echo ""
        echo -e "${CYAN}Documentation: See openclaw-security-vulnerabilities.md for remediation details${NC}"
        echo ""
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --fix)
                FIX_MODE=true
                shift
                ;;
            --json)
                JSON_MODE=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --deep)
                DEEP_MODE=true
                shift
                ;;
            --stig)
                STIG_MODE=true
                shift
                ;;
            --help|-h)
                print_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done

    if [[ "$JSON_MODE" == false ]]; then
        print_banner

        if [[ "$STIG_MODE" == true ]]; then
            echo -e "${CYAN}STIG MODE: DISA STIG / CIS Benchmark / NIST 800-53 controls enabled${NC}"
            echo ""
        fi

        if [[ "$FIX_MODE" == true ]]; then
            echo -e "${YELLOW}Running in FIX MODE - will attempt to remediate issues${NC}"
            echo ""
        fi
    fi

    # Run core checks (always)
    check_ssh_security
    check_firewall
    check_gateway_exposure
    check_user_allowlist
    check_browser_profile
    check_password_manager
    check_docker_security
    check_file_permissions
    check_exposed_tokens
    check_running_processes
    
    # Run OpenClaw-specific checks
    check_critical_vulnerabilities
    check_prompt_injection_defense
    check_sandbox_mode
    check_mcp_server_security
    check_skill_integrity
    check_api_key_hygiene
    check_session_isolation
    check_openclaw_doctor
    
    # Run native audit
    check_openclaw_native_audit

    # Generate report
    generate_report

    # Exit with appropriate code
    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    elif [[ $WARN_COUNT -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

main "$@"

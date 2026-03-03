#!/usr/bin/env bash
# gigaspray - credential tracking and spraying tool for OSCP/CTF

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Globals ──────────────────────────────────────────────────────────────────
TOOL_NAME="gigaspray"
GS_DIR=""   # resolved at runtime via require_gs_dir() or resolve_gs_dir()
SPRAY_PROTOCOLS=(smb rdp winrm ssh ldap ftp mssql)
SPRAY_QUIET=0      # -q: filter terminal output to [+] hits only
SPRAY_OUTNAME=""   # -o <name>: save full output to logs/<name>
SPRAY_HOSTS=""     # --spray-hosts / -h: override default hosts_ip.txt target
SPRAY_EPHEMERAL_USER=""  # -u (standalone): ephemeral user, not saved to files
SPRAY_EPHEMERAL_PASS=""  # -p (standalone): ephemeral pass, not saved to files
SPRAY_EPHEMERAL_HASH=""  # -H (standalone): ephemeral hash, not saved to files
DNS_SERVER=""            # --dns-server: override DNS server for bulk host resolution
VERBOSE=0                # -v: show per-item detail during bulk imports
SPRAY_LOCAL_AUTH=0       # 1=also spray with --local-auth; loaded from config, CLI overrides
_WRITE_CRED_ADDED=0      # internal: set to 1 by write_cred() when anything new is added
_CLEAN_REMOVED=0         # internal: duplicate count accumulated by cmd_clean helpers

# ─── Helpers ──────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[!]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

log_entry() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] $*" >> "${GS_DIR}/logs/gigaspray.log"
}

banner() {
    echo -e "${BOLD}${CYAN}"
    cat << 'EOF'
  _____ _                 _____
 / ____(_)               / ____|
| |  __ _  __ _  __ _  | (___  _ __  _ __ __ _ _   _
| | |_ | |/ _` |/ _` |  \___ \| '_ \| '__/ _` | | | |
| |__| | | (_| | (_| |  ____) | |_) | | | (_| | |_| |
 \_____|_|\__, |\__,_| |_____/| .__/|_|  \__,_|\__, |
           __/ |               | |               __/ |
          |___/                |_|              |___/
EOF
    echo -e "${RESET}"
    echo -e "  ${BOLD}Credential tracker & spray automation for OSCP/CTF${RESET}"
    echo
}

# ─── Load (and auto-create) ~/.config/gigaspray/gigaspray.conf ───────────────
load_config() {
    local conf_dir="${HOME}/.config/gigaspray"
    local conf="${conf_dir}/gigaspray.conf"

    # Create default config on first run
    if [[ ! -f "$conf" ]]; then
        mkdir -p "$conf_dir"
        cat > "$conf" << 'EOF'
# gigaspray configuration
# local-auth: also spray with --local-auth (test local accounts in addition to domain)
local-auth=True
EOF
    fi

    # Parse key=value pairs
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        local line="${raw%%#*}"                 # strip inline comments
        [[ -z "${line//[[:space:]]/}" ]] && continue  # skip blank lines
        [[ "$line" != *=* ]] && continue
        local key="${line%%=*}"
        local value="${line#*=}"
        key="${key//[[:space:]]/}"
        value="${value//[[:space:]]/}"
        [[ -z "$key" ]] && continue
        case "$key" in
            local-auth)
                case "${value,,}" in
                    true|1|yes)  SPRAY_LOCAL_AUTH=1 ;;
                    false|0|no)  SPRAY_LOCAL_AUTH=0 ;;
                esac ;;
        esac
    done < "$conf"
}

usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $TOOL_NAME [global options] <command> [command options]"
    echo
    # ── Global options ────────────────────────────────────────────────────────
    echo -e "${BOLD}Global options:${RESET}"
    echo "  -d <path>              Workspace path (overrides \$GIGASPRAY_DIR)"
    echo "  -v                     Verbose — show per-item detail during bulk imports."
    echo "                         Default is quiet: only summary counts are printed."
    echo
    echo "  --local-auth           Also spray with --local-auth (test local accounts)."
    echo "                         Overrides the config file setting for this run."
    echo "  --no-local-auth        Disable local-auth spray for this run."
    echo "                         Config: ~/.config/gigaspray/gigaspray.conf"
    echo "                           local-auth=True   (default)"
    echo "                           local-auth=False"
    echo
    echo -e "${BOLD}Spray output options${RESET} (apply to all spray commands):"
    echo "  -q                     Quiet — show only [+] hits on terminal."
    echo "                         Named outfile and gigaspray.log still get full output."
    echo "  -o <name>              Save full spray output to logs/<name>."
    echo "                         Also appended to gigaspray.log."
    echo
    echo -e "${BOLD}Spray target option${RESET} (applies to all spray commands):"
    echo "  --spray-hosts <value>  Override the default spray target (hosts_ip.txt)."
    echo "  -h <value>             Shorthand for --spray-hosts (standalone spray only)."
    echo "                         <value> is one of:"
    echo "                           • a single IP       e.g. 10.10.10.5"
    echo "                           • a single domain   e.g. corp.local"
    echo "                           • a single FQDN     e.g. dc01.corp.local"
    echo "                           • a file of targets (one entry per line)"
    echo "                         If omitted, hosts_ip.txt in the workspace is used."
    echo
    echo -e "${BOLD}Ephemeral credential options${RESET} (standalone spray only — NOT saved to workspace):"
    echo "  -u <user>              Use this username for the spray without saving it."
    echo "  -p <pass>              Use this password for the spray without saving it."
    echo "  -H <hash>              Use this hash for the spray without saving it."
    echo "                         Unspecified sides fall back to workspace files:"
    echo "                           -u only  → all_pass.txt + all_hashes.txt"
    echo "                           -p only  → all_user.txt"
    echo "                           -H only  → all_user.txt"
    echo "                           -h only  → all_user.txt × all_pass.txt + all_hashes.txt"
    echo
    # ── Commands ──────────────────────────────────────────────────────────────
    echo -e "${BOLD}Commands:${RESET}"
    echo "  init                   Create a new gigaspray workspace"
    echo "  --add                  Add credentials or hosts to the workspace"
    echo "  --clean                Remove duplicates from all workspace files."
    echo "                         Simple files (all_user.txt, all_pass.txt, etc.)"
    echo "                         are deduplicated by exact line. Paired files"
    echo "                         (user_paired/pass_paired, hash_user_paired/"
    echo "                         hashes_paired) are deduplicated on the (user, cred)"
    echo "                         pair — one user with multiple passwords and multiple"
    echo "                         users sharing a password are both preserved."
    echo "  --spray-<proto>        Standalone spray for a specific protocol"
    echo "  --spray-all            Standalone spray across all protocols"
    echo
    # ── --add options ─────────────────────────────────────────────────────────
    echo -e "${BOLD}--add credential options:${RESET}"
    echo "  -u <user>              Username"
    echo "  -p <pass>              Password (quote to protect special characters)"
    echo "  -H <hash>              NTLM hash"
    echo "  --desc <text>          Description written to creds.txt"
    echo "  -U <file>              Import usernames from file (one per line)"
    echo "  -P <file>              Import passwords from file (one per line)"
    echo "  -L <file>              Import user:pass pairs from file (one per line)"
    echo "                         Passwords containing colons are handled correctly."
    echo "  --secretsdump <file>   Import from secretsdump output."
    echo "                         Parses username and NT hash from each line:"
    echo "                           username:RID:LM_hash:NT_hash:::"
    echo "                         DOMAIN\\ prefix is stripped from usernames."
    echo "                         Machine accounts (ending in \$) are included."
    echo
    echo -e "${BOLD}--add host options:${RESET}"
    echo "  -h <value>             Add a host by IP, domain name, FQDN, or file."
    echo "                         Single-value type is auto-detected:"
    echo "                           • IP    → hosts_ip.txt"
    echo "                           • FQDN  → hosts_fqdn.txt  (2+ dots)"
    echo "                           • other → hosts_dn.txt"
    echo "                         When an IP is given, nxc smb probes it to resolve"
    echo "                         hostname and domain, then populates all host files."
    echo "                         When <value> is a FILE, bulk import is performed:"
    echo "                           • /etc/hosts format → auto-detected, IPs + hostnames parsed"
    echo "                           • plain list        → one IP/domain/FQDN per line;"
    echo "                                                 domains are DNS-resolved to IPs"
    echo "                         hosts.txt is regenerated via nxc after every add."
    echo "  --dns-server <ip>      DNS server to use when resolving domains during"
    echo "                         plain-list bulk import. Defaults to the default"
    echo "                         gateway (ip route show default), then system default."
    echo
    # ── Spray protocol flags ──────────────────────────────────────────────────
    echo -e "${BOLD}Spray protocol flags${RESET} (usable with --add or standalone):"
    echo "  --spray-smb            SMB (port 445)"
    echo "  --spray-rdp            RDP (port 3389)"
    echo "  --spray-winrm          WinRM (port 5985/5986)"
    echo "  --spray-ssh            SSH (port 22)"
    echo "  --spray-ldap           LDAP (port 389)"
    echo "  --spray-ftp            FTP (port 21)"
    echo "  --spray-mssql          MSSQL (port 1433)"
    echo "  --spray-all            All of the above in sequence"
    echo
    echo -e "  All sprays use ${BOLD}--continue-on-success${RESET}."
    echo -e "  When combined with ${BOLD}--add${RESET}, the newly-added credential is used as the"
    echo    "  fixed input; the other side falls back to the workspace credential files:"
    echo    "    new user only  → spray with all_pass.txt and all_hashes.txt"
    echo    "    new pass only  → spray with all_user.txt"
    echo    "    new hash only  → spray with all_user.txt"
    echo    "    new user+pass  → spray that specific pair (+ all_hashes.txt)"
    echo    "    standalone     → spray all_user.txt × all_pass.txt + all_hashes.txt"
    echo
    # ── Examples ──────────────────────────────────────────────────────────────
    echo -e "${BOLD}Examples:${RESET}"
    echo    "  # Workspace setup"
    echo    "  $TOOL_NAME init"
    echo
    echo    "  # Add credentials"
    echo    "  $TOOL_NAME --add -u john -p 'P@\$\$w0rd' --desc 'found in web.config'"
    echo    "  $TOOL_NAME --add -u john -H aad3b435b51404eeaad3b435b51404ee"
    echo    "  $TOOL_NAME --add 'john:P@\$\$w0rd'                  # inline user:pass"
    echo    "  $TOOL_NAME --add -U users.txt -P passes.txt         # paired file import"
    echo    "  $TOOL_NAME --add -L creds.txt                       # user:pass file import"
    echo    "  $TOOL_NAME --add --secretsdump hashes.txt           # secretsdump NT hashes"
    echo    "  $TOOL_NAME --add --secretsdump hashes.txt --spray-smb  # import then spray"
    echo
    echo    "  # Add a host"
    echo    "  $TOOL_NAME --add -h 10.10.10.5       # IP — nxc probes for hostname/domain"
    echo    "  $TOOL_NAME --add -h dc01.corp.local  # FQDN"
    echo    "  $TOOL_NAME --add -h corp.local       # domain name"
    echo
    echo    "  # Bulk host import from file"
    echo    "  $TOOL_NAME --add -h ips.txt                            # plain IP list"
    echo    "  $TOOL_NAME --add -h domains.txt                        # plain domain list (DNS via default gateway)"
    echo    "  $TOOL_NAME --add -h domains.txt --dns-server 10.10.10.1  # custom DNS server"
    echo    "  $TOOL_NAME --add -h /etc/hosts                         # /etc/hosts format auto-detected"
    echo
    echo    "  # Add creds then spray immediately"
    echo    "  $TOOL_NAME --add -u john -p 'P@\$\$w0rd' --spray-smb"
    echo    "  $TOOL_NAME --add -u john --spray-smb --spray-winrm  # new user, all passes"
    echo    "  $TOOL_NAME --add -p 'P@\$\$w0rd' --spray-all        # new pass, all users"
    echo
    echo    "  # Standalone sprays (use existing workspace files)"
    echo    "  $TOOL_NAME --spray-smb"
    echo    "  $TOOL_NAME --spray-all"
    echo
    echo    "  # Spray output control"
    echo    "  $TOOL_NAME --spray-smb -q                    # hits only on terminal"
    echo    "  $TOOL_NAME --spray-smb -o smb_round1         # save output to logs/smb_round1"
    echo    "  $TOOL_NAME --spray-smb -q -o smb_round1      # both"
    echo
    echo    "  # Override spray target"
    echo    "  $TOOL_NAME --spray-smb --spray-hosts 10.10.10.5"
    echo    "  $TOOL_NAME --spray-smb --spray-hosts dc01.corp.local"
    echo    "  $TOOL_NAME --spray-smb --spray-hosts targets.txt"
    echo    "  $TOOL_NAME --add -u john -p pass --spray-smb --spray-hosts 10.10.10.5"
    echo
    echo    "  # Ephemeral spray (no workspace files modified)"
    echo    "  $TOOL_NAME -h 10.10.10.5 --spray-rdp            # one host, all creds"
    echo    "  $TOOL_NAME -h 10.10.10.5 -u john --spray-rdp   # one host+user, all passes/hashes"
    echo    "  $TOOL_NAME -u john --spray-smb                  # one user, all passes/hashes"
    echo    "  $TOOL_NAME -p 'P@\$\$w0rd' --spray-all          # one pass, all users"
    echo    "  $TOOL_NAME -H aad3b435... --spray-smb           # one hash, all users"
}

# ─── Detect whether a string is an IPv4, FQDN, domain name, or short hostname ─
# Prints one of: ip | fqdn | domain | hostname
detect_host_type() {
    local val="$1"
    # IPv4
    if [[ "$val" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ip"; return
    fi
    # Count dots
    local nodots="${val//./}"
    local dot_count=$(( ${#val} - ${#nodots} ))
    if   [[ $dot_count -ge 2 ]]; then echo "fqdn"
    elif [[ $dot_count -eq 1 ]]; then echo "domain"
    else                               echo "hostname"
    fi
}

# ─── Run nxc smb against an IP and parse name/domain from output ──────────────
# Prints two lines on stdout: "<name>" then "<domain>". Either may be empty.
# All human-readable status goes to stderr so callers can safely capture stdout.
resolve_via_nxc() {
    local ip="$1"
    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping automatic hostname resolution" >&2
        echo ""; echo ""; return
    fi
    info "Running: nxc smb ${ip} (resolving hostname/domain...)" >&2
    local out
    out="$(nxc smb "$ip" 2>/dev/null)" || true
    # Output line format:
    #   SMB  10.10.10.5  445  DC01  [*] ... (name:DC01) (domain:corp.local) ...
    local name domain
    name="$(echo   "$out" | grep -oP '(?<=\(name:)[^)]+' | head -1)" || true
    domain="$(echo "$out" | grep -oP '(?<=\(domain:)[^)]+' | head -1)" || true
    echo "$name"
    echo "$domain"
}

# ─── Regenerate hosts.txt via nxc --generate-hosts-file ──────────────────────
regenerate_hosts_file() {
    if [[ ! -s "${GS_DIR}/hosts_ip.txt" ]]; then
        warn "hosts_ip.txt is empty — skipping hosts.txt regeneration"
        return
    fi
    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping hosts.txt regeneration"
        return
    fi
    info "Regenerating hosts.txt via nxc..."
    nxc smb "${GS_DIR}/hosts_ip.txt" \
        --generate-hosts-file "${GS_DIR}/hosts.txt" &>/dev/null || \
        warn "nxc --generate-hosts-file returned an error (hosts.txt may be incomplete)"
    success "hosts.txt updated."
}

# ─── Add a single host value and trigger resolution / regen as needed ─────────
add_host() {
    local val="$1"
    local type
    type="$(detect_host_type "$val")"

    echo
    info "Adding host: ${BOLD}${val}${RESET} (detected type: ${type})"
    echo

    case "$type" in
        ip)
            if add_unique "${GS_DIR}/hosts_ip.txt" "$val"; then
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${GREEN}+${RESET} IP         → hosts_ip.txt  (${val})"
                log_entry "ADD host ip='${val}'"
            else
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${YELLOW}~${RESET} IP         already in hosts_ip.txt (${val}) — skipped"
            fi

            # Try to resolve hostname and domain via nxc
            local resolved
            mapfile -t resolved < <(resolve_via_nxc "$val")
            local r_name="${resolved[0]:-}"
            local r_domain="${resolved[1]:-}"

            if [[ -n "$r_name" ]]; then
                if add_unique "${GS_DIR}/hosts_dn.txt" "$r_name"; then
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} hostname   → hosts_dn.txt  (${r_name})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} hostname   already in hosts_dn.txt (${r_name})"
                fi
            fi

            if [[ -n "$r_domain" ]]; then
                if add_unique "${GS_DIR}/hosts_dn.txt" "$r_domain"; then
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} domain     → hosts_dn.txt  (${r_domain})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} domain     already in hosts_dn.txt (${r_domain})"
                fi
            fi

            if [[ -n "$r_name" && -n "$r_domain" ]]; then
                local fqdn="${r_name}.${r_domain}"
                if add_unique "${GS_DIR}/hosts_fqdn.txt" "$fqdn"; then
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt (${fqdn})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (${fqdn})"
                fi
                log_entry "ADD host ip='${val}' name='${r_name}' domain='${r_domain}' fqdn='${fqdn}'"
                success "Resolved: ${r_name}.${r_domain} (${val})"
            elif [[ -z "$r_name" && -z "$r_domain" ]]; then
                warn "Could not resolve hostname/domain for ${val} via nxc"
                warn "Add domain name manually: $TOOL_NAME --add -h <domain_or_fqdn>"
            fi
            ;;

        fqdn)
            if add_unique "${GS_DIR}/hosts_fqdn.txt" "$val"; then
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt  (${val})"
                log_entry "ADD host fqdn='${val}'"
            else
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (${val}) — skipped"
            fi
            ;;

        domain|hostname)
            if add_unique "${GS_DIR}/hosts_dn.txt" "$val"; then
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${GREEN}+${RESET} domain/hn  → hosts_dn.txt  (${val})"
                log_entry "ADD host domain='${val}'"
            else
                [[ "$VERBOSE" -eq 1 ]] && \
                    echo -e "    ${YELLOW}~${RESET} domain/hn  already in hosts_dn.txt (${val}) — skipped"
            fi
            ;;
    esac

    echo
    regenerate_hosts_file
}

# ─── Detect whether a file is in /etc/hosts format ───────────────────────────
# Returns 0 if the file looks like /etc/hosts (IP<TAB/space>hostname on each
# non-blank, non-comment line), 1 if it looks like a plain list of IPs/domains.
is_hosts_file_format() {
    local file="$1"
    local has_hostname_line=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip blank lines and comments
        [[ -z "$line" || "$line" == \#* ]] && continue
        # If the line has whitespace after the first token, it matches hosts format
        if [[ "$line" =~ ^[^[:space:]]+[[:space:]]+[^[:space:]] ]]; then
            has_hostname_line=1
            break
        fi
    done < "$file"
    [[ "$has_hostname_line" -eq 1 ]]
}

# ─── Resolve a hostname to an IP via dig / host / nslookup ───────────────────
# Args: hostname [dns_server]
# Prints the first A-record IP, or empty string on failure.
resolve_dns() {
    local hostname="$1"
    local dns_server="${2:-}"
    local ip=""

    if command -v dig &>/dev/null; then
        if [[ -n "$dns_server" ]]; then
            ip="$(dig +short "@${dns_server}" "$hostname" A 2>/dev/null | grep -Eo '^[0-9.]+$' | head -1)" || true
        else
            ip="$(dig +short "$hostname" A 2>/dev/null | grep -Eo '^[0-9.]+$' | head -1)" || true
        fi
    fi

    if [[ -z "$ip" ]] && command -v host &>/dev/null; then
        if [[ -n "$dns_server" ]]; then
            ip="$(host "$hostname" "$dns_server" 2>/dev/null \
                | grep -oP '(?<=has address )[0-9.]+' | head -1)" || true
        else
            ip="$(host "$hostname" 2>/dev/null \
                | grep -oP '(?<=has address )[0-9.]+' | head -1)" || true
        fi
    fi

    if [[ -z "$ip" ]] && command -v nslookup &>/dev/null; then
        if [[ -n "$dns_server" ]]; then
            ip="$(nslookup "$hostname" "$dns_server" 2>/dev/null \
                | awk '/^Address:/ && !/^Address: '"$dns_server"'/ {print $2; exit}')" || true
        else
            ip="$(nslookup "$hostname" 2>/dev/null \
                | awk 'found && /^Address:/ {print $2; exit} /^Name:/ {found=1}')" || true
        fi
    fi

    echo "$ip"
}

# ─── Import an /etc/hosts-format file into the workspace ─────────────────────
# Parses IP<whitespace>hostname lines. Adds IP to hosts_ip.txt, classifies each
# hostname into hosts_fqdn.txt or hosts_dn.txt, and writes the line verbatim to
# hosts.txt. Calls regenerate_hosts_file() once at end.
import_hosts_file() {
    local file="$1"
    local added=0 skipped=0

    info "Importing /etc/hosts-format file: ${BOLD}${file}${RESET}"
    [[ "$VERBOSE" -eq 1 ]] && echo

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip blank lines and comments
        [[ -z "$line" || "$line" == \#* ]] && continue

        # Extract IP (first field) and all hostnames (remaining fields)
        local ip
        ip="$(echo "$line" | awk '{print $1}')"
        local -a hostnames
        mapfile -t hostnames < <(echo "$line" | awk '{for(i=2;i<=NF;i++) print $i}')

        if [[ -z "$ip" || ${#hostnames[@]} -eq 0 ]]; then
            continue
        fi

        local line_new=0

        # Add IP
        if add_unique "${GS_DIR}/hosts_ip.txt" "$ip"; then
            line_new=1
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${GREEN}+${RESET} IP         → hosts_ip.txt  (${ip})"
        else
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${YELLOW}~${RESET} IP         already in hosts_ip.txt (${ip}) — skipped"
        fi

        # Classify and add each hostname
        for hn in "${hostnames[@]}"; do
            local htype
            htype="$(detect_host_type "$hn")"
            case "$htype" in
                fqdn)
                    if add_unique "${GS_DIR}/hosts_fqdn.txt" "$hn"; then
                        line_new=1
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt (${hn})"
                    else
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (${hn}) — skipped"
                    fi
                    ;;
                domain|hostname)
                    if add_unique "${GS_DIR}/hosts_dn.txt" "$hn"; then
                        line_new=1
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${GREEN}+${RESET} domain/hn  → hosts_dn.txt  (${hn})"
                    else
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${YELLOW}~${RESET} domain/hn  already in hosts_dn.txt (${hn}) — skipped"
                    fi
                    ;;
            esac
        done

        # Write the line verbatim to hosts.txt
        if ! grep -qxF "$line" "${GS_DIR}/hosts.txt" 2>/dev/null; then
            echo "$line" >> "${GS_DIR}/hosts.txt"
        fi

        log_entry "ADD host (hosts-file) ip='${ip}' hostnames='${hostnames[*]}'"
        if [[ "$line_new" -eq 1 ]]; then
            added=$((added + 1))
        else
            skipped=$((skipped + 1))
        fi
    done < "$file"

    echo
    success "Imported $((added + skipped)) host entry(ies) from $(basename "$file"): ${added} new, ${skipped} skipped."
    echo
    regenerate_hosts_file
}

# ─── Import a plain list of IPs / domains / FQDNs into the workspace ─────────
# One entry per line. IPs go directly to hosts_ip.txt. Domains/FQDNs are also
# DNS-resolved to get IPs. DNS server priority: --dns-server > default gateway
# > system default. Calls regenerate_hosts_file() once at end.
import_hosts_plain() {
    local file="$1"
    local dns_server="${2:-}"
    local count=0

    # Auto-detect default gateway as fallback DNS server
    local effective_dns="$dns_server"
    if [[ -z "$effective_dns" ]]; then
        effective_dns="$(ip route show default 2>/dev/null \
            | awk '/^default/ {print $3; exit}')" || true
    fi

    info "Importing plain host list: ${BOLD}${file}${RESET}"
    [[ -n "$effective_dns" ]] && info "DNS server: ${effective_dns}"
    [[ "$VERBOSE" -eq 1 ]] && echo

    local added=0 skipped=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue

        local entry_type
        entry_type="$(detect_host_type "$line")"
        local line_new=0

        case "$entry_type" in
            ip)
                if add_unique "${GS_DIR}/hosts_ip.txt" "$line"; then
                    line_new=1
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} IP         → hosts_ip.txt  (${line})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} IP         already in hosts_ip.txt (${line}) — skipped"
                fi
                log_entry "ADD host (plain-list) ip='${line}'"
                ;;
            fqdn)
                if add_unique "${GS_DIR}/hosts_fqdn.txt" "$line"; then
                    line_new=1
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt (${line})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (${line}) — skipped"
                fi
                # DNS-resolve to also populate hosts_ip.txt
                local resolved_ip
                resolved_ip="$(resolve_dns "$line" "$effective_dns")" || true
                if [[ -n "$resolved_ip" ]]; then
                    if add_unique "${GS_DIR}/hosts_ip.txt" "$resolved_ip"; then
                        line_new=1
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${GREEN}+${RESET} resolved   → hosts_ip.txt  (${resolved_ip})"
                    else
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${YELLOW}~${RESET} resolved   already in hosts_ip.txt (${resolved_ip}) — skipped"
                    fi
                else
                    warn "Could not resolve ${line} to an IP — add manually if needed"
                fi
                log_entry "ADD host (plain-list) fqdn='${line}' resolved='${resolved_ip:-}'"
                ;;
            domain|hostname)
                if add_unique "${GS_DIR}/hosts_dn.txt" "$line"; then
                    line_new=1
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} domain/hn  → hosts_dn.txt  (${line})"
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} domain/hn  already in hosts_dn.txt (${line}) — skipped"
                fi
                # DNS-resolve to also populate hosts_ip.txt
                local resolved_ip
                resolved_ip="$(resolve_dns "$line" "$effective_dns")" || true
                if [[ -n "$resolved_ip" ]]; then
                    if add_unique "${GS_DIR}/hosts_ip.txt" "$resolved_ip"; then
                        line_new=1
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${GREEN}+${RESET} resolved   → hosts_ip.txt  (${resolved_ip})"
                    else
                        [[ "$VERBOSE" -eq 1 ]] && \
                            echo -e "    ${YELLOW}~${RESET} resolved   already in hosts_ip.txt (${resolved_ip}) — skipped"
                    fi
                else
                    warn "Could not resolve ${line} to an IP — add manually if needed"
                fi
                log_entry "ADD host (plain-list) domain='${line}' resolved='${resolved_ip:-}'"
                ;;
        esac

        if [[ "$line_new" -eq 1 ]]; then
            added=$((added + 1))
        else
            skipped=$((skipped + 1))
        fi
    done < "$file"

    echo
    success "Imported $((added + skipped)) host entry(ies) from $(basename "$file"): ${added} new, ${skipped} skipped."
    echo
    regenerate_hosts_file
}

# ─── Add value to file only if not already present ────────────────────────────
# Returns 0 if added (new), 1 if already existed (skipped)
add_unique() {
    local file="$1" value="$2"
    if grep -qxF "$value" "$file" 2>/dev/null; then
        return 1
    fi
    echo "$value" >> "$file"
    return 0
}

# ─── Resolve GS_DIR for non-init commands ─────────────────────────────────────
# Priority: -d flag > $GIGASPRAY_DIR > error
require_gs_dir() {
    local flag_dir="${1:-}"

    if [[ -n "$flag_dir" ]]; then
        GS_DIR="$flag_dir"
    elif [[ -n "${GIGASPRAY_DIR:-}" ]]; then
        GS_DIR="$GIGASPRAY_DIR"
    else
        die "No workspace specified. Set \$GIGASPRAY_DIR or use -d <path>."
    fi

    [[ -d "$GS_DIR" ]] || \
        die "Workspace not found at: ${GS_DIR}\nRun '${TOOL_NAME} init' to create one."
    [[ -f "${GS_DIR}/creds.txt" ]] || \
        die "Directory exists but doesn't look like a gigaspray workspace: ${GS_DIR}"
}

# ─── Resolve GS_DIR for init (prompts if env var not set) ─────────────────────
resolve_gs_dir() {
    if [[ -n "${GIGASPRAY_DIR:-}" ]]; then
        GS_DIR="$GIGASPRAY_DIR"
        info "Using workspace from \$GIGASPRAY_DIR: ${BOLD}${GS_DIR}${RESET}"
        return
    fi

    local shell_cfg=""
    case "${SHELL:-}" in
        */zsh)  shell_cfg="~/.zshrc" ;;
        */bash) shell_cfg="~/.bashrc" ;;
        *)      shell_cfg="your shell config file" ;;
    esac

    echo
    warn "\$GIGASPRAY_DIR is not set."
    echo -e "  Enter the ${BOLD}absolute path${RESET} of the directory in which to create the gigaspray"
    echo -e "  workspace, or press ${BOLD}Enter${RESET} to use the current directory:"
    echo    "    $(pwd)"
    echo
    read -rp "$(echo -e "${YELLOW}[?]${RESET} Base path [$(pwd)]: ")" base_input

    local base_path
    if [[ -z "$base_input" ]]; then
        base_path="$(pwd)"
    else
        base_path="${base_input%/}"
        base_path="${base_path/#\~/$HOME}"
        if [[ "$base_path" != /* ]]; then
            die "Path must be absolute (start with /). Got: $base_path"
        fi
    fi

    GS_DIR="${base_path}/gigaspray"
    export GIGASPRAY_DIR="$GS_DIR"

    echo
    info "Workspace will be created at: ${BOLD}${GS_DIR}${RESET}"
    echo
    echo -e "  ${BOLD}Tip:${RESET} To avoid this prompt in future sessions, add the following to ${shell_cfg}:"
    echo -e "  ${CYAN}  export GIGASPRAY_DIR=\"${GS_DIR}\"${RESET}"
    echo
}

# ─── Write a single credential set to all relevant files ──────────────────────
# Args: user pass hash desc
# Any argument can be empty — only non-empty combos trigger writes.
write_cred() {
    local user="${1:-}" pass="${2:-}" hash="${3:-}" desc="${4:-}"

    _WRITE_CRED_ADDED=0

    # ── all_user.txt ──────────────────────────────────────────────────────────
    if [[ -n "$user" ]]; then
        if add_unique "${GS_DIR}/all_user.txt" "$user"; then
            _WRITE_CRED_ADDED=1
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${GREEN}+${RESET} user      → all_user.txt  (${user})"
        else
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${YELLOW}~${RESET} user      already in all_user.txt (${user}) — skipped"
        fi
    fi

    # ── all_pass.txt ──────────────────────────────────────────────────────────
    if [[ -n "$pass" ]]; then
        if add_unique "${GS_DIR}/all_pass.txt" "$pass"; then
            _WRITE_CRED_ADDED=1
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${GREEN}+${RESET} password  → all_pass.txt  (${pass})"
        else
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${YELLOW}~${RESET} password  already in all_pass.txt (${pass}) — skipped"
        fi
    fi

    # ── all_hashes.txt ────────────────────────────────────────────────────────
    if [[ -n "$hash" ]]; then
        if add_unique "${GS_DIR}/all_hashes.txt" "$hash"; then
            _WRITE_CRED_ADDED=1
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${GREEN}+${RESET} hash      → all_hashes.txt  (${hash})"
        else
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${YELLOW}~${RESET} hash      already in all_hashes.txt (${hash}) — skipped"
        fi
    fi

    # ── user:pass paired files + creds.txt ────────────────────────────────────
    if [[ -n "$user" && -n "$pass" ]]; then
        echo "$user" >> "${GS_DIR}/user_paired.txt"
        echo "$pass" >> "${GS_DIR}/pass_paired.txt"
        echo "${user}:${pass}${desc:+:${desc}}" >> "${GS_DIR}/creds.txt"
        [[ "$VERBOSE" -eq 1 ]] && \
            echo -e "    ${GREEN}+${RESET} pair      → user_paired.txt / pass_paired.txt / creds.txt"
        log_entry "ADD user:pass user='${user}' desc='${desc}'"
    fi

    # ── user:hash paired files + creds.txt ────────────────────────────────────
    if [[ -n "$user" && -n "$hash" ]]; then
        echo "$user" >> "${GS_DIR}/hash_user_paired.txt"
        echo "$hash" >> "${GS_DIR}/hashes_paired.txt"
        echo "${user}:${hash}${desc:+:${desc}}" >> "${GS_DIR}/creds.txt"
        [[ "$VERBOSE" -eq 1 ]] && \
            echo -e "    ${GREEN}+${RESET} hash pair → hash_user_paired.txt / hashes_paired.txt / creds.txt"
        log_entry "ADD user:hash user='${user}' desc='${desc}'"
    fi

    # ── user only (log only) ──────────────────────────────────────────────────
    if [[ -n "$user" && -z "$pass" && -z "$hash" ]]; then
        log_entry "ADD user user='${user}'"
    fi
}

# ─── Import secretsdump output (username:RID:LM:NT:::) ───────────────────────
# Format: Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT_hash>:::
# Extracts username and NT hash per line; strips DOMAIN\ prefix if present.
import_secretsdump() {
    local file="$1"
    local desc="${2:-}"
    local added=0 skipped=0

    info "Importing secretsdump: ${BOLD}${file}${RESET}"
    [[ "$VERBOSE" -eq 1 ]] && echo

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue

        # Need at least 4 colon-separated fields
        [[ "$line" != *:*:*:* ]] && continue

        local raw_user nt_hash
        raw_user="$(echo "$line" | cut -d: -f1)"
        nt_hash="$(echo "$line"  | cut -d: -f4)"

        # Strip DOMAIN\ prefix from username
        local user="${raw_user##*\\}"

        [[ -z "$user" || -z "$nt_hash" ]] && continue

        # Validate: NT hash must be exactly 32 hex chars
        [[ ! "$nt_hash" =~ ^[0-9a-fA-F]{32}$ ]] && continue

        _WRITE_CRED_ADDED=0
        write_cred "$user" "" "$nt_hash" "$desc"
        if [[ "$_WRITE_CRED_ADDED" -eq 1 ]]; then
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${GREEN}+${RESET} ${user}  :  ${nt_hash}"
            added=$((added + 1))
        else
            [[ "$VERBOSE" -eq 1 ]] && \
                echo -e "    ${YELLOW}~${RESET} ${user}  already imported — skipped"
            skipped=$((skipped + 1))
        fi
    done < "$file"

    echo
    success "Imported $((added + skipped)) credential(s) from $(basename "$file"): ${added} new, ${skipped} skipped."
}

# ─── Record one valid credential hit to valid_creds.txt ───────────────────────
record_valid_cred() {
    local user="$1" cred="$2" protocol="$3" host="$4"
    [[ -z "$user" || -z "$cred" || -z "$protocol" || -z "$host" ]] && return
    local entry="${user}:${cred}:${protocol}:${host}"
    local vc_file="${GS_DIR}/valid_creds.txt"
    if ! grep -qxF "$entry" "$vc_file" 2>/dev/null; then
        echo "$entry" >> "$vc_file"
        success "Valid cred saved → ${vc_file##*/}: ${BOLD}${entry}${RESET}"
        log_entry "VALID_CRED user='${user}' cred='${cred}' protocol='${protocol}' host='${host}'"
    fi
}

# ─── Parse nxc [+] lines from a captured output file and record hits ──────────
# nxc success line format:
#   PROTO  IP  PORT  HOSTNAME  [+] [DOMAIN\]user:cred [(Pwn3d!)]
parse_nxc_hits() {
    local protocol="$1" tmpfile="$2"
    [[ ! -f "$tmpfile" ]] && return
    while IFS= read -r line; do
        [[ "$line" != *'[+]'* ]] && continue
        local host
        host="$(echo "$line" | awk '{print $2}')"
        [[ -z "$host" ]] && continue
        # Extract the token immediately after [+]
        local cred_field
        cred_field="$(echo "$line" | grep -oP '(?<=\[\+\] )\S+')" || continue
        [[ -z "$cred_field" ]] && continue
        # Strip optional DOMAIN\ prefix
        local user_and_cred="${cred_field##*\\}"
        # Must contain a colon (user:cred); skip bare tokens like "Guest"
        [[ "$user_and_cred" != *:* ]] && continue
        local u="${user_and_cred%%:*}"
        local c="${user_and_cred#*:}"
        [[ -n "$u" && -n "$c" ]] && record_valid_cred "$u" "$c" "$protocol" "$host"
    done < "$tmpfile"
}

# ─── Execute one nxc spray command, handling -q and -o output routing ─────────
# Always prints the command first. Then:
#   -q         : terminal shows only [+] hits (successes); files still get full output
#   -o <name>  : full output appended to logs/<name> AND logs/gigaspray.log
#   both       : filtered terminal, full files
#   neither    : full output to terminal only (summary log_entry still written)
spray_exec() {
    local label="$1"; shift   # e.g. "SMB pass-spray"
    local protocol="$1"; shift # protocol name for hit recording (smb, ssh, etc.)
    local -a cmd=("$@")
    local log_main="${GS_DIR}/logs/gigaspray.log"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local tmpfile
    tmpfile="$(mktemp)"

    # Build display string: wrap the value after -p in single quotes
    local display_cmd=() i=0
    while [[ $i -lt ${#cmd[@]} ]]; do
        if [[ "${cmd[$i]}" == "-p" && $((i+1)) -lt ${#cmd[@]} ]]; then
            display_cmd+=("-p" "'${cmd[$((i+1))]}'")
            i=$((i+2))
        else
            display_cmd+=("${cmd[$i]}")
            i=$((i+1))
        fi
    done

    # Always print the command being run
    echo -e "  ${CYAN}\$${RESET} ${display_cmd[*]}"
    echo

    # Resolve named outfile (empty if -o not set)
    local outfile=""
    if [[ -n "$SPRAY_OUTNAME" ]]; then
        outfile="${GS_DIR}/logs/${SPRAY_OUTNAME}"
        # Write command header to both files
        printf '\n[%s] %s\n  CMD: %s\n' \
            "$timestamp" "$label" "${cmd[*]}" | tee -a "$outfile" >> "$log_main"
    fi

    # Run and route output; tee to tmpfile first so we can parse hits after
    if [[ -n "$outfile" && "$SPRAY_QUIET" -eq 1 ]]; then
        # Full output → outfile + main log; filtered output → terminal
        "${cmd[@]}" 2>&1 | tee "$tmpfile" | tee -a "$outfile" | tee -a "$log_main" \
            | grep -aF '[+]' || true

    elif [[ -n "$outfile" ]]; then
        # Full output → outfile + main log + terminal
        "${cmd[@]}" 2>&1 | tee "$tmpfile" | tee -a "$outfile" | tee -a "$log_main" || true

    elif [[ "$SPRAY_QUIET" -eq 1 ]]; then
        # Filtered output → terminal only
        "${cmd[@]}" 2>&1 | tee "$tmpfile" | grep -aF '[+]' || true

    else
        # Full output → terminal only
        "${cmd[@]}" 2>&1 | tee "$tmpfile" || true
    fi

    # Parse [+] hits and append unique entries to valid_creds.txt
    parse_nxc_hits "$protocol" "$tmpfile"
    rm -f "$tmpfile"
}

# ─── Spray a single protocol with the given credentials ───────────────────────
# Args: protocol user pass hash
# Empty user/pass/hash falls back to the corresponding workspace file.
run_spray() {
    local protocol="$1"
    local user="${2:-}" pass="${3:-}" hash="${4:-}"
    # ── resolve targets ───────────────────────────────────────────────────────
    # --spray-hosts overrides the default hosts_ip.txt.
    # Value can be a single IP/domain/FQDN, or a path to a file of targets.
    local targets
    if [[ -n "$SPRAY_HOSTS" ]]; then
        targets="$SPRAY_HOSTS"
        # If it's a file, make sure it's non-empty
        if [[ -f "$targets" && ! -s "$targets" ]]; then
            warn "[$protocol] Spray hosts file is empty: $targets — skipping"
            return
        fi
    else
        targets="${GS_DIR}/hosts_ip.txt"
        if [[ ! -s "$targets" ]]; then
            warn "hosts_ip.txt is empty — no targets to spray"
            warn "Add a host first: $TOOL_NAME --add -h <ip>"
            return
        fi
    fi

    # ── build user arg ────────────────────────────────────────────────────────
    local -a u_arg
    if [[ -n "$user" ]]; then
        u_arg=(-u "$user")
    elif [[ -s "${GS_DIR}/all_user.txt" ]]; then
        u_arg=(-u "${GS_DIR}/all_user.txt")
    else
        warn "[$protocol] No users available — skipping"
        return
    fi

    # ── password spray ────────────────────────────────────────────────────────
    local -a p_arg=()
    if [[ -n "$pass" ]]; then
        p_arg=(-p "$pass")
    elif [[ -s "${GS_DIR}/all_pass.txt" ]]; then
        p_arg=(-p "${GS_DIR}/all_pass.txt")
    fi

    # ── hash spray ────────────────────────────────────────────────────────────
    local -a h_arg=()
    if [[ -n "$hash" ]]; then
        h_arg=(-H "$hash")
    elif [[ -s "${GS_DIR}/all_hashes.txt" ]]; then
        h_arg=(-H "${GS_DIR}/all_hashes.txt")
    fi

    if [[ ${#p_arg[@]} -eq 0 && ${#h_arg[@]} -eq 0 ]]; then
        warn "[$protocol] No passwords or hashes available — skipping"
        return
    fi

    echo
    info "${BOLD}${protocol^^}${RESET} spray → ${targets}"

    if [[ ${#p_arg[@]} -gt 0 ]]; then
        local -a cmd=(nxc "$protocol" "$targets" "${u_arg[@]}" "${p_arg[@]}" --continue-on-success)
        spray_exec "${protocol^^} pass-spray" "$protocol" "${cmd[@]}"
        log_entry "SPRAY ${protocol^^} user='${user:-<file>}' pass='${pass:-<file>}'"
    fi

    if [[ ${#h_arg[@]} -gt 0 ]]; then
        local -a cmd=(nxc "$protocol" "$targets" "${u_arg[@]}" "${h_arg[@]}" --continue-on-success)
        spray_exec "${protocol^^} hash-spray" "$protocol" "${cmd[@]}"
        log_entry "SPRAY ${protocol^^} user='${user:-<file>}' hash='${hash:-<file>}'"
    fi

    # ── local-auth spray (if enabled) ─────────────────────────────────────────
    if [[ "$SPRAY_LOCAL_AUTH" -eq 1 ]]; then
        echo
        info "${BOLD}${protocol^^}${RESET} local-auth spray → ${targets}"

        if [[ ${#p_arg[@]} -gt 0 ]]; then
            local -a cmd=(nxc "$protocol" "$targets" "${u_arg[@]}" "${p_arg[@]}" \
                          --local-auth --continue-on-success)
            spray_exec "${protocol^^} local-auth pass-spray" "$protocol" "${cmd[@]}"
            log_entry "SPRAY ${protocol^^} local-auth user='${user:-<file>}' pass='${pass:-<file>}'"
        fi

        if [[ ${#h_arg[@]} -gt 0 ]]; then
            local -a cmd=(nxc "$protocol" "$targets" "${u_arg[@]}" "${h_arg[@]}" \
                          --local-auth --continue-on-success)
            spray_exec "${protocol^^} local-auth hash-spray" "$protocol" "${cmd[@]}"
            log_entry "SPRAY ${protocol^^} local-auth user='${user:-<file>}' hash='${hash:-<file>}'"
        fi
    fi
}

# ─── Run sprays across one or more protocols ──────────────────────────────────
# Args: user pass hash protocol [protocol ...]
run_sprays() {
    local user="$1" pass="$2" hash="$3"
    shift 3
    local protocols=("$@")

    if ! command -v nxc &>/dev/null; then
        die "nxc not found — cannot spray"
    fi

    echo
    info "Starting spray (${#protocols[@]} protocol(s): ${protocols[*]})"
    local target_display="${SPRAY_HOSTS:-${GS_DIR}/hosts_ip.txt}"
    echo "  targets    : ${target_display}"
    [[ -n "$user" ]] && echo "  user       : $user" || echo "  user       : all_user.txt"
    [[ -n "$pass" ]] && echo "  pass       : $pass" || echo "  pass       : all_pass.txt"
    [[ -n "$hash" ]] && echo "  hash       : $hash" || echo "  hash       : all_hashes.txt"
    [[ "$SPRAY_LOCAL_AUTH" -eq 1 ]] \
        && echo "  local-auth : enabled  (--no-local-auth to disable)" \
        || echo "  local-auth : disabled (--local-auth to enable)"

    for proto in "${protocols[@]}"; do
        run_spray "$proto" "$user" "$pass" "$hash"
    done

    echo
    success "Spray complete."
}

# ─── --add command ────────────────────────────────────────────────────────────
cmd_add() {
    local flag_dir="$1"; shift

    local username="" password="" hash="" desc=""
    local user_file="" pass_file="" cred_file="" secretsdump_file=""
    local host_val=""
    local -a spray_protocols=()

    # Inline "user:pass" as first arg (doesn't start with -)
    local inline=""
    if [[ $# -gt 0 && "$1" != -* ]]; then
        inline="$1"
        shift
    fi

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u)        [[ $# -lt 2 ]] && die "-u requires an argument"
                       username="$2"; shift 2 ;;
            -p)        [[ $# -lt 2 ]] && die "-p requires an argument"
                       password="$2"; shift 2 ;;
            -H)        [[ $# -lt 2 ]] && die "-H requires an argument"
                       hash="$2"; shift 2 ;;
            --desc|-D) [[ $# -lt 2 ]] && die "--desc requires an argument"
                       desc="$2"; shift 2 ;;
            -U)        [[ $# -lt 2 ]] && die "-U requires a file path"
                       user_file="$2"; shift 2 ;;
            -P)        [[ $# -lt 2 ]] && die "-P requires a file path"
                       pass_file="$2"; shift 2 ;;
            -L)            [[ $# -lt 2 ]] && die "-L requires a file path"
                           cred_file="$2"; shift 2 ;;
            --secretsdump) [[ $# -lt 2 ]] && die "--secretsdump requires a file path"
                           secretsdump_file="$2"; shift 2 ;;
            -h)        [[ $# -lt 2 ]] && die "-h requires a host value (IP, domain, or FQDN)"
                       host_val="$2"; shift 2 ;;
            --spray-smb)   spray_protocols+=(smb);   shift ;;
            --spray-rdp)   spray_protocols+=(rdp);   shift ;;
            --spray-winrm) spray_protocols+=(winrm); shift ;;
            --spray-ssh)   spray_protocols+=(ssh);   shift ;;
            --spray-ldap)  spray_protocols+=(ldap);  shift ;;
            --spray-ftp)   spray_protocols+=(ftp);   shift ;;
            --spray-mssql) spray_protocols+=(mssql); shift ;;
            --spray-all)   spray_protocols=("${SPRAY_PROTOCOLS[@]}"); shift ;;
            -q)            SPRAY_QUIET=1; shift ;;
            -o)            [[ $# -lt 2 ]] && die "-o requires a name"
                           SPRAY_OUTNAME="$2"; shift 2 ;;
            --spray-hosts) [[ $# -lt 2 ]] && die "--spray-hosts requires a value or file path"
                           SPRAY_HOSTS="$2"; shift 2 ;;
            --dns-server)    [[ $# -lt 2 ]] && die "--dns-server requires an IP address"
                             DNS_SERVER="$2"; shift 2 ;;
            --local-auth)    SPRAY_LOCAL_AUTH=1; shift ;;
            --no-local-auth) SPRAY_LOCAL_AUTH=0; shift ;;
            -v)              VERBOSE=1; shift ;;
            *)         die "Unknown option for --add: $1" ;;
        esac
    done

    require_gs_dir "$flag_dir"

    # ── Parse inline user:pass ─────────────────────────────────────────────────
    # Split on FIRST colon only — everything after is the password,
    # so passwords containing colons are handled correctly.
    if [[ -n "$inline" ]]; then
        username="${inline%%:*}"
        if [[ "$inline" == *:* ]]; then
            password="${inline#*:}"
        fi
    fi

    # ── Host add ──────────────────────────────────────────────────────────────
    if [[ -n "$host_val" ]]; then
        if [[ -f "$host_val" ]]; then
            if is_hosts_file_format "$host_val"; then
                import_hosts_file "$host_val"
            else
                import_hosts_plain "$host_val" "$DNS_SERVER"
            fi
        else
            add_host "$host_val"
        fi
    fi

    # ── Nothing provided at all ────────────────────────────────────────────────
    if [[ -z "$username" && -z "$password" && -z "$hash" \
       && -z "$host_val" \
       && -z "$user_file" && -z "$pass_file" && -z "$cred_file" \
       && -z "$secretsdump_file" ]]; then
        error "Nothing to add. Provide credentials or a file to import."
        echo
        usage
        exit 1
    fi

    # ── Single credential (flags or inline) ───────────────────────────────────
    if [[ -n "$username" || -n "$password" || -n "$hash" ]]; then
        echo
        info "Adding credential:"
        [[ -n "$username" ]] && echo -e "  ${BOLD}user${RESET} : $username"
        [[ -n "$password" ]] && echo -e "  ${BOLD}pass${RESET} : $password"
        [[ -n "$hash"     ]] && echo -e "  ${BOLD}hash${RESET} : $hash"
        [[ -n "$desc"     ]] && echo -e "  ${BOLD}desc${RESET} : $desc"
        echo
        write_cred "$username" "$password" "$hash" "$desc"
        echo
        success "Done."
    fi

    # ── -L: import user:pass pairs from file ──────────────────────────────────
    if [[ -n "$cred_file" ]]; then
        [[ ! -f "$cred_file" ]] && die "Cred file not found: $cred_file"
        echo
        info "Importing cred pairs from: ${BOLD}${cred_file}${RESET}"
        [[ "$VERBOSE" -eq 1 ]] && echo
        local added=0 skipped=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            local u="${line%%:*}"
            local p=""
            [[ "$line" == *:* ]] && p="${line#*:}"
            _WRITE_CRED_ADDED=0
            write_cred "$u" "$p" "" "$desc"
            if [[ "$_WRITE_CRED_ADDED" -eq 1 ]]; then
                added=$((added + 1))
            else
                skipped=$((skipped + 1))
            fi
        done < "$cred_file"
        echo
        success "Imported $((added + skipped)) credential pair(s) from $(basename "$cred_file"): ${added} new, ${skipped} skipped."
    fi

    # ── --secretsdump: import username:NT pairs from secretsdump output ──────────
    if [[ -n "$secretsdump_file" ]]; then
        [[ ! -f "$secretsdump_file" ]] && die "secretsdump file not found: $secretsdump_file"
        echo
        import_secretsdump "$secretsdump_file" "$desc"
    fi

    # ── -U / -P: import from separate user and/or password files ──────────────
    if [[ -n "$user_file" || -n "$pass_file" ]]; then
        [[ -n "$user_file" && ! -f "$user_file" ]] && die "User file not found: $user_file"
        [[ -n "$pass_file" && ! -f "$pass_file" ]] && die "Pass file not found: $pass_file"

        if [[ -n "$user_file" && -n "$pass_file" ]]; then
            # Paired import: line N of user_file pairs with line N of pass_file
            echo
            info "Importing paired users+passwords:"
            echo -e "  users : ${BOLD}${user_file}${RESET}"
            echo -e "  passes: ${BOLD}${pass_file}${RESET}"
            echo
            local users=() passes=()
            mapfile -t users  < <(grep -v '^[[:space:]]*$\|^#' "$user_file")
            mapfile -t passes < <(grep -v '^[[:space:]]*$\|^#' "$pass_file")
            local min_len
            min_len=$(( ${#users[@]} < ${#passes[@]} ? ${#users[@]} : ${#passes[@]} ))
            if [[ ${#users[@]} -ne ${#passes[@]} ]]; then
                warn "File lengths differ (${#users[@]} users, ${#passes[@]} passes)." \
                     "Pairing up to line ${min_len}."
            fi
            [[ "$VERBOSE" -eq 1 ]] && echo
            local i paired_added=0 paired_skipped=0
            for (( i=0; i<min_len; i++ )); do
                _WRITE_CRED_ADDED=0
                write_cred "${users[$i]}" "${passes[$i]}" "" "$desc"
                if [[ "$_WRITE_CRED_ADDED" -eq 1 ]]; then
                    paired_added=$((paired_added + 1))
                else
                    paired_skipped=$((paired_skipped + 1))
                fi
            done
            echo
            success "Imported ${min_len} paired credential(s): ${paired_added} new, ${paired_skipped} skipped."

        elif [[ -n "$user_file" ]]; then
            # Usernames only
            echo
            info "Importing usernames from: ${BOLD}${user_file}${RESET}"
            [[ "$VERBOSE" -eq 1 ]] && echo
            local added=0 skipped=0
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                if add_unique "${GS_DIR}/all_user.txt" "$line"; then
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} user      → all_user.txt  (${line})"
                    log_entry "ADD user user='${line}'"
                    added=$((added + 1))
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} user      already in all_user.txt (${line}) — skipped"
                    skipped=$((skipped + 1))
                fi
            done < "$user_file"
            echo
            success "Imported $((added + skipped)) username(s): ${added} new, ${skipped} skipped."

        else
            # Passwords only — no pairing, just bulk-add to all_pass.txt
            echo
            info "Importing passwords from: ${BOLD}${pass_file}${RESET}"
            [[ "$VERBOSE" -eq 1 ]] && echo
            local added=0 skipped=0
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                if add_unique "${GS_DIR}/all_pass.txt" "$line"; then
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${GREEN}+${RESET} password  → all_pass.txt  (${line})"
                    added=$((added + 1))
                else
                    [[ "$VERBOSE" -eq 1 ]] && \
                        echo -e "    ${YELLOW}~${RESET} password  already in all_pass.txt (${line}) — skipped"
                    skipped=$((skipped + 1))
                fi
            done < "$pass_file"
            echo
            success "Imported $((added + skipped)) password(s): ${added} new, ${skipped} skipped."
        fi
    fi

    # ── Spray (if requested) ──────────────────────────────────────────────────
    # Pass the specific newly-added cred values so the spray uses them as the
    # fixed input and falls back to the credential files for the other side.
    if [[ ${#spray_protocols[@]} -gt 0 ]]; then
        run_sprays "$username" "$password" "$hash" "${spray_protocols[@]}"
    fi
}

# ─── Dedup a single file in-place, preserving first-occurrence order ──────────
# Increments _CLEAN_REMOVED by the number of lines removed.
_dedup_file() {
    local file="$1" label="$2"
    [[ ! -f "$file" ]] && return

    local before after removed tmp
    before="$(wc -l < "$file")"
    tmp="$(mktemp)"
    awk '!seen[$0]++' "$file" > "$tmp"
    after="$(wc -l < "$tmp")"
    removed=$(( before - after ))
    cat "$tmp" > "$file"
    rm -f "$tmp"

    if [[ "$removed" -gt 0 ]]; then
        echo -e "  ${GREEN}✓${RESET} ${label}: ${removed} duplicate(s) removed"
    else
        echo -e "  ${CYAN}·${RESET} ${label}: clean"
    fi
    _CLEAN_REMOVED=$(( _CLEAN_REMOVED + removed ))
}

# ─── Dedup two parallel paired files, preserving pairs where one side differs ─
# A "duplicate pair" is a row where BOTH file1[i] and file2[i] are identical to
# a previously seen row.  Rows like (john, pass1) and (john, pass2) are kept
# because they represent different credentials for the same user.
# Increments _CLEAN_REMOVED by the number of duplicate pairs removed.
_dedup_paired() {
    local file1="$1" file2="$2" label="$3"
    [[ ! -f "$file1" || ! -f "$file2" ]] && return

    local tmp1 tmp2 before after removed
    tmp1="$(mktemp)"
    tmp2="$(mktemp)"
    before=0
    after=0
    local sep=$'\x01'   # SOH — safe separator that won't appear in usernames/passwords
    declare -A _seen_pairs

    while IFS= read -r f1_line <&3 && IFS= read -r f2_line <&4; do
        before=$(( before + 1 ))
        local key="${f1_line}${sep}${f2_line}"
        if [[ -z "${_seen_pairs[$key]+x}" ]]; then
            _seen_pairs[$key]=1
            echo "$f1_line" >> "$tmp1"
            echo "$f2_line" >> "$tmp2"
            after=$(( after + 1 ))
        fi
    done 3< "$file1" 4< "$file2"

    removed=$(( before - after ))
    cat "$tmp1" > "$file1"; rm -f "$tmp1"
    cat "$tmp2" > "$file2"; rm -f "$tmp2"

    if [[ "$removed" -gt 0 ]]; then
        echo -e "  ${GREEN}✓${RESET} ${label}: ${removed} duplicate pair(s) removed"
    else
        echo -e "  ${CYAN}·${RESET} ${label}: clean"
    fi
    _CLEAN_REMOVED=$(( _CLEAN_REMOVED + removed ))
}

# ─── --clean command ───────────────────────────────────────────────────────────
cmd_clean() {
    local flag_dir="$1"
    require_gs_dir "$flag_dir"

    _CLEAN_REMOVED=0   # not local — shared with _dedup_file / _dedup_paired

    echo
    info "Cleaning workspace: ${BOLD}${GS_DIR}${RESET}"
    echo

    # ── Credential files (simple unique-line dedup) ───────────────────────────
    echo -e "  ${BOLD}Credential lists:${RESET}"
    _dedup_file "${GS_DIR}/all_user.txt"    "all_user.txt"
    _dedup_file "${GS_DIR}/all_pass.txt"    "all_pass.txt"
    _dedup_file "${GS_DIR}/all_hashes.txt"  "all_hashes.txt"
    _dedup_file "${GS_DIR}/creds.txt"       "creds.txt"
    _dedup_file "${GS_DIR}/valid_creds.txt" "valid_creds.txt"
    echo

    # ── Paired files (dedup on the (user, cred) pair; keeps one user + many
    #    different passwords, and many users sharing the same password) ─────────
    echo -e "  ${BOLD}Paired credential files:${RESET}"
    echo -e "  ${CYAN}(same user with different passwords/hashes is preserved)${RESET}"
    _dedup_paired "${GS_DIR}/user_paired.txt"      \
                  "${GS_DIR}/pass_paired.txt"      \
                  "user_paired / pass_paired"
    _dedup_paired "${GS_DIR}/hash_user_paired.txt" \
                  "${GS_DIR}/hashes_paired.txt"    \
                  "hash_user_paired / hashes_paired"
    echo

    # ── Host files ────────────────────────────────────────────────────────────
    local before_hosts="$_CLEAN_REMOVED"
    echo -e "  ${BOLD}Host files:${RESET}"
    _dedup_file "${GS_DIR}/hosts_ip.txt"   "hosts_ip.txt"
    _dedup_file "${GS_DIR}/hosts_dn.txt"   "hosts_dn.txt"
    _dedup_file "${GS_DIR}/hosts_fqdn.txt" "hosts_fqdn.txt"
    _dedup_file "${GS_DIR}/hosts.txt"      "hosts.txt"

    # If any host file changed, regenerate hosts.txt from the cleaned IPs
    if [[ $(( _CLEAN_REMOVED - before_hosts )) -gt 0 ]]; then
        echo
        regenerate_hosts_file
    fi

    echo
    if [[ "$_CLEAN_REMOVED" -gt 0 ]]; then
        success "Clean complete: ${_CLEAN_REMOVED} duplicate(s) removed."
    else
        success "Clean complete: workspace is already clean."
    fi
    log_entry "CLEAN removed=${_CLEAN_REMOVED}"
}

# ─── init command ─────────────────────────────────────────────────────────────
cmd_init() {
    banner
    resolve_gs_dir

    if [[ -d "$GS_DIR" ]]; then
        error "A 'gigaspray' directory already exists at: ${GS_DIR}"
        error "Resolve this before running init (rename, move, or delete it)."
        exit 1
    fi

    read -rp "$(echo -e "${YELLOW}[?]${RESET} Create gigaspray workspace here? [y/N] ")" answer
    case "${answer,,}" in
        y|yes) ;;
        *)
            info "Aborted. No files were created."
            exit 0
            ;;
    esac

    echo
    info "Creating workspace..."

    mkdir -p "${GS_DIR}/logs"

    touch "${GS_DIR}/all_user.txt"
    touch "${GS_DIR}/all_pass.txt"
    touch "${GS_DIR}/user_paired.txt"
    touch "${GS_DIR}/pass_paired.txt"
    touch "${GS_DIR}/all_hashes.txt"
    touch "${GS_DIR}/hash_user_paired.txt"
    touch "${GS_DIR}/hashes_paired.txt"
    touch "${GS_DIR}/creds.txt"
    touch "${GS_DIR}/valid_creds.txt"
    touch "${GS_DIR}/hosts.txt"
    touch "${GS_DIR}/hosts_ip.txt"
    touch "${GS_DIR}/hosts_dn.txt"
    touch "${GS_DIR}/hosts_fqdn.txt"

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] gigaspray workspace initialized" > "${GS_DIR}/logs/gigaspray.log"

    echo
    success "Workspace created at: ${BOLD}${GS_DIR}${RESET}"
    echo
    echo -e "  ${BOLD}Credential files:${RESET}"
    echo    "    all_user.txt          all unique usernames"
    echo    "    all_pass.txt          all unique passwords"
    echo    "    user_paired.txt       usernames (1:1 with pass_paired.txt)"
    echo    "    pass_paired.txt       passwords (1:1 with user_paired.txt)"
    echo    "    all_hashes.txt        all unique hashes"
    echo    "    hash_user_paired.txt  usernames (1:1 with hashes_paired.txt)"
    echo    "    hashes_paired.txt     hashes (1:1 with hash_user_paired.txt)"
    echo    "    creds.txt             user:pass/hash:description"
    echo    "    valid_creds.txt       auto-populated: user:cred:protocol:host (spray hits)"
    echo
    echo -e "  ${BOLD}Host files:${RESET}"
    echo    "    hosts.txt             /etc/hosts format"
    echo    "    hosts_ip.txt          IPs only"
    echo    "    hosts_dn.txt          domain names only"
    echo    "    hosts_fqdn.txt        FQDNs only"
    echo
    echo -e "  ${BOLD}Logs:${RESET}"
    echo    "    logs/gigaspray.log"
    echo
    echo -e "  ${BOLD}Config:${RESET}"
    echo    "    ${HOME}/.config/gigaspray/gigaspray.conf"
    echo    "    (created automatically on first run with defaults)"
    echo
}

# ─── Entrypoint ───────────────────────────────────────────────────────────────
main() {
    load_config   # load ~/.config/gigaspray/gigaspray.conf before flag parsing

    [[ $# -eq 0 ]] && { usage; exit 1; }

    local flag_dir=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d)
                [[ $# -lt 2 ]] && die "-d requires a path argument"
                flag_dir="$2"; shift 2 ;;
            -q)
                SPRAY_QUIET=1; shift ;;
            -v)
                VERBOSE=1; shift ;;
            --local-auth)
                SPRAY_LOCAL_AUTH=1; shift ;;
            --no-local-auth)
                SPRAY_LOCAL_AUTH=0; shift ;;
            -o)
                [[ $# -lt 2 ]] && die "-o requires a name argument"
                SPRAY_OUTNAME="$2"; shift 2 ;;
            --spray-hosts)
                [[ $# -lt 2 ]] && die "--spray-hosts requires a value or file path"
                SPRAY_HOSTS="$2"; shift 2 ;;
            -h)
                [[ $# -lt 2 ]] && die "-h requires a host value"
                SPRAY_HOSTS="$2"; shift 2 ;;
            -u)
                [[ $# -lt 2 ]] && die "-u requires a username"
                SPRAY_EPHEMERAL_USER="$2"; shift 2 ;;
            -p)
                [[ $# -lt 2 ]] && die "-p requires a password"
                SPRAY_EPHEMERAL_PASS="$2"; shift 2 ;;
            -H)
                [[ $# -lt 2 ]] && die "-H requires a hash"
                SPRAY_EPHEMERAL_HASH="$2"; shift 2 ;;
            init)
                cmd_init; exit $? ;;
            --add)
                shift; cmd_add "$flag_dir" "$@"; exit $? ;;
            --clean)
                cmd_clean "$flag_dir"; exit $? ;;
            --spray-smb|--spray-rdp|--spray-winrm|--spray-ssh|\
            --spray-ldap|--spray-ftp|--spray-mssql|--spray-all)
                proto="${1#--spray-}"
                shift
                # Consume any remaining options that follow the spray command
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        -q)            SPRAY_QUIET=1; shift ;;
                        -o)            [[ $# -lt 2 ]] && die "-o requires a name"
                                       SPRAY_OUTNAME="$2"; shift 2 ;;
                        --spray-hosts) [[ $# -lt 2 ]] && die "--spray-hosts requires a value or file path"
                                       SPRAY_HOSTS="$2"; shift 2 ;;
                        -h)            [[ $# -lt 2 ]] && die "-h requires a host value"
                                       SPRAY_HOSTS="$2"; shift 2 ;;
                        -u)            [[ $# -lt 2 ]] && die "-u requires a username"
                                       SPRAY_EPHEMERAL_USER="$2"; shift 2 ;;
                        -p)            [[ $# -lt 2 ]] && die "-p requires a password"
                                       SPRAY_EPHEMERAL_PASS="$2"; shift 2 ;;
                        -H)              [[ $# -lt 2 ]] && die "-H requires a hash"
                                         SPRAY_EPHEMERAL_HASH="$2"; shift 2 ;;
                        --local-auth)    SPRAY_LOCAL_AUTH=1; shift ;;
                        --no-local-auth) SPRAY_LOCAL_AUTH=0; shift ;;
                        *)               break ;;
                    esac
                done
                require_gs_dir "$flag_dir"
                if [[ -n "$SPRAY_EPHEMERAL_USER" || -n "$SPRAY_EPHEMERAL_PASS" \
                   || -n "$SPRAY_EPHEMERAL_HASH" ]]; then
                    warn "Ephemeral mode — credentials not saved to workspace."
                fi
                if [[ "$proto" == "all" ]]; then
                    run_sprays "$SPRAY_EPHEMERAL_USER" "$SPRAY_EPHEMERAL_PASS" \
                               "$SPRAY_EPHEMERAL_HASH" "${SPRAY_PROTOCOLS[@]}"
                else
                    run_sprays "$SPRAY_EPHEMERAL_USER" "$SPRAY_EPHEMERAL_PASS" \
                               "$SPRAY_EPHEMERAL_HASH" "$proto"
                fi
                exit $? ;;
            --help)
                usage; exit 0 ;;
            *)
                die "Unknown command: $1  (use --help for usage)" ;;
        esac
    done

    usage; exit 1
}

main "$@"

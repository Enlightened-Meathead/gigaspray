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
SPRAY_HOSTS=""     # --spray-hosts: override default hosts_ip.txt target

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

usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $TOOL_NAME [global options] <command> [command options]"
    echo
    # ── Global options ────────────────────────────────────────────────────────
    echo -e "${BOLD}Global options:${RESET}"
    echo "  -d <path>              Workspace path (overrides \$GIGASPRAY_DIR)"
    echo
    echo -e "${BOLD}Spray output options${RESET} (apply to all spray commands):"
    echo "  -q                     Quiet — show only [+] hits on terminal."
    echo "                         Named outfile and gigaspray.log still get full output."
    echo "  -o <name>              Save full spray output to logs/<name>."
    echo "                         Also appended to gigaspray.log."
    echo
    echo -e "${BOLD}Spray target option${RESET} (applies to all spray commands):"
    echo "  --spray-hosts <value>  Override the default spray target (hosts_ip.txt)."
    echo "                         <value> is one of:"
    echo "                           • a single IP       e.g. 10.10.10.5"
    echo "                           • a single domain   e.g. corp.local"
    echo "                           • a single FQDN     e.g. dc01.corp.local"
    echo "                           • a file of targets (one entry per line)"
    echo "                         If omitted, hosts_ip.txt in the workspace is used."
    echo
    # ── Commands ──────────────────────────────────────────────────────────────
    echo -e "${BOLD}Commands:${RESET}"
    echo "  init                   Create a new gigaspray workspace"
    echo "  --add                  Add credentials or hosts to the workspace"
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
    echo
    echo -e "${BOLD}--add host options:${RESET}"
    echo "  -h <value>             Add a host by IP, domain name, or FQDN."
    echo "                         Type is auto-detected:"
    echo "                           • IP    → hosts_ip.txt"
    echo "                           • FQDN  → hosts_fqdn.txt  (2+ dots)"
    echo "                           • other → hosts_dn.txt"
    echo "                         When an IP is given, nxc smb probes it to resolve"
    echo "                         hostname and domain, then populates all host files."
    echo "                         hosts.txt is regenerated via nxc after every add."
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
    echo
    echo    "  # Add a host"
    echo    "  $TOOL_NAME --add -h 10.10.10.5       # IP — nxc probes for hostname/domain"
    echo    "  $TOOL_NAME --add -h dc01.corp.local  # FQDN"
    echo    "  $TOOL_NAME --add -h corp.local       # domain name"
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
                echo -e "    ${GREEN}+${RESET} IP         → hosts_ip.txt"
                log_entry "ADD host ip='${val}'"
            else
                echo -e "    ${YELLOW}~${RESET} IP         already in hosts_ip.txt (skipped)"
            fi

            # Try to resolve hostname and domain via nxc
            local resolved
            mapfile -t resolved < <(resolve_via_nxc "$val")
            local r_name="${resolved[0]:-}"
            local r_domain="${resolved[1]:-}"

            if [[ -n "$r_name" ]]; then
                if add_unique "${GS_DIR}/hosts_dn.txt" "$r_name"; then
                    echo -e "    ${GREEN}+${RESET} hostname   → hosts_dn.txt  (${r_name})"
                else
                    echo -e "    ${YELLOW}~${RESET} hostname   already in hosts_dn.txt (${r_name})"
                fi
            fi

            if [[ -n "$r_domain" ]]; then
                if add_unique "${GS_DIR}/hosts_dn.txt" "$r_domain"; then
                    echo -e "    ${GREEN}+${RESET} domain     → hosts_dn.txt  (${r_domain})"
                else
                    echo -e "    ${YELLOW}~${RESET} domain     already in hosts_dn.txt (${r_domain})"
                fi
            fi

            if [[ -n "$r_name" && -n "$r_domain" ]]; then
                local fqdn="${r_name}.${r_domain}"
                if add_unique "${GS_DIR}/hosts_fqdn.txt" "$fqdn"; then
                    echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt (${fqdn})"
                else
                    echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (${fqdn})"
                fi
                log_entry "ADD host ip='${val}' name='${r_name}' domain='${r_domain}' fqdn='${fqdn}'"
            elif [[ -z "$r_name" && -z "$r_domain" ]]; then
                warn "Could not resolve hostname/domain for ${val} via nxc"
                warn "Add domain name manually: $TOOL_NAME --add -h <domain_or_fqdn>"
            fi
            ;;

        fqdn)
            if add_unique "${GS_DIR}/hosts_fqdn.txt" "$val"; then
                echo -e "    ${GREEN}+${RESET} FQDN       → hosts_fqdn.txt"
                log_entry "ADD host fqdn='${val}'"
            else
                echo -e "    ${YELLOW}~${RESET} FQDN       already in hosts_fqdn.txt (skipped)"
            fi
            ;;

        domain|hostname)
            if add_unique "${GS_DIR}/hosts_dn.txt" "$val"; then
                echo -e "    ${GREEN}+${RESET} domain/hn  → hosts_dn.txt"
                log_entry "ADD host domain='${val}'"
            else
                echo -e "    ${YELLOW}~${RESET} domain/hn  already in hosts_dn.txt (skipped)"
            fi
            ;;
    esac

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

    # ── all_user.txt ──────────────────────────────────────────────────────────
    if [[ -n "$user" ]]; then
        if add_unique "${GS_DIR}/all_user.txt" "$user"; then
            echo -e "    ${GREEN}+${RESET} user      → all_user.txt"
        else
            echo -e "    ${YELLOW}~${RESET} user      already in all_user.txt (skipped)"
        fi
    fi

    # ── all_pass.txt ──────────────────────────────────────────────────────────
    if [[ -n "$pass" ]]; then
        if add_unique "${GS_DIR}/all_pass.txt" "$pass"; then
            echo -e "    ${GREEN}+${RESET} password  → all_pass.txt"
        else
            echo -e "    ${YELLOW}~${RESET} password  already in all_pass.txt (skipped)"
        fi
    fi

    # ── all_hashes.txt ────────────────────────────────────────────────────────
    if [[ -n "$hash" ]]; then
        if add_unique "${GS_DIR}/all_hashes.txt" "$hash"; then
            echo -e "    ${GREEN}+${RESET} hash      → all_hashes.txt"
        else
            echo -e "    ${YELLOW}~${RESET} hash      already in all_hashes.txt (skipped)"
        fi
    fi

    # ── user:pass paired files + creds.txt ────────────────────────────────────
    if [[ -n "$user" && -n "$pass" ]]; then
        echo "$user" >> "${GS_DIR}/user_paired.txt"
        echo "$pass" >> "${GS_DIR}/pass_paired.txt"
        echo "${user}:${pass}${desc:+:${desc}}" >> "${GS_DIR}/creds.txt"
        echo -e "    ${GREEN}+${RESET} pair      → user_paired.txt / pass_paired.txt / creds.txt"
        log_entry "ADD user:pass user='${user}' desc='${desc}'"
    fi

    # ── user:hash paired files + creds.txt ────────────────────────────────────
    if [[ -n "$user" && -n "$hash" ]]; then
        echo "$user" >> "${GS_DIR}/hash_user_paired.txt"
        echo "$hash" >> "${GS_DIR}/hashes_paired.txt"
        echo "${user}:${hash}${desc:+:${desc}}" >> "${GS_DIR}/creds.txt"
        echo -e "    ${GREEN}+${RESET} hash pair → hash_user_paired.txt / hashes_paired.txt / creds.txt"
        log_entry "ADD user:hash user='${user}' desc='${desc}'"
    fi

    # ── user only (log only) ──────────────────────────────────────────────────
    if [[ -n "$user" && -z "$pass" && -z "$hash" ]]; then
        log_entry "ADD user user='${user}'"
    fi
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

    # Always print the command being run
    echo -e "  ${CYAN}\$${RESET} ${cmd[*]}"
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
    echo "  targets : ${target_display}"
    [[ -n "$user" ]] && echo "  user    : $user" || echo "  user    : all_user.txt"
    [[ -n "$pass" ]] && echo "  pass    : $pass" || echo "  pass    : all_pass.txt"
    [[ -n "$hash" ]] && echo "  hash    : $hash" || echo "  hash    : all_hashes.txt"

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
    local user_file="" pass_file="" cred_file=""
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
            -L)        [[ $# -lt 2 ]] && die "-L requires a file path"
                       cred_file="$2"; shift 2 ;;
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
        add_host "$host_val"
    fi

    # ── Nothing provided at all ────────────────────────────────────────────────
    if [[ -z "$username" && -z "$password" && -z "$hash" \
       && -z "$host_val" \
       && -z "$user_file" && -z "$pass_file" && -z "$cred_file" ]]; then
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
        echo
        local count=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            local u="${line%%:*}"
            local p=""
            [[ "$line" == *:* ]] && p="${line#*:}"
            write_cred "$u" "$p" "" "$desc"
            count=$((count + 1))
        done < "$cred_file"
        echo
        success "Imported ${count} credential pair(s) from $(basename "$cred_file")."
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
            local i
            for (( i=0; i<min_len; i++ )); do
                write_cred "${users[$i]}" "${passes[$i]}" "" "$desc"
            done
            echo
            success "Imported ${min_len} paired credential(s)."

        elif [[ -n "$user_file" ]]; then
            # Usernames only
            echo
            info "Importing usernames from: ${BOLD}${user_file}${RESET}"
            echo
            local count=0
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                write_cred "$line" "" "" ""
                count=$((count + 1))
            done < "$user_file"
            echo
            success "Imported ${count} username(s)."

        else
            # Passwords only — no pairing, just bulk-add to all_pass.txt
            echo
            info "Importing passwords from: ${BOLD}${pass_file}${RESET}"
            echo
            local count=0
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                if add_unique "${GS_DIR}/all_pass.txt" "$line"; then
                    echo -e "    ${GREEN}+${RESET} password → all_pass.txt"
                else
                    echo -e "    ${YELLOW}~${RESET} password already in all_pass.txt (skipped)"
                fi
                count=$((count + 1))
            done < "$pass_file"
            echo
            success "Imported ${count} password(s)."
        fi
    fi

    # ── Spray (if requested) ──────────────────────────────────────────────────
    # Pass the specific newly-added cred values so the spray uses them as the
    # fixed input and falls back to the credential files for the other side.
    if [[ ${#spray_protocols[@]} -gt 0 ]]; then
        run_sprays "$username" "$password" "$hash" "${spray_protocols[@]}"
    fi
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
}

# ─── Entrypoint ───────────────────────────────────────────────────────────────
main() {
    [[ $# -eq 0 ]] && { usage; exit 1; }

    local flag_dir=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d)
                [[ $# -lt 2 ]] && die "-d requires a path argument"
                flag_dir="$2"; shift 2 ;;
            -q)
                SPRAY_QUIET=1; shift ;;
            -o)
                [[ $# -lt 2 ]] && die "-o requires a name argument"
                SPRAY_OUTNAME="$2"; shift 2 ;;
            --spray-hosts)
                [[ $# -lt 2 ]] && die "--spray-hosts requires a value or file path"
                SPRAY_HOSTS="$2"; shift 2 ;;
            init)
                cmd_init; exit $? ;;
            --add)
                shift; cmd_add "$flag_dir" "$@"; exit $? ;;
            --spray-smb|--spray-rdp|--spray-winrm|--spray-ssh|\
            --spray-ldap|--spray-ftp|--spray-mssql|--spray-all)
                proto="${1#--spray-}"
                shift
                # Consume any -q / -o / --spray-hosts that follow the spray command
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        -q)            SPRAY_QUIET=1; shift ;;
                        -o)            [[ $# -lt 2 ]] && die "-o requires a name"
                                       SPRAY_OUTNAME="$2"; shift 2 ;;
                        --spray-hosts) [[ $# -lt 2 ]] && die "--spray-hosts requires a value or file path"
                                       SPRAY_HOSTS="$2"; shift 2 ;;
                        *)             break ;;
                    esac
                done
                require_gs_dir "$flag_dir"
                if [[ "$proto" == "all" ]]; then
                    run_sprays "" "" "" "${SPRAY_PROTOCOLS[@]}"
                else
                    run_sprays "" "" "" "$proto"
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

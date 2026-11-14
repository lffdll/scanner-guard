#!/usr/bin/env bash
# Scanner Guard (standalone)
# Drops NEW incoming connections from known scanner / government subnets.
# Backends: ipset + iptables (preferred) or native nftables.
# Lists refresh automatically through a systemd timer (cron as a fallback).
#
# Usage:
#   scanner-guard.sh install [--source URL]... [--whitelist CIDR]...
#   scanner-guard update | status | uninstall

set -euo pipefail

VERSION="1.0.1"
# Last modified: 2026-11-15 00:52 RTZST (test push)
SCRIPT_URL="${SCANNER_GUARD_SCRIPT_URL:-https://raw.githubusercontent.com/lffdll/scanner-guard/main/scanner-guard.sh}"
DEFAULT_SOURCE="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"

BIN="/usr/local/sbin/scanner-guard"
CONF_DIR="/etc/scanner-guard"
STATE_DIR="/var/lib/scanner-guard"
SOURCES_FILE="$CONF_DIR/sources.list"
WHITELIST_FILE="$CONF_DIR/whitelist.list"
UNIT_SERVICE="/etc/systemd/system/scanner-guard.service"
UNIT_TIMER="/etc/systemd/system/scanner-guard.timer"
CRON_FILE="/etc/cron.d/scanner-guard"
LOCK_FILE="/run/scanner-guard.lock"

CHAIN="SCANGUARD"
SET_PREFIX="scanguard"
NFT_TABLE="scanguard"
MAXELEM=131072
REFRESH_INTERVAL="6h"

TMP_DIR=""

log()  { printf '[scanner-guard] %s\n' "$*"; }
warn() { printf '[scanner-guard] WARNING: %s\n' "$*" >&2; }
die()  { printf '[scanner-guard] ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() { if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT

need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

make_tmp() { if [ -z "$TMP_DIR" ]; then TMP_DIR="$(mktemp -d)"; fi; }

# ---------------------------------------------------------------- parsing ---

# Strip CR, comments and surrounding whitespace; keep single-token lines.
clean() {
    sed -e 's/\r$//' -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$@" \
        | awk 'NF == 1'
}

# Valid IPv4 address / CIDR. Prefixes shorter than /8 are rejected on purpose:
# one bad line in a remote list must not be able to block half the internet.
filter_v4() {
    awk -F'[./]' '
        /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {
            if ($1 > 255 || $2 > 255 || $3 > 255 || $4 > 255) next
            if (NF == 5 && ($5 < 8 || $5 > 32)) next
            print
        }'
}

# IPv6 address / CIDR, prefixes shorter than /16 rejected.
filter_v6() {
    awk '
        /^[0-9a-fA-F:]+(\/[0-9]+)?$/ && /:/ {
            n = split($0, p, "/")
            if (n == 2 && (p[2] < 16 || p[2] > 128)) next
            print tolower($0)
        }'
}

count_lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# ---------------------------------------------------------------- fetching --

fetch_lists() {
    make_tmp
    local n=0 url
    rm -f "$TMP_DIR"/src.*
    while IFS= read -r url; do
        case "$url" in
            http://*|https://*) ;;
            *) warn "skipping invalid source: $url"; continue ;;
        esac
        if ! curl -fsSL --retry 3 --connect-timeout 10 --max-time 90 -o "$TMP_DIR/src.$n" "$url"; then
            warn "download failed: $url"
            return 1
        fi
        n=$((n + 1))
    done < <(clean "$SOURCES_FILE")

    if [ "$n" -eq 0 ]; then
        warn "no list sources configured in $SOURCES_FILE"
        return 1
    fi

    clean "$TMP_DIR"/src.* | filter_v4 | sort -u > "$TMP_DIR/v4.list"
    clean "$TMP_DIR"/src.* | filter_v6 | sort -u > "$TMP_DIR/v6.list"

    local c4 c6
    c4="$(count_lines "$TMP_DIR/v4.list")"
    c6="$(count_lines "$TMP_DIR/v6.list")"
    if [ $((c4 + c6)) -eq 0 ]; then
        warn "downloaded lists contain no valid subnets; keeping the previous list"
        return 1
    fi
    if [ "$c4" -gt "$MAXELEM" ] || [ "$c6" -gt "$MAXELEM" ]; then
        warn "list exceeds $MAXELEM entries per family; keeping the previous list"
        return 1
    fi

    mv -f "$TMP_DIR/v4.list" "$STATE_DIR/v4.list"
    mv -f "$TMP_DIR/v6.list" "$STATE_DIR/v6.list"
    date -Iseconds > "$STATE_DIR/last_update"
    return 0
}

build_whitelist() {
    if [ -f "$WHITELIST_FILE" ]; then
        clean "$WHITELIST_FILE" | filter_v4 | sort -u > "$STATE_DIR/wl4.list"
        clean "$WHITELIST_FILE" | filter_v6 | sort -u > "$STATE_DIR/wl6.list"
    else
        : > "$STATE_DIR/wl4.list"
        : > "$STATE_DIR/wl6.list"
    fi
}

# ---------------------------------------------------------------- backend ---

detect_backend() {
    if have iptables && have ipset; then echo iptables
    elif have nft; then echo nft
    elif have iptables; then echo iptables
    else echo none
    fi
}

backend() {
    if [ -s "$STATE_DIR/backend" ]; then cat "$STATE_DIR/backend"; else detect_backend; fi
}

pkg_install() {
    log "installing packages: $*"
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif have dnf; then dnf install -y -q "$@"
    elif have yum; then yum install -y -q "$@"
    else die "no supported package manager; install manually: $*"
    fi
}

ensure_deps() {
    have curl || pkg_install curl
    case "$(detect_backend)" in
        none) pkg_install iptables ipset ;;
        iptables) have ipset || pkg_install ipset ;;
    esac
    local be
    be="$(detect_backend)"
    if [ "$be" = "none" ] || { [ "$be" = "iptables" ] && ! have ipset; }; then
        die "no usable firewall backend (need ipset + iptables, or nft)"
    fi
}

# --- ipset + iptables ---

ipset_load() { # family set-name file
    local fam="$1" name="$2" file="$3"
    {
        echo "create ${name}-tmp hash:net family $fam maxelem $MAXELEM -exist"
        echo "create ${name} hash:net family $fam maxelem $MAXELEM -exist"
        echo "flush ${name}-tmp"
        sed "s/^/add ${name}-tmp /" "$file"
        echo "swap ${name} ${name}-tmp"
        echo "destroy ${name}-tmp"
    } | ipset restore -exist
}

ipt_ensure() { # binary family-digit
    local bin="$1" f="$2" hook
    "$bin" -w 5 -N "$CHAIN" 2>/dev/null || true
    "$bin" -w 5 -C "$CHAIN" -m set --match-set "${SET_PREFIX}-wl$f" src -j RETURN 2>/dev/null \
        || "$bin" -w 5 -I "$CHAIN" 1 -m set --match-set "${SET_PREFIX}-wl$f" src -j RETURN
    "$bin" -w 5 -C "$CHAIN" -m set --match-set "${SET_PREFIX}-bl$f" src -j DROP 2>/dev/null \
        || "$bin" -w 5 -A "$CHAIN" -m set --match-set "${SET_PREFIX}-bl$f" src -j DROP
    # INPUT covers services on the host; DOCKER-USER covers published container ports.
    for hook in INPUT DOCKER-USER; do
        "$bin" -w 5 -nL "$hook" >/dev/null 2>&1 || continue
        "$bin" -w 5 -C "$hook" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null \
            || "$bin" -w 5 -I "$hook" 1 -m conntrack --ctstate NEW -j "$CHAIN"
    done
}

apply_iptables() {
    ipset_load inet  "${SET_PREFIX}-bl4" "$STATE_DIR/v4.list"
    ipset_load inet  "${SET_PREFIX}-wl4" "$STATE_DIR/wl4.list"
    ipt_ensure iptables 4
    if have ip6tables; then
        if ipset_load inet6 "${SET_PREFIX}-bl6" "$STATE_DIR/v6.list" \
            && ipset_load inet6 "${SET_PREFIX}-wl6" "$STATE_DIR/wl6.list" \
            && ipt_ensure ip6tables 6; then
            :
        else
            warn "IPv6 rules were not installed (IPv4 protection is active)"
        fi
    fi
}

remove_iptables() {
    local bin hook s
    for bin in iptables ip6tables; do
        have "$bin" || continue
        for hook in INPUT DOCKER-USER; do
            while "$bin" -w 5 -D "$hook" -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null; do :; done
        done
        "$bin" -w 5 -F "$CHAIN" 2>/dev/null || true
        "$bin" -w 5 -X "$CHAIN" 2>/dev/null || true
    done
    if have ipset; then
        for s in bl4 wl4 bl6 wl6; do
            ipset destroy "${SET_PREFIX}-$s" 2>/dev/null || true
            ipset destroy "${SET_PREFIX}-$s-tmp" 2>/dev/null || true
        done
    fi
}

# --- native nftables ---

nft_set() { # name type file
    echo "    set $1 {"
    echo "        type $2; flags interval; auto-merge;"
    if [ -s "$3" ]; then
        echo "        elements = {"
        sed 's/$/,/' "$3"
        echo "        }"
    fi
    echo "    }"
}

apply_nft() {
    make_tmp
    {
        # create-if-missing, delete, re-create: the whole swap is one atomic transaction
        echo "table inet $NFT_TABLE"
        echo "delete table inet $NFT_TABLE"
        echo "table inet $NFT_TABLE {"
        nft_set bl4 ipv4_addr "$STATE_DIR/v4.list"
        nft_set wl4 ipv4_addr "$STATE_DIR/wl4.list"
        nft_set bl6 ipv6_addr "$STATE_DIR/v6.list"
        nft_set wl6 ipv6_addr "$STATE_DIR/wl6.list"
        echo "    chain input {"
        echo "        type filter hook input priority -10; policy accept;"
        echo "        ct state new ip saddr @wl4 return"
        echo "        ct state new ip6 saddr @wl6 return"
        echo "        ct state new ip saddr @bl4 counter drop"
        echo "        ct state new ip6 saddr @bl6 counter drop"
        echo "    }"
        echo "}"
    } > "$TMP_DIR/ruleset.nft"
    nft -f "$TMP_DIR/ruleset.nft"
}

remove_nft() {
    if have nft; then nft delete table inet "$NFT_TABLE" 2>/dev/null || true; fi
}

apply_firewall() {
    [ -f "$STATE_DIR/v4.list" ] || die "no cached list in $STATE_DIR and the download failed"
    [ -f "$STATE_DIR/v6.list" ] || : > "$STATE_DIR/v6.list"
    build_whitelist
    case "$(backend)" in
        iptables) apply_iptables ;;
        nft) apply_nft ;;
        *) die "no usable firewall backend" ;;
    esac
}

# --------------------------------------------------------------- commands ---

lock() {
    if have flock; then
        exec 9> "$LOCK_FILE"
        flock -w 120 9 || die "another scanner-guard run is in progress"
    fi
}

cmd_update() {
    need_root
    [ -d "$CONF_DIR" ] || die "not installed; run: scanner-guard.sh install"
    lock
    mkdir -p "$STATE_DIR"
    if fetch_lists; then
        log "lists refreshed"
    else
        warn "list refresh failed; applying the cached list"
    fi
    apply_firewall
    log "active: $(count_lines "$STATE_DIR/v4.list") IPv4 + $(count_lines "$STATE_DIR/v6.list") IPv6 subnets blocked (backend: $(backend))"
}

install_self() {
    local src="${BASH_SOURCE[0]:-}"
    if [ -n "$src" ] && [ -f "$src" ]; then
        if [ "$(readlink -f "$src")" != "$BIN" ]; then install -m 0755 "$src" "$BIN"; fi
    else
        # running from a pipe (curl ... | bash): fetch a real copy for the timer
        curl -fsSL --retry 3 -o "$BIN.new" "$SCRIPT_URL" || die "cannot download $SCRIPT_URL"
        chmod 0755 "$BIN.new"
        mv -f "$BIN.new" "$BIN"
    fi
}

install_schedule() {
    if have systemctl && [ -d /run/systemd/system ]; then
        cat > "$UNIT_SERVICE" <<EOF
[Unit]
Description=Scanner Guard - block scanner subnets
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN update

[Install]
WantedBy=multi-user.target
EOF
        cat > "$UNIT_TIMER" <<EOF
[Unit]
Description=Scanner Guard - periodic list refresh

[Timer]
OnBootSec=2min
OnUnitActiveSec=$REFRESH_INTERVAL
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable scanner-guard.service >/dev/null 2>&1
        systemctl enable --now scanner-guard.timer >/dev/null 2>&1
    else
        cat > "$CRON_FILE" <<EOF
@reboot root sleep 30 && $BIN update >/dev/null 2>&1
17 */6 * * * root $BIN update >/dev/null 2>&1
EOF
        chmod 0644 "$CRON_FILE"
    fi
}

cmd_install() {
    need_root
    local sources=() whitelist=() x
    while [ $# -gt 0 ]; do
        case "$1" in
            --source) [ $# -ge 2 ] || die "--source needs a URL"; sources+=("$2"); shift 2 ;;
            --whitelist) [ $# -ge 2 ] || die "--whitelist needs an IP or CIDR"; whitelist+=("$2"); shift 2 ;;
            *) die "unknown option: $1" ;;
        esac
    done

    ensure_deps
    mkdir -p "$CONF_DIR" "$STATE_DIR"

    if [ ${#sources[@]} -gt 0 ]; then
        printf '%s\n' "${sources[@]}" > "$SOURCES_FILE"
    elif [ ! -f "$SOURCES_FILE" ]; then
        printf '# One URL per line\n%s\n' "$DEFAULT_SOURCE" > "$SOURCES_FILE"
    fi
    [ -f "$WHITELIST_FILE" ] || printf '# One IP or CIDR per line; these are never blocked\n' > "$WHITELIST_FILE"
    for x in ${whitelist[@]+"${whitelist[@]}"}; do
        grep -qxF "$x" "$WHITELIST_FILE" || printf '%s\n' "$x" >> "$WHITELIST_FILE"
    done

    [ -s "$STATE_DIR/backend" ] || detect_backend > "$STATE_DIR/backend"
    install_self
    install_schedule
    cmd_update
    echo
    cmd_status
}

cmd_status() {
    need_root
    if [ ! -d "$CONF_DIR" ]; then echo "State:           not installed"; return 0; fi
    local be rules="missing" dropped="-"
    be="$(backend)"
    case "$be" in
        iptables)
            if iptables -w 5 -C INPUT -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null \
                && iptables -w 5 -C "$CHAIN" -m set --match-set "${SET_PREFIX}-bl4" src -j DROP 2>/dev/null; then
                rules="installed"
                dropped="$(iptables -w 5 -nvxL "$CHAIN" 2>/dev/null | awk '$3 == "DROP" { s += $1 } END { print s + 0 }')"
            fi
            ;;
        nft)
            if nft list chain inet "$NFT_TABLE" input 2>/dev/null | grep -q '@bl4.*drop'; then
                rules="installed"
                dropped="$(nft list chain inet "$NFT_TABLE" input 2>/dev/null \
                    | awk '/drop/ { for (i = 1; i < NF; i++) if ($i == "packets") s += $(i + 1) } END { print s + 0 }')"
            fi
            ;;
    esac
    local state="Disabled"
    [ "$rules" = "installed" ] && state="Enabled"
    echo "State:           $state"
    echo "Blocked subnets: $(( $(count_lines "$STATE_DIR/v4.list") + $(count_lines "$STATE_DIR/v6.list") )) (IPv4: $(count_lines "$STATE_DIR/v4.list"), IPv6: $(count_lines "$STATE_DIR/v6.list"))"
    echo "Whitelisted:     $(( $(count_lines "$STATE_DIR/wl4.list") + $(count_lines "$STATE_DIR/wl6.list") ))"
    echo "Firewall rules:  $rules"
    echo "Firewall backend: $be"
    echo "Dropped packets: $dropped"
    echo "Last list update: $(cat "$STATE_DIR/last_update" 2>/dev/null || echo never)"
    echo "Config:          $SOURCES_FILE, $WHITELIST_FILE"
}

cmd_uninstall() {
    need_root
    if have systemctl; then
        systemctl disable --now scanner-guard.timer >/dev/null 2>&1 || true
        systemctl disable scanner-guard.service >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT_SERVICE" "$UNIT_TIMER" "$CRON_FILE"
    if have systemctl; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    remove_iptables
    remove_nft
    rm -rf "$CONF_DIR" "$STATE_DIR"
    rm -f "$BIN" "$LOCK_FILE"
    log "removed"
}

usage() {
    cat <<EOF
Scanner Guard $VERSION
Usage:
  scanner-guard install [--source URL]... [--whitelist CIDR]...
  scanner-guard update      refresh lists and re-apply rules
  scanner-guard status
  scanner-guard uninstall
EOF
}

main() {
    local cmd="${1:-install}"
    if [ $# -gt 0 ]; then shift; fi
    case "$cmd" in
        install) cmd_install "$@" ;;
        update|refresh) cmd_update ;;
        status) cmd_status ;;
        uninstall|remove) cmd_uninstall ;;
        -h|--help|help) usage ;;
        *) usage; exit 1 ;;
    esac
}

if [ -z "${SCANNER_GUARD_LIB:-}" ]; then
    main "$@"
fi

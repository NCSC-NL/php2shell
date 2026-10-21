#!/usr/bin/env bash
#
# Partial mitigations for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")
# on Hestia Control Panel (hestia-php & Multi-PHP FPM pools).
#
# Per the php.net advisory (2026-10-21) ONLY UPDATING IS A COMPLETE FIX.
# These settings reduce exposure; they do not make an installation fully safe.
#
# What it does:
#   1. Identifies HestiaCP panel's PHP ini (/usr/local/hestia/php/lib/php.ini
#      or /usr/local/hestia/php/etc/php.ini) and applies:
#        memory_limit = -1
#        session.upload_progress.enabled = 0
#        post_max_size = 32M
#   2. Scans all hosted multi-PHP FPM pool configurations (/etc/php/*/fpm/pool.d/*.conf)
#      and injects pool overrides:
#        php_admin_value[memory_limit] = -1
#        php_admin_flag[session.upload_progress.enabled] = off
#        php_admin_value[post_max_size] = 32M
#   3. Restarts hestia and running php*-fpm services.
#
# Default is a dry run. Pass --apply to make changes.
#
# Usage:
#   hestiacp-mitigate.sh              # dry run, show plan
#   hestiacp-mitigate.sh --apply      # apply mitigations
#   hestiacp-mitigate.sh --rollback   # restore backed up configs
#
set -euo pipefail

APPLY=0
ROLLBACK=0
POST_MAX=32M
TAG="cve-2026-109618-109619"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --apply          Apply mitigations (default is dry-run)
  --rollback       Roll back modifications from backups
  --post-max <val> Max POST body size (default: 32M)
  -h, --help       Show this help message
EOF
    exit 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --apply)
            APPLY=1
            shift
            ;;
        --rollback)
            ROLLBACK=1
            APPLY=1
            shift
            ;;
        --post-max)
            POST_MAX="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ] && [ "$APPLY" -eq 1 ]; then
    echo "ERROR: --apply requires root privileges (run with sudo)" >&2
    exit 1
fi

echo "=== HestiaCP Mitigation Tool ($TAG) ==="
if [ "$APPLY" -eq 0 ]; then
    echo "Mode: DRY RUN (no files modified; pass --apply to execute)"
elif [ "$ROLLBACK" -eq 1 ]; then
    echo "Mode: ROLLBACK (restoring previous configuration)"
else
    echo "Mode: APPLY (modifying configurations)"
fi
echo

# 1. Locate hestia-php ini
HESTIA_INI=""
for candidate in "/usr/local/hestia/php/lib/php.ini" "/usr/local/hestia/php/etc/php.ini"; do
    if [ -f "$candidate" ]; then
        HESTIA_INI="$candidate"
        break
    fi
done

if [ -n "$HESTIA_INI" ]; then
    echo "Found HestiaCP panel PHP config: $HESTIA_INI"
    if [ "$ROLLBACK" -eq 1 ]; then
        latest_bak=$(ls -t "${HESTIA_INI}.bak-${TAG}-"* 2>/dev/null | head -n1 || true)
        if [ -n "$latest_bak" ] && [ -f "$latest_bak" ]; then
            echo "  --> Restoring from $latest_bak"
            cp -a "$latest_bak" "$HESTIA_INI"
        else
            echo "  --> No backup found for $HESTIA_INI, skipping"
        fi
    elif grep -q "$TAG" "$HESTIA_INI"; then
        echo "  --> Already contains mitigation, skipping"
    else
        echo "  --> Plan: Append mitigations to $HESTIA_INI"
        if [ "$APPLY" -eq 1 ]; then
            cp -a "$HESTIA_INI" "${HESTIA_INI}.bak-${TAG}-$(date +%s)"
            cat >> "$HESTIA_INI" <<EOF

; --- $TAG emergency hardening ---
memory_limit = -1
session.upload_progress.enabled = 0
post_max_size = $POST_MAX
EOF
            echo "  --> Applied"
        fi
    fi
else
    echo "HestiaCP panel PHP config not found (skipping panel layer)"
fi
echo

# 2. Locate Multi-PHP FPM pool configs
echo "Scanning for PHP-FPM pools under /etc/php/*/fpm/pool.d/..."
POOL_FILES=()
for p in /etc/php/*/fpm/pool.d/*.conf; do
    [ -f "$p" ] || continue
    POOL_FILES+=("$p")
done

if [ "${#POOL_FILES[@]}" -eq 0 ]; then
    echo "No pool files found under /etc/php/*/fpm/pool.d/"
else
    echo "Found ${#POOL_FILES[@]} pool configuration file(s)"
    for pool in "${POOL_FILES[@]}"; do
        if [ "$ROLLBACK" -eq 1 ]; then
            latest_bak=$(ls -t "${pool}.bak-${TAG}-"* 2>/dev/null | head -n1 || true)
            if [ -n "$latest_bak" ] && [ -f "$latest_bak" ]; then
                echo "  --> Restoring $pool from $latest_bak"
                cp -a "$latest_bak" "$pool"
            else
                echo "  --> No backup found for $pool, skipping"
            fi
        elif grep -q "$TAG" "$pool"; then
            echo "  --> $pool: Already contains mitigation, skipping"
        else
            echo "  --> Plan: Append mitigation to $pool"
            if [ "$APPLY" -eq 1 ]; then
                cp -a "$pool" "${pool}.bak-${TAG}-$(date +%s)"
                cat >> "$pool" <<EOF

; --- $TAG emergency hardening ---
php_admin_value[memory_limit] = -1
php_admin_flag[session.upload_progress.enabled] = off
php_admin_value[post_max_size] = $POST_MAX
EOF
                echo "  --> $pool: Applied"
            fi
        fi
    done
fi
echo

# 3. Restarts if applied
if [ "$APPLY" -eq 1 ]; then
    echo "Restarting services..."
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet hestia 2>/dev/null; then
            echo "  --> Restarting hestia"
            systemctl restart hestia || true
        fi
        for fpm_svc in $(systemctl list-unit-files 'php*-fpm.service' 2>/dev/null | awk '{print $1}' | grep '^php.*fpm\.service' || true); do
            echo "  --> Restarting $fpm_svc"
            systemctl restart "$fpm_svc" || true
        done
    fi
    echo "Done. Please verify services with 'systemctl status hestia php*-fpm'."
fi

#!/usr/bin/env bash
#
# Partial mitigations for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")
# on cPanel EasyApache 4 PHP (ea-phpXX).
#
# Per the php.net advisory (2026-10-21) ONLY UPDATING IS A COMPLETE FIX.
# These settings reduce exposure; they do not make an installation safe.
#
# What it does, for every installed /opt/cpanel/ea-php*/root:
#   - writes etc/php.d/zzzzzzzz-cve-2026-109618-109619.ini (loaded after
#     php.ini and every other php.d file, so it wins over cPanel's
#     MultiPHP INI Editor values and over per-directory php.ini files used
#     by suphp/cgi). It never edits php.ini itself.
#       session.upload_progress.enabled = 0   (CVE-2026-109619)
#       post_max_size / upload_max_filesize   (CVE-2026-109618; never raised
#                                              above the current value)
#       memory_limit = -1                     (optional, --memory-unlimited)
#   - reports per-directory overrides (.htaccess php_value/php_flag,
#     .user.ini, php.ini) under /home that could undo these settings
#   - reports Apache RLimitMEM/RLimitCPU, which the advisory says NOT to use
#     for memory limiting (RLIMIT_AS/RLIMIT_DATA trigger the vulnerable path)
#   - restarts Apache (and any running ea-php FPM pools) so every worker
#     picks up the change
#
# Default is a dry run. Pass --apply to make changes.
#
# Usage:
#   php2shell-mitigate.sh                       # dry run, show plan
#   php2shell-mitigate.sh --apply               # apply with defaults (32M)
#   php2shell-mitigate.sh --apply --post-max 8M # no uploads needed
#   php2shell-mitigate.sh --rollback --apply    # remove the drop-in files
#
set -euo pipefail

EA_ROOT=${EA_ROOT:-/opt/cpanel}
SCAN_ROOT=${SCAN_ROOT:-/home}
DROPIN_NAME=zzzzzzzz-cve-2026-109618-109619.ini

POST_MAX=32M
UPLOAD_MAX=
MEMORY_UNLIMITED=0
APPLY=0
ROLLBACK=0
RESTART=1
SCAN=1

usage() {
	sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
	cat <<'EOF'
Options:
  --apply              make changes (default is a dry run)
  --post-max SIZE      post_max_size ceiling (default 32M; use 8M if no uploads)
  --upload-max SIZE    upload_max_filesize ceiling (default: same as --post-max)
  --memory-unlimited   also set memory_limit = -1 (see advisory; trades
                       availability for removing the PHP-level OOM trigger)
  --no-restart         don't restart Apache / PHP-FPM
  --no-scan            skip the /home per-directory override scan
  --rollback           remove the drop-in files instead of writing them
  -h, --help           show this help
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
		--apply) APPLY=1 ;;
		--post-max) POST_MAX=${2:?}; shift ;;
		--upload-max) UPLOAD_MAX=${2:?}; shift ;;
		--memory-unlimited) MEMORY_UNLIMITED=1 ;;
		--no-restart) RESTART=0 ;;
		--no-scan) SCAN=0 ;;
		--rollback) ROLLBACK=1 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done
UPLOAD_MAX=${UPLOAD_MAX:-$POST_MAX}

log()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
run()  { if [ "$APPLY" = 1 ]; then "$@"; else log "  [dry-run] $*"; fi; }

# PHP shorthand size -> bytes. 0 means "no limit" for post_max_size.
to_bytes() {
	local v n
	v=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
	n=${v%[KMG]}
	case $n in ''|*[!0-9]*) echo -1; return ;; esac
	case $v in
		*K) echo $((n * 1024)) ;;
		*M) echo $((n * 1024 * 1024)) ;;
		*G) echo $((n * 1024 * 1024 * 1024)) ;;
		*)  echo "$n" ;;
	esac
}

# Smaller of current and ceiling, treating 0/unparseable current as unlimited.
cap() {
	local cur=$1 ceil=$2 cb
	cb=$(to_bytes "$cur")
	if [ "$cb" -gt 0 ] && [ "$cb" -lt "$(to_bytes "$ceil")" ]; then
		echo "$cur"
	else
		echo "$ceil"
	fi
}

for s in "$POST_MAX" "$UPLOAD_MAX"; do
	if [ "$(to_bytes "$s")" -le 0 ]; then
		echo "invalid size: $s" >&2; exit 2
	fi
done
if [ "$(to_bytes "$UPLOAD_MAX")" -gt "$(to_bytes "$POST_MAX")" ]; then
	UPLOAD_MAX=$POST_MAX
fi

if [ "$APPLY" = 1 ] && [ "$(id -u)" != 0 ]; then
	echo "--apply must run as root" >&2; exit 1
fi

[ "$APPLY" = 1 ] || log "DRY RUN: no changes will be made (pass --apply)"
log ""

if command -v whmapi1 >/dev/null 2>&1; then
	log "== PHP handlers (whmapi1 php_get_handlers)"
	whmapi1 php_get_handlers 2>/dev/null \
		| awk '/current_handler:/ {h = $NF} /version: ea-php/ {print "  " $NF ": " h; h = ""}' || true
	log ""
fi

shopt -s nullglob
roots=("$EA_ROOT"/ea-php*/root)
if [ ${#roots[@]} -eq 0 ]; then
	echo "no EA4 PHP installs found under $EA_ROOT/ea-php*/root" >&2; exit 1
fi

fpm_services=()
for root in "${roots[@]}"; do
	ver=$(basename "$(dirname "$root")")
	php=$root/usr/bin/php
	scandir=$root/etc/php.d
	dropin=$scandir/$DROPIN_NAME

	log "== $ver"
	if [ ! -x "$php" ] || [ ! -d "$scandir" ]; then
		warn "$ver: missing $php or $scandir, skipping"
		continue
	fi

	if [ "$ROLLBACK" = 1 ]; then
		if [ -e "$dropin" ]; then
			run rm -f "$dropin"
			log "  removed $dropin"
		else
			log "  nothing to remove"
		fi
	else
		# Read current effective values with our drop-in excluded, so re-runs
		# compare against the real baseline rather than our own previous caps.
		tmpd=$(mktemp -d)
		for f in "$scandir"/*.ini; do
			[ "$(basename "$f")" = "$DROPIN_NAME" ] || cp "$f" "$tmpd/"
		done
		cur=$(PHP_INI_SCAN_DIR=$tmpd "$php" -r '
			foreach (["session.upload_progress.enabled", "post_max_size",
			          "upload_max_filesize", "memory_limit"] as $k)
				echo $k, "=", ini_get($k), "\n";')
		rm -rf "$tmpd"
		cur_post=$(printf '%s\n' "$cur" | sed -n 's/^post_max_size=//p')
		cur_upload=$(printf '%s\n' "$cur" | sed -n 's/^upload_max_filesize=//p')
		log "  current: $(printf '%s' "$cur" | tr '\n' ' ')"

		new_post=$(cap "$cur_post" "$POST_MAX")
		new_upload=$(cap "$cur_upload" "$UPLOAD_MAX")
		if [ "$(to_bytes "$new_upload")" -gt "$(to_bytes "$new_post")" ]; then
			new_upload=$new_post
		fi

		content="; Managed by php2shell-mitigate.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ)).
; PARTIAL mitigation for CVE-2026-109618 / CVE-2026-109619. Only updating
; PHP is a complete fix. Remove with: php2shell-mitigate.sh --rollback --apply
session.upload_progress.enabled = 0
post_max_size = $new_post
upload_max_filesize = $new_upload"
		if [ "$MEMORY_UNLIMITED" = 1 ]; then
			content="$content
memory_limit = -1"
		fi

		log "  write $dropin:"
		printf '%s\n' "$content" | sed -n '/^[^;]/s/^/    /p'
		if [ "$APPLY" = 1 ]; then
			printf '%s\n' "$content" > "$dropin.tmp"
			chmod 644 "$dropin.tmp"
			mv -f "$dropin.tmp" "$dropin"

			got=$("$php" -r 'echo ini_get("session.upload_progress.enabled") ? "1" : "0", " ",
				ini_get("post_max_size"), " ", ini_get("upload_max_filesize"), " ",
				ini_get("memory_limit");')
			want="0 $new_post $new_upload"
			[ "$MEMORY_UNLIMITED" = 1 ] && want="$want -1"
			case "$got" in
				"$want"*) log "  verified: $got" ;;
				*) warn "$ver: verification mismatch, got '$got', want '$want'" ;;
			esac
		fi
	fi

	svc=${ver}-php-fpm
	if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$svc" 2>/dev/null; then
		fpm_services+=("$svc")
	fi
	log ""
done

if [ "$SCAN" = 1 ] && [ "$ROLLBACK" = 0 ] && [ -d "$SCAN_ROOT" ]; then
	log "== Per-directory overrides under $SCAN_ROOT"
	log "   (.htaccess php_value/php_flag override everything under mod_php/dso;"
	log "    check these sites don't re-enable upload progress or raise sizes)"
	hits=$(find "$SCAN_ROOT" -xdev -path '*/virtfs' -prune -o \
			\( -name .htaccess -o -name .user.ini -o -name php.ini \) -type f -print0 2>/dev/null \
		| xargs -0 grep -HniE 'session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit' 2>/dev/null \
		| grep -v '^[^:]*:[0-9]*:[[:space:]]*[;#]' || true)
	if [ -n "$hits" ]; then
		printf '%s\n' "$hits" | sed 's/^/  /'
	else
		log "  none found"
	fi
	log ""
fi

log "== Apache resource limits (advisory: do NOT limit memory via RLIMIT_AS/DATA)"
rl=$(grep -rniE '^[[:space:]]*RLimit(MEM|CPU)' /etc/apache2/conf /etc/apache2/conf.d 2>/dev/null || true)
if [ -n "$rl" ]; then
	printf '%s\n' "$rl" | sed 's/^/  /'
	warn "RLimitMEM is set. Disable it in WHM > Apache Configuration > Memory Usage Restrictions (httpd.conf is regenerated, don't hand-edit)."
else
	log "  none found"
fi
log ""

if [ "$RESTART" = 1 ]; then
	log "== Restarting services so every worker reloads php.ini"
	if [ -x /scripts/restartsrv_httpd ]; then
		run /scripts/restartsrv_httpd
	else
		warn "/scripts/restartsrv_httpd not found; restart Apache manually"
	fi
	for svc in ${fpm_services[@]+"${fpm_services[@]}"}; do
		run systemctl restart "$svc"
	done
else
	log "== Skipped restart (--no-restart). Restart Apache and any PHP-FPM pools yourself."
fi

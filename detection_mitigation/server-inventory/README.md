# Server-wide PHP inventory

Updating "PHP" on a server often misses copies that the package manager does not manage.
A single host can run several PHP builds at once:

| Source | Updated by `apt` / `dnf`? | Notes |
| --- | --- | --- |
| Distribution packages | Yes | Backports may keep the old version number; check the changelog, not the version. |
| Third-party repositories (e.g. sury, remi) | Yes | Usually carry the upstream version number. |
| Control-panel builds compiled from source (e.g. aaPanel / BT Panel in `/www/server/php/NN`, DirectAdmin CustomBuild in `/usr/local/phpNN`) | No | Update through the panel. Several panels ship patched builds. |
| Manually compiled PHP (e.g. `/opt/php*`) | No | Rebuild from a fixed release, or the official backport for 7.4 / 8.0 / 8.1. |

The steps below find every PHP build on a Linux host and show whether each one has the fix.

## 1. Find PHP builds

Running PHP processes:

```bash
ps -eo pid,user,cmd | grep -E 'php-fpm: master|lsphp|php-cgi|apache2|httpd' | grep -v grep
```

PHP binaries in common locations:

```bash
find /usr/bin /usr/sbin /usr/local /opt /www/server -maxdepth 6 \
  -regextype posix-extended -regex '.*/s?bin/(php(-fpm|-cgi)?|lsphp)[0-9.]*' 2>/dev/null
```

Note: with GNU `find`, write the pattern as `php(-fpm|-cgi)?`. The form `(php|php-fpm|php-cgi)` does not match `php-fpm` or `php-cgi`, because matching stops at the first alternative.

## 2. Check each build

Find out whether a package owns the binary:

```bash
dpkg -S /path/to/php-binary     # Debian / Ubuntu
rpm -qf /path/to/php-binary     # RHEL family
```

For package builds, look for the CVE identifiers in the changelog:

```bash
zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/<package>/changelog.Debian.gz
rpm -q --changelog <package> | grep -E 'CVE-2026-10961[89]'
```

For builds no package owns, compare `/path/to/php -v` with the fixed releases (8.2.35, 8.3.36, 8.4.27, 8.5.12) or your vendor's patched build.

## 3. Make sure workers run the patched binary

A patched binary on disk is not used until the PHP workers restart. This lists processes still running a binary that has been replaced:

```bash
for d in /proc/[0-9]*; do
  e=$(readlink "$d/exe" 2>/dev/null) || continue
  [[ $e == *php*"(deleted)" ]] && echo "${d#/proc/} $e"
done
```

Restart (or, for php-fpm, reload) the service that owns each process listed.

## Automated option

[php2shell-fix](https://github.com/xbuddhi/php2shell-fix) is a community script that automates the steps above. It is not made or reviewed by NCSC-NL. By default it only reports. With `--apply` it:

- upgrades package builds through the package manager;
- rebuilds source builds from php.net releases, using each build's original configure options;
- applies PHP's official 7.4 / 8.0 / 8.1 backport commits;
- leaves vendor-patched builds (e.g. aaPanel 7.4.34) alone;
- backs up each build before rebuilding it and rolls back on failure.

Review it and test it before using it in production.

Updating to fixed PHP releases or vendor-provided backports remains the complete remediation.

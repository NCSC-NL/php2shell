# Server-wide PHP inventory

Updating "PHP" on a server often misses copies that the package manager does not manage.
A single host can run several PHP builds at once:

| Source | Updated by `apt` / `dnf`? | Notes |
| --- | --- | --- |
| Distribution packages | Yes, if a fixed package is available from an enabled repository | Backports may retain the upstream version; compare the full installed package version with the distribution advisory. |
| Third-party repositories (e.g. sury, remi) | Yes, if a fixed package is available from an enabled repository | Verify the repository's advisory and installed package version. |
| Control-panel builds compiled from source (e.g. aaPanel / BT Panel in `/www/server/php/NN`, DirectAdmin CustomBuild in `/usr/local/phpNN`) | No | Follow the panel vendor's update instructions and confirm coverage of both CVEs for each installed build. |
| Manually compiled PHP (e.g. `/opt/php*`) | No | Rebuild from a fixed supported release; see the end-of-life caveat below. |

These Bash examples are a starting point for an inventory, not an exhaustive scanner or proof of remediation. Use sufficient privileges to read other users' processes and protected directories. Add deployment-specific paths, inspect service and web-server configuration, and inventory containers and chroots separately. Resolve permission errors; an empty result is not proof that PHP is absent or fixed.

## 1. Find PHP builds

Candidate PHP and web-server processes, including long-running CLI workers:

```bash
ps -ww -eo pid,user,args | grep -E '[p]hp|[a]pache2|[h]ttpd'
```

PHP binaries and Apache PHP modules in common locations (GNU `find`). Remove nonexistent search roots and add custom locations:

```bash
find /usr/bin /usr/sbin /usr/local /usr/lib /usr/lib64 /opt /www/server \
  -regextype posix-extended \( -type f -o -type l \) \
  \( -regex '.*/(php([0-9.]*(-fpm|-cgi)?|(-fpm|-cgi)[0-9.]*)|lsphp[0-9.]*|frankenphp)' \
     -o -name 'libphp*.so' \) -print
```

GNU `find -regex` matches the entire path; both `php(-fpm|-cgi)?` and `(php|php-fpm|php-cgi)` are valid alternatives for those three names. The search above also handles common versioned names such as `php8.3-fpm` and `php-fpm8.3`. It lists symlinks but does not traverse symlinked directories; inspect their targets separately. Renamed binaries and embedded runtimes may need manual identification.

For each candidate process, inspect its actual executable and any loaded Apache PHP module. Replace the example PID:

```bash
pid=1234
readlink "/proc/$pid/exe"
grep -E '/libphp[^/ ]*\.so([[:space:]]|$)' "/proc/$pid/maps"
```

Apache's executable version is not its loaded PHP version. A CLI `php -v` result also does not establish the version used by a web service. Record the executable or module path, owning package or build, and service for each runtime.

## 2. Check each build

Find out whether a package owns the executable or module. Resolve symlinks and query the target as well; replace the example path:

```bash
dpkg-query -S /path/to/php-binary  # Debian / Ubuntu
rpm -qf /path/to/php-binary     # RHEL family
```

For Debian/Ubuntu packages, record the installed version and inspect the relevant changelog entry. Replace the package name with the owner found above:

```bash
package='REPLACE_WITH_OWNING_PACKAGE'
dpkg-query -W "$package"
zgrep -n -E 'CVE-2026-10961[89]' "/usr/share/doc/$package/changelog.Debian.gz"
```

For RPM-based systems:

```bash
package='REPLACE_WITH_OWNING_PACKAGE'
rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package"
rpm -q --changelog "$package" | grep -n -E 'CVE-2026-10961[89]'
```

A CVE match is only a lead: read the full entry and confirm that it fixes **both** CVEs for the installed distribution release, package and architecture. Compare the full installed package version (including any epoch and vendor revision) with the vendor's fixed version using distribution-aware version comparison. A changelog can mention an unresolved issue, and missing or omitted entries do not prove vulnerability. Consult the vendor advisory or security tracker when local records are insufficient; [Red Hat documents advisory inspection with DNF](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_and_monitoring_security_updates/identifying-security-updates_managing-and-monitoring-security-updates).

For trusted builds no package owns, compare that specific binary's `-v` output and build provenance with the [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5). The supported-branch fixes are 8.2.35, 8.3.36, 8.4.27 and 8.5.12, or later releases on the corresponding branch. For vendor builds, require an explicit advisory covering both CVEs; a custom version suffix or marker file is not proof. Do not execute unknown binaries as root merely to identify them.

PHP 7.4, 8.0 and 8.1 are end-of-life. PHP published minimal source backports, not new supported releases; the [PHP 7.4 backport commit](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2) explicitly describes a minimal mitigation for an EOL version. Do not equate these with the full supported-release fixes. Follow vendor guidance and plan migration to a supported branch.

## 3. Make sure workers run the patched binary

A patched file on disk does not update workers already using the old executable or module. These checks identify some stale mappings through Linux's [`/proc` interface](https://www.kernel.org/doc/html/latest/filesystems/proc.html):

```bash
for d in /proc/[0-9]*; do
  e=$(readlink "$d/exe" 2>/dev/null) || continue
  if [[ $e == *php*' (deleted)' ]]; then
    printf '%s %s\n' "${d#/proc/}" "$e"
  fi
done

grep -H -E '/libphp[^/ ]*\.so.* \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null
```

The module check covers Apache `mod_php`, whose executable is normally named `apache2` or `httpd`, not PHP. Process exits and permission failures are suppressed in this example, so review access restrictions separately. No output is not proof of freshness: renamed files, in-place updates and custom executable names may not be detected by these checks.

Use each service's documented restart procedure after updating, including Apache when it loads `mod_php`, FPM, LiteSpeed and long-running workers as applicable. An FPM reload is sufficient only if the service's implementation re-executes the updated binary and all old workers exit. Recheck process executable/module paths and package or build provenance, confirm old workers have drained, and test service health. Rebuild and redeploy container images separately; updating the host does not patch them.

## Automated option

[php2shell-fix](https://github.com/xbuddhi/php2shell-fix) is a third-party inventory and remediation tool. It is not made, reviewed or endorsed by NCSC-NL. Its installer and script can have different defaults; this guide does not guarantee report-only behavior, complete coverage, fix detection or rollback. Review a pinned revision and its dependencies before execution, prefer vendor-supported update procedures, and test changes and recovery on a non-production copy. Do not treat a tool's report alone as evidence that every runtime is fixed.

Updating to fixed PHP releases or vendor-provided backports remains the complete remediation.

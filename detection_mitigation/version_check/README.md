# Runtime version check

Many sites hide their PHP version (`expose_php = Off`, no `X-Powered-By` header), so an outside scan cannot tell
whether a site is on a fixed release. On shared hosting the PHP version used by the web server can also differ from
`php -v` on the command line.

`check-php.php` gives the exact runtime version as seen by the web server, then deletes itself so the version is not
left public.

## Use

1. Upload `check-php.php` to the site's document root (the folder with `index.php`, often `public_html`).
2. Open `https://<site>/check-php.php` once.
3. It prints the PHP version and whether the branch is end of life, then removes itself. If it reports that it could
   not delete itself, delete it by hand.

The file is 10 lines and has no dependencies. Review it before use.

## Reading the result

| Runtime version | Status |
| --- | --- |
| 8.5.12, 8.4.27, 8.3.36, 8.2.35 or newer in the branch | Fixed release |
| Older 8.2 to 8.5 | Update to the fixed release for the branch and restart PHP workers |
| 8.1, 8.0, 7.4 | No PHP project release; check for a distribution, LTS vendor or hosting provider backport |
| 7.3 and older | No fix available; upgrade to a supported branch |

Distribution builds (for example `8.3.6-1ubuntu...`) may contain backported fixes without a version change. Check the
distribution's security notices for those.

An outside, non-intrusive check that reads only public signals (headers, cookies, CMS fingerprints) is also available
at https://simgen.dev/php-patch-check.

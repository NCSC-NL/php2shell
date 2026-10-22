from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


README = Path(__file__).resolve().parents[1] / "detection_mitigation/server-inventory/README.md"


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"),
                     "Linux and Bash are required for the inventory examples")
class ServerInventoryExamplesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks = re.findall(r"```bash\n(.*?)```", README.read_text(encoding="utf-8"), re.S)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="php-inventory-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def block(self, prefix):
        matches = [block for block in self.blocks if block.startswith(prefix)]
        self.assertEqual(len(matches), 1, f"Expected one example starting with {prefix!r}")
        return matches[0]

    def run_example(self, code, stdin=None):
        return subprocess.run(["bash", "-c", code], input=stdin, capture_output=True,
                              text=True, timeout=10)

    def fixture_file(self, relative, contents=""):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def stale_example(self):
        # Redirect every /proc reference, including PID formatting, into test fixtures.
        return self.block("for d in /proc/").replace("/proc/", f"{self.root}/proc/")

    def test_all_shell_examples_parse(self):
        self.assertEqual(len(self.blocks), 7)
        for number, block in enumerate(self.blocks, 1):
            with self.subTest(example=number):
                result = subprocess.run(["bash", "-n"], input=block, capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_discovery_handles_versions_modules_deep_paths_and_symlinks(self):
        names = [
            "usr/bin/php", "usr/bin/php8.3", "usr/sbin/php-fpm", "usr/sbin/php-fpm8.3",
            "usr/sbin/php8.3-fpm", "usr/bin/php-cgi8.3", "usr/bin/php8.3-cgi",
            "usr/local/lsws/lsphp83/bin/php", "opt/panel/lsphp", "opt/panel/lsphp83",
            "usr/bin/frankenphp", "usr/lib/apache2/modules/libphp8.3.so",
            "usr/lib64/httpd/modules/libphp.so", "opt/a/b/c/d/e/f/g/bin/php",
        ]
        expected = {str(self.fixture_file(name)) for name in names}
        for name in ["usr/bin/php-config", "usr/bin/phpize", "opt/info.php",
                     "usr/lib/apache2/modules/mod_ssl.so", "opt/php-fpm.backup"]:
            self.fixture_file(name)
        (self.root / "usr/bin/php9.0").mkdir()
        alias = self.root / "usr/bin/php8.5"
        alias.symlink_to(self.root / "usr/bin/php")
        expected.add(str(alias))
        code = self.block("find /usr/bin")
        roots = "/usr/bin /usr/sbin /usr/local /usr/lib /usr/lib64 /opt /www/server"
        self.assertIn(roots, code)
        result = self.run_example(code.replace(roots, shlex.quote(str(self.root)), 1))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(result.stdout.splitlines()), expected)

    def test_gnu_regex_alternatives_both_match_fpm_and_cgi(self):
        expected = {str(self.fixture_file(f"bin/{name}")) for name in ["php", "php-fpm", "php-cgi"]}
        for pattern in [".*/php(-fpm|-cgi)?", ".*/(php|php-fpm|php-cgi)"]:
            with self.subTest(pattern=pattern):
                result = self.run_example(
                    f"find {shlex.quote(str(self.root))} -regextype posix-extended "
                    f"-regex {shlex.quote(pattern)}"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(set(result.stdout.splitlines()), expected)

    def test_process_filter_includes_cli_workers_and_embedded_runtime(self):
        candidates = [
            "101 www php-fpm: master process", "102 www php-fpm: pool app",
            "103 app /opt/php/bin/php queue.php", "104 www lsphp",
            "105 www php-cgi", "106 www apache2", "107 www httpd",
            "108 www frankenphp run",
        ]
        stdin = ("PID USER COMMAND\n" + "\n".join(candidates)
                 + "\n109 root sshd\n110 root grep -E [p]hp|[a]pache2|[h]ttpd\n")
        result = self.run_example("ps() { cat; }\n" + self.block("ps -ww"), stdin)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), candidates)

    def test_stale_check_finds_replaced_executable_and_apache_module(self):
        self.fixture_file("proc/101/maps")
        (self.root / "proc/101/exe").symlink_to("/opt/php/bin/php-fpm (deleted)")
        self.fixture_file("proc/102/maps", "1000-2000 r-xp 0 00:01 42 /usr/lib/apache2/libphp.so (deleted)\n")
        (self.root / "proc/102/exe").symlink_to("/usr/sbin/apache2")
        self.fixture_file("proc/103/maps", "1000-2000 r-xp 0 00:01 43 /usr/lib/apache2/libphp.so\n")
        (self.root / "proc/103/exe").symlink_to("/usr/sbin/php-fpm8.3")
        self.fixture_file("proc/104/maps", "1000-2000 r-xp 0 00:01 44 /usr/lib/libssl.so (deleted)\n")
        (self.root / "proc/104/exe").symlink_to("/usr/sbin/httpd")
        result = self.run_example(self.stale_example())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 2)
        self.assertIn("101 /opt/php/bin/php-fpm (deleted)", result.stdout)
        self.assertIn("proc/102/maps:", result.stdout)
        self.assertNotIn("proc/103", result.stdout)
        self.assertNotIn("proc/104", result.stdout)

    def test_stale_check_with_current_files_has_no_findings(self):
        self.fixture_file("proc/101/maps", "1000-2000 r-xp 0 00:01 42 /usr/lib/apache2/libphp.so\n")
        (self.root / "proc/101/exe").symlink_to("/usr/sbin/apache2")
        result = self.run_example(self.stale_example())
        self.assertEqual(result.returncode, 1)  # grep reports no matches.
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

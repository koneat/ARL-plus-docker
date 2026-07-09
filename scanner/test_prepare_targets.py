#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("prepare_targets.py")
SPEC = importlib.util.spec_from_file_location("prepare_targets", MODULE_PATH)
assert SPEC and SPEC.loader
prepare_targets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare_targets)


class PrepareTargetsTest(unittest.TestCase):
    def test_domain_port_keeps_dns_host_clean(self) -> None:
        self.assertEqual(
            prepare_targets.classify("api.example.com:8443"),
            ("domain", "api.example.com\tapi.example.com:8443"),
        )

    def test_wildcard_root_is_preserved(self) -> None:
        self.assertEqual(
            prepare_targets.classify("*.example.com"),
            ("domain", "example.com\texample.com"),
        )

    def test_ipv6_port_is_supported(self) -> None:
        self.assertEqual(
            prepare_targets.classify("[2001:db8::1]:443"),
            ("ip-port", "2001:db8::1\t[2001:db8::1]:443"),
        )

    def test_unicode_domain_is_idna_normalized(self) -> None:
        kind, value = prepare_targets.classify("例子.测试") or (None, None)
        self.assertEqual(kind, "domain")
        self.assertTrue(value.startswith("xn--"))

    def test_main_separates_dns_and_http_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "targets.txt"
            output = root / "out"
            source.write_text(
                "*.example.com\napi.example.com:8443\n[2001:db8::1]:443\n",
                encoding="utf-8",
            )
            with patch("sys.argv", ["prepare_targets.py", str(source), str(output)]):
                self.assertEqual(prepare_targets.main(), 0)

            self.assertEqual(
                (output / "domains.txt").read_text(encoding="utf-8").splitlines(),
                ["example.com", "api.example.com"],
            )
            self.assertEqual(
                (output / "ips.txt").read_text(encoding="utf-8").splitlines(),
                ["2001:db8::1"],
            )
            self.assertEqual(
                (output / "http-probe.txt").read_text(encoding="utf-8").splitlines(),
                ["example.com", "api.example.com:8443", "[2001:db8::1]:443"],
            )


if __name__ == "__main__":
    unittest.main()

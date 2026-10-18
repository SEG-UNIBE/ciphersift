#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
"""P3-SUITE: IANA TLS cipher-suite names (spec/anycall-names.csv rows of group G5d-tls-suite, each with its IANA URL)
as Python literal patterns, filed under the Python rule of the Java rule each row names. usage: gen_python_suites.py <repository root>"""
import csv, sys
from pathlib import Path
W = Path(sys.argv[1])
per = {}
for r in csv.DictReader(open(W / "spec/anycall-names.csv")):
    if r["group"] == "G5d-tls-suite":
        per.setdefault("python." + r["rule"].split(".", 1)[1], set()).add(r["name"])
MARK = "# DECISIONS P3-SUITE"
for rid, names in sorted(per.items()):
    p = W / "rules/python" / f"{rid}.yaml"
    s = p.read_text()
    if MARK in s:
        s = s[:s.index(MARK)]
    s = s.rstrip("\n") + "\n"
    s += (MARK + ": IANA TLS cipher suites as exact string literals (names and source URL: spec/anycall-names.csv,\n"
          "# group G5d-tls-suite, IANA TLS Cipher Suites registry, fetched 2026-10-18)\n"
          "- literal: [" + ", ".join("'" + n + "'" for n in sorted(names)) + "]\n  feature: python-literal-names\n")
    p.write_text(s)
    print(rid, len(names))

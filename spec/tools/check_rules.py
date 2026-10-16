#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
"""Validate rule files against spec/rule-schema.json plus the semantic checks of SPEC.md 5.8.

Usage: python3 check_rules.py [rules dir]   (needs PyYAML and jsonschema)
Prints counts and exits non-zero on the first set of errors.
"""
import json
import re
import sys
from pathlib import Path

import jsonschema
import yaml

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parents[1] / "rules"
schema = json.loads((HERE.parent / "rule-schema.json").read_text())
validator = jsonschema.Draft202012Validator(schema)
errors, ids, counts = [], {}, {}
RX_KEYS = ("firstString", "anyString", "argsText", "body", "value")
for f in sorted(ROOT.rglob("*")):
    if f.suffix not in (".yaml", ".yml", ".json") or not f.is_file():
        continue
    doc = yaml.safe_load(f.read_text(encoding="utf-8"))
    for e in validator.iter_errors(doc):
        errors.append(f"{f}: {e.message} at {list(e.absolute_path)}")
    rid = doc.get("id")
    if rid in ids:
        errors.append(f"{f}: duplicate id {rid} (also {ids[rid]})")
    ids[rid] = f
    if f.stem != rid and doc.get("kind") != "constants":
        errors.append(f"{f}: file name must be <id>.yaml")
    kind = doc.get("kind")
    key = doc.get("language") or doc.get("ecosystem")
    counts[(kind, key)] = counts.get((kind, key), 0) + 1
    for p in doc.get("match") or []:
        for k in RX_KEYS:
            if k in p:
                re.compile(p[k])
        for rx in (p.get("kwargs") or {}).values():
            re.compile(rx)
        if doc.get("language") == "python" and "*" in str(p.get("method", "")):
            errors.append(f"{f}: '*' prefix is Java-only")
if errors:
    print("\n".join(errors[:50]))
    sys.exit(1)
for k in sorted(counts, key=str):
    print(f"{k[0]:10} {k[1]:7} {counts[k]}")

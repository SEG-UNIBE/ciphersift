#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
"""Produce the expected findings of the conformance suite from the reference tool.

The reference tool is the BF-CBOM fork of Crypsy (Python). This script must run
with the reference tool's interpreter, because it drives the tool's own file
collection, classification and extraction phases and records the raw findings
(before the reference tool's component merging, which can hide occurrences):

  <crypsy venv>/bin/python -I spec/tools/make_expected.py \
      --registry <crypistry dir> --rules rules --cases spec/conformance/cases \
      --deviations spec/conformance/deviations.yaml

For every case directory (a directory containing input/), it writes
expected.json next to input/. Findings are post-processed into the
implementation-independent format of spec/conformance/README.md:

  * rule ids are mapped to CipherSift ids (src.java.X -> java.X,
    src.python.X -> python.X, dep.python.* -> dep.pypi);
  * paths are made relative to input/ (POSIX separators);
  * asset properties are taken from the converted CipherSift rule;
  * only Java/Python source findings and PyPI dependency findings are kept
    (Maven expectations are hand-written in deviations.yaml, because the
    reference tool's pom.xml support is not part of the carried-over work);
  * the deviations listed in deviations.yaml (intentional differences between
    CipherSift and the reference tool) are applied last.

Nothing of the reference tool is copied; it is only executed.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

import yaml


def load_new_rules(rules_dir: Path) -> dict[str, dict]:
    out = {}
    for f in rules_dir.rglob("*.yaml"):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(d, dict) and d.get("kind") in ("source", "dependency"):
            out[d["id"]] = d
    return out


def map_rule_id(old: str) -> str | None:
    m = re.fullmatch(r"src\.(java|python)\.(.+)", old)
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    if old.startswith("dep.python."):
        return "dep.pypi"
    return None


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def record(finding, rel: str, new_id: str, rule: dict) -> dict:
    a = rule["asset"]
    if rule["kind"] == "dependency":
        rd = finding.raw_data
        return {"file": rel, "line": None, "rule": new_id, "type": "library",
                "ecosystem": rule["ecosystem"], "package": norm_pypi(rd["package"]),
                "version": rd.get("version") or None}
    rd = finding.raw_data
    rec = {"file": rel, "line": finding.location.line, "rule": new_id, "type": a["type"]}
    for k in ("subtype", "primitive", "family", "variant", "protocol", "version"):
        rec[k] = a.get(k)
    rec["param"] = None if rd.get("param") is None else str(rd["param"])
    if a["type"] == "algorithm":
        rec["name"] = rd.get("component_name") or rd.get("call")
    else:
        rec["name"] = None
    return rec


TEST_DIRS = {"test", "tests", "testing", "__tests__", "testdata", "test-data", "testfixtures",
             "test-fixtures", "integrationtest", "integration-test", "integration-tests"}


def is_test_file(rel: str) -> bool:
    """SPEC.md 4.7 (CipherSift behaviour; the reference tool has no test-file detection)."""
    parts = rel.split("/")
    dirs, base = parts[:-1], parts[-1]
    for i, d in enumerate(dirs):
        if d.lower() in TEST_DIRS or (d.lower() == "it" and i > 0 and dirs[i - 1].lower() == "src"):
            return True
    # file-name rules are case-sensitive (Surefire / pytest conventions); directories are not
    if base.endswith(".java"):
        stem = base[:-5]
        if (stem.endswith(("Test", "Tests", "TestCase", "IT"))
                or (stem.startswith("Test") and len(stem) > 4 and stem[4].isupper())):
            return True
    if base.endswith(".py"):
        if base.startswith("test_") or base.endswith("_test.py") or base in ("tests.py", "conftest.py"):
            return True
    return False


def key(r: dict) -> tuple:
    return (r["file"], r["line"] or 0, r["rule"], r.get("name") or "", r.get("param") or "",
            r.get("package") or "", r.get("version") or "")


def scan_case(input_dir: Path, registry, new_rules, options: dict) -> list[dict]:
    from crypsy.asset_discovery.asset_extractor import extract_assets
    from crypsy.asset_discovery.file_classifier import classify_files, filter_ruleset
    from crypsy.asset_discovery.file_collector import collect_files
    from crypsy.core.scan_config import ScanConfig

    args = list(options.get("args") or [])
    excludes = [args[i + 1] for i, a in enumerate(args) if a == "--exclude"]
    # the reference tool has no test-file switch; --exclude-tests is applied through deviations.yaml
    cfg = ScanConfig(target_path=input_dir, exclude_patterns=excludes)
    files = collect_files(cfg)
    classified = classify_files(files, registry.ruleset)
    active = filter_ruleset(registry.ruleset, classified, True)
    findings = extract_assets(classified, active)
    out: dict[tuple, dict] = {}
    root = input_dir.resolve()
    for f in findings:
        new_id = map_rule_id(f.rule_identifier)
        if new_id is None:
            continue
        rel = Path(f.location.file_path).resolve().relative_to(root).as_posix()
        rec = record(f, rel, new_id, new_rules[new_id])
        if is_test_file(rel):
            rec["test"] = True
        out.setdefault(key(rec), rec)
    return [out[k] for k in sorted(out)]


def apply_deviations(case: str, recs: list[dict], devs: dict, new_rules) -> list[dict]:
    d = (devs.get("cases") or {}).get(case) or {}
    for rm in d.get("remove") or []:
        before = len(recs)
        recs = [r for r in recs if not all(r.get(k) == v for k, v in rm["match"].items())]
        if len(recs) == before:
            sys.exit(f"{case}: deviation remove {rm['match']} matched nothing")
    for add in d.get("add") or []:
        rec = dict(add["finding"])
        rule = new_rules[rec["rule"]]
        a = rule["asset"]
        if rule["kind"] == "source":
            base = {"file": None, "line": None, "rule": None, "type": a["type"]}
            for k in ("subtype", "primitive", "family", "variant", "protocol", "version"):
                base[k] = a.get(k)
            base.update({"param": None, "name": None})
        else:
            base = {"file": None, "line": None, "rule": None, "type": "library",
                    "ecosystem": rule["ecosystem"], "package": None, "version": None}
        base.update(rec)
        if is_test_file(base["file"]):
            base["test"] = True
        if any(key(r) == key(base) for r in recs):
            sys.exit(f"{case}: deviation add {rec} already present")
        recs.append(base)
    for ch in d.get("change") or []:
        hit = [r for r in recs if all(r.get(k) == v for k, v in ch["match"].items())]
        if not hit:
            sys.exit(f"{case}: deviation change {ch['match']} matched nothing")
        for r in hit:
            r.update(ch["set"])
    return sorted(recs, key=key)


def render(case: str, recs: list[dict]) -> str:
    """One finding per line, keys in a fixed order, so that diffs stay readable."""
    body = ",\n".join("  " + json.dumps(r, ensure_ascii=False) for r in recs)
    return ('{"case": ' + json.dumps(case) + ', "findings": [\n' + body + ("\n" if recs else "")
            + "]}\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--rules", required=True, type=Path)
    ap.add_argument("--cases", required=True, type=Path)
    ap.add_argument("--deviations", required=True, type=Path)
    ap.add_argument("--raw", action="store_true", help="write expected.raw.json without deviations too")
    args = ap.parse_args()
    logging.disable(logging.WARNING)

    from crypsy.registry_loader.registry_parser import load_rule_registry
    registry = load_rule_registry(args.registry.resolve(), "default")
    new_rules = load_new_rules(args.rules)
    devs = yaml.safe_load(args.deviations.read_text(encoding="utf-8")) or {}
    known = set(devs.get("cases") or {})
    total = 0
    for input_dir in sorted(args.cases.rglob("input")):
        if not input_dir.is_dir():
            continue
        case_dir = input_dir.parent
        case = case_dir.relative_to(args.cases).as_posix()
        known.discard(case)
        opt_file = case_dir / "options.json"
        options = json.loads(opt_file.read_text()) if opt_file.exists() else {}
        recs = scan_case(input_dir, registry, new_rules, options)
        if args.raw:
            (case_dir / "expected.raw.json").write_text(json.dumps(recs, indent=1) + "\n")
        recs = apply_deviations(case, recs, devs, new_rules)
        (case_dir / "expected.json").write_text(render(case, recs), encoding="utf-8")
        total += len(recs)
        print(f"{case}: {len(recs)}")
    if known:
        sys.exit(f"deviations for unknown cases: {sorted(known)}")
    print(f"total findings: {total}")


if __name__ == "__main__":
    main()

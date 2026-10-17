#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
"""Run the CipherSift conformance suite, or compare existing CBOMs with it.

  python3 conformance.py --cmd "java --enable-native-access=ALL-UNNAMED -jar target/ciphersift-all.jar"
  python3 conformance.py --cbom-dir out/          # out/<case path>.cdx.json already produced
  python3 conformance.py --show <cbom.json>       # print the normalised findings of one CBOM

The normalisation (CBOM -> finding list) is the one described in spec/conformance/README.md.
Only the Python standard library is needed.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE.parent / "conformance" / "cases"

SOURCE_FIELDS = ("file", "line", "rule", "type", "subtype", "primitive", "family", "variant",
                 "protocol", "version", "param", "oid", "name", "test")
DEP_FIELDS = ("file", "line", "rule", "type", "ecosystem", "package", "version", "test")


def normalise(cbom: dict) -> list[dict]:
    """Turn a CipherSift CBOM into the implementation-independent finding list."""
    out = []
    for comp in cbom.get("components") or []:
        props = {p["name"]: p["value"] for p in comp.get("properties") or []}
        occs = (comp.get("evidence") or {}).get("occurrences") or []
        for occ in occs:
            ctx = json.loads(occ["additionalContext"])
            if comp["type"] == "library":
                eco = props["ciphersift:ecosystem"]
                pkg = f'{comp["group"]}:{comp["name"]}' if eco == "maven" else comp["name"]
                out.append({"file": occ["location"], "line": occ.get("line"), "rule": ctx["ruleId"],
                            "type": "library", "ecosystem": eco, "package": pkg,
                            "version": comp.get("version")})
                if ctx.get("test"):
                    out[-1]["test"] = True
                continue
            cp = comp["cryptoProperties"]
            rtype = props.get("ciphersift:assetType") or cp["assetType"]
            proto = cp.get("protocolProperties") or {}
            alg = cp.get("algorithmProperties") or {}
            out.append({
                "file": occ["location"], "line": occ.get("line"), "rule": ctx["ruleId"],
                "type": rtype, "subtype": props.get("ciphersift:subtype"),
                "primitive": props.get("ciphersift:primitive"),
                "family": props.get("ciphersift:family"), "variant": props.get("ciphersift:variant"),
                "protocol": proto.get("type"), "version": proto.get("version"),
                "param": alg.get("parameterSetIdentifier"),
                "oid": cp.get("oid"),
                "name": comp["name"] if rtype == "algorithm" else None,
            })
            if ctx.get("test"):
                out[-1]["test"] = True
    return out


def key(r: dict) -> tuple:
    fields = DEP_FIELDS if r.get("type") == "library" else SOURCE_FIELDS
    return tuple((f, r.get(f)) for f in fields)


def compare(case: str, got: list[dict], expected: list[dict]) -> list[str]:
    g = {key(r) for r in got}
    e = {key(r) for r in expected}
    msgs = []
    for k in sorted(e - g, key=str):
        msgs.append(f"  missing:    {dict(k)}")
    for k in sorted(g - e, key=str):
        msgs.append(f"  unexpected: {dict(k)}")
    if len(got) != len(g):
        msgs.append(f"  {len(got) - len(g)} duplicate occurrence(s)")
    return msgs


def main() -> None:
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--cmd", help="command that runs ciphersift (split with shlex)")
    grp.add_argument("--cbom-dir", type=Path, help="directory with <case>.cdx.json files")
    grp.add_argument("--show", type=Path, help="print the normalised findings of one CBOM")
    ap.add_argument("--case", action="append", help="only these cases (e.g. java/selection)")
    args = ap.parse_args()

    if args.show:
        for r in sorted(normalise(json.loads(args.show.read_text())), key=lambda r: str(key(r))):
            print(json.dumps(r))
        return

    failures = total = 0
    tmp = Path(tempfile.mkdtemp(prefix="ciphersift-conf-"))
    for exp_file in sorted(CASES.rglob("expected.json")):
        case_dir = exp_file.parent
        case = case_dir.relative_to(CASES).as_posix()
        if args.case and case not in args.case:
            continue
        total += 1
        expected = json.loads(exp_file.read_text(encoding="utf-8"))["findings"]
        opt_file = case_dir / "options.json"
        opts = json.loads(opt_file.read_text()) if opt_file.exists() else {}
        if args.cmd:
            out = tmp / (case.replace("/", "__") + ".cdx.json")
            cmd = shlex.split(args.cmd) + ["scan", str(case_dir / "input"), "-o", str(out)] + opts.get("args", [])
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"FAIL {case}: exit {res.returncode}\n{res.stderr}")
                failures += 1
                continue
        else:
            out = args.cbom_dir / f"{case}.cdx.json"
        got = normalise(json.loads(out.read_text(encoding="utf-8")))
        msgs = compare(case, got, expected)
        if msgs:
            failures += 1
            print(f"FAIL {case}")
            print("\n".join(msgs))
        else:
            print(f"ok   {case} ({len(expected)} findings)")
    print(f"{total - failures}/{total} cases passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

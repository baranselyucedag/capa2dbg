#!/usr/bin/env python3
"""Offline validator mirroring capa2dbg parse/dedup/critical-BP logic."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ALLOWLIST = [
    "host-interaction/process",
    "host-interaction/thread",
    "host-interaction/registry",
    "data-manipulation",
    "persistence",
    "linking/runtime-linking",
    "collection",
    "host-interaction/clipboard",
    "anti-analysis",
    "communication",
    "c2",
]


def is_critical(ns: str | None, is_lib: bool) -> bool:
    if is_lib or not ns:
        return False
    return any(ns.startswith(p) for p in ALLOWLIST)


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    analysis = data["meta"]["analysis"]
    base = analysis["base_address"]["value"]
    arch = analysis.get("arch")
    func_starts = {
        f["address"]["value"]
        for f in analysis.get("layout", {}).get("functions", [])
        if f.get("address", {}).get("type") == "absolute"
    }

    by_addr: dict[int, dict] = {}
    file_notes = []
    match_count = 0

    for rule in data["rules"].values():
        meta = rule["meta"]
        name = meta.get("name", "?")
        ns = meta.get("namespace")
        is_lib = bool(meta.get("lib"))
        scope = (meta.get("scopes") or {}).get("static")

        for m in rule.get("matches", []):
            addr = m[0]
            if addr.get("type") == "absolute":
                match_count += 1
                va = addr["value"]
                agg = by_addr.setdefault(
                    va, {"rules": set(), "func": False, "critical": False}
                )
                agg["rules"].add(name)
                if scope == "function" and va in func_starts:
                    agg["func"] = True
                if is_critical(ns, is_lib):
                    agg["critical"] = True
            else:
                note = name if not ns else f"{name} [{ns}]"
                file_notes.append(note)

    n_label = sum(1 for a in by_addr.values() if a["func"])
    n_bp = sum(1 for a in by_addr.values() if a["critical"])

    print(f"base=0x{base:X} arch={arch}")
    print(f"layout.functions={len(func_starts)}")
    print(f"matches(with addr)={match_count}")
    print(f"unique addresses={len(by_addr)}")
    print(f"labels(function scope)={n_label}")
    print(f"critical breakpoints={n_bp}")
    print(f"file-scope notes={len(file_notes)}")
    for n in file_notes:
        print(f"  (file-scope) {n}")

    # Sanity checks for the known sample
    assert arch == "i386", arch
    assert base == 0x400000, base
    assert len(by_addr) > 0
    assert n_bp > 0
    assert any("create process on Windows" in a["rules"] for a in by_addr.values())
    assert len(file_notes) >= 1
    print("OK: offline validation passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python validate_capa_json.py <capa_output.json>")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
